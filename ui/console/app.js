// AIOps console — dependency-free ES module served by control-plane-api at /console.
// Talks only to the control-plane API (same origin); every call carries the user's bearer token
// and the API enforces RBAC + tenant scope. Nothing here is trusted for authorisation.

const API = "..";                       // /console/ → control-plane root
const store = {                          // session storage can be blocked: never let it throw
  get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* memory only */ } },
  del(k) { try { sessionStorage.removeItem(k); } catch { /* ignore */ } },
};

const FAILURE = {
  disk_full: "Disk full", memory_exhaustion: "Memory exhaustion", cpu_saturation: "CPU saturation",
  connection_pool_exhaustion: "DB connection pool exhausted", interface_flap: "Interface flapping",
  error_spike: "Error spike", latency_degradation: "Latency degradation",
  tls_certificate_expiry: "TLS certificate expiry",
};
const STATUS = {
  verified: "AI-verified", unverified: "Unverified", needs_human: "Needs review", resolved: "Resolved",
};
const OUTCOME = { true_positive: "Confirmed real", false_positive: "False alarm", missed: "Missed" };

const state = { token: null, me: null, tenant: null, incidents: [], filter: "open", config: {} };
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const label = (ft) => FAILURE[ft] || ft.replaceAll("_", " ");
const has = (role) => {
  const order = ["viewer", "operator", "approver", "admin"];
  return Math.max(...(state.me?.roles || []).map((r) => order.indexOf(r))) >= order.indexOf(role);
};

// ------------------------------------------------------------------ API
class ApiError extends Error { constructor(status, detail) { super(detail); this.status = status; } }

async function api(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${state.token}`, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (res.status === 401) { signOut("Your session has expired. Sign in again."); throw new ApiError(401, "unauthorised"); }
  const body = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) throw new ApiError(res.status, body?.detail || `Request failed (${res.status})`);
  return body;
}

// ------------------------------------------------------------------ auth (OIDC code + PKCE, or a pasted token in dev)
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function oidcMeta() {
  const r = await fetch(`${state.config.oidc.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
  return r.json();
}

async function oidcLogin() {
  const meta = await oidcMeta();
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const st = b64url(crypto.getRandomValues(new Uint8Array(16)));
  store.set("pkce", JSON.stringify({ verifier, st }));
  const q = new URLSearchParams({
    response_type: "code", client_id: state.config.oidc.client_id, scope: "openid profile",
    redirect_uri: location.origin + location.pathname, code_challenge: challenge,
    code_challenge_method: "S256", state: st,
  });
  location.assign(`${meta.authorization_endpoint}?${q}`);
}

async function oidcCallback() {
  const q = new URLSearchParams(location.search);
  if (!q.get("code")) return false;
  const saved = JSON.parse(store.get("pkce") || "{}");
  history.replaceState(null, "", location.pathname + location.hash);
  if (!saved.verifier || saved.st !== q.get("state")) throw new Error("Sign-in response did not match this browser session. Try again.");
  const meta = await oidcMeta();
  const r = await fetch(meta.token_endpoint, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code: q.get("code"), client_id: state.config.oidc.client_id,
      redirect_uri: location.origin + location.pathname, code_verifier: saved.verifier,
    }),
  });
  if (!r.ok) throw new Error("The identity provider rejected the sign-in. Try again.");
  store.del("pkce");
  store.set("token", (await r.json()).access_token);
  return true;
}

function signOut(message) {
  store.del("token");
  state.token = null; state.me = null;
  renderSignIn(message);
}

function renderSignIn(message = "") {
  $(".tabs").hidden = true; $(".who").hidden = true;
  const oidc = !!state.config.oidc;
  $("#main").innerHTML = `
    <div class="signin"><div class="card">
      <h1>Sign in to AIOps</h1>
      <p>Predicted incidents, AI root cause and fix approvals for your estate.</p>
      ${message ? `<div class="error" role="alert">${esc(message)}</div>` : ""}
      ${oidc ? `<button class="primary" id="sso" type="button">Sign in with single sign-on</button>` : `
        <label class="field">Access token
          <textarea id="tok" spellcheck="false" autocomplete="off" placeholder="Paste a token from your identity provider, or run: make token"></textarea>
        </label>
        <button class="primary" id="use" type="button">Sign in</button>`}
    </div></div>`;
  if (oidc) $("#sso").onclick = () => oidcLogin().catch((e) => renderSignIn(e.message));
  else $("#use").onclick = async () => {
    state.token = $("#tok").value.trim();
    if (!state.token) return renderSignIn("Paste an access token first.");
    try { await boot(); store.set("token", state.token); } catch (e) { if (e.status !== 401) renderSignIn(e.message); }
  };
}

// ------------------------------------------------------------------ shell
async function boot() {
  state.me = await api("/v1/me");
  const tenants = await api("/v1/tenants");
  if (!tenants.length) return renderSignIn("Your account has no tenants. Ask an admin to grant you access.");
  const sel = $("#tenant");
  sel.innerHTML = tenants.map((t) => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join("");
  state.tenant = tenants.some((t) => t.id === store.get("tenant")) ? store.get("tenant") : tenants[0].id;
  sel.value = state.tenant;
  sel.onchange = () => { state.tenant = sel.value; store.set("tenant", sel.value); route(); };
  $("#user").textContent = `${state.me.sub} · ${state.me.roles.join(", ")}`;
  $("#signout").onclick = () => signOut("You have signed out.");
  $(".tabs").hidden = false; $(".who").hidden = false;
  window.onhashchange = route;
  route();
}

function route() {
  closeDrawer();
  const name = (location.hash.replace(/^#\//, "") || "incidents").split("?")[0];
  document.querySelectorAll(".tabs a").forEach((a) => { if (a.dataset.route === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  const views = { incidents, approvals, quality, audit };
  (views[name] || incidents)();
  refreshApprovalsCount();
}

function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.remove("show"), 3200);
}

function confirmDialog(title, text, ok) {
  const d = $("#confirm");
  $("#confirm-title").textContent = title; $("#confirm-text").textContent = text; $("#confirm-ok").textContent = ok;
  d.showModal();
  return new Promise((res) => d.addEventListener("close", () => res(d.returnValue === "ok"), { once: true }));
}

const loading = (rows = 4) => `<div class="panel">${'<div class="skeleton"></div>'.repeat(rows)}</div>`;
const empty = (title, text) => `<div class="empty"><div class="mark" aria-hidden="true"></div><h2>${esc(title)}</h2><p>${esc(text)}</p></div>`;
const errorBox = (e) => `<div class="error" role="alert">${esc(e.status === 502 || e.status === 503 ? "Incident data is unavailable: the feedback service did not respond. Check the feedback-service health and try again." : e.message)}</div>`;

// ------------------------------------------------------------------ incidents
function timing(i, now = Date.now()) {
  const start = Date.parse(i.predicted_at);
  const base = Date.parse(i.updated_at || i.predicted_at);
  const failAt = i.eta_minutes != null ? base + i.eta_minutes * 60000 : null;
  const left = failAt != null ? (failAt - now) / 60000 : null;
  const pct = failAt != null ? Math.min(100, Math.max(2, ((now - start) / (failAt - start)) * 100)) : 100;
  return { start, failAt, left, pct };
}

function ago(ts) {
  const m = Math.round((Date.now() - Date.parse(ts)) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} days ago`;
}

const clock = (ms) => new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(ms));

function runway(i) {
  const t = timing(i);
  const done = !!i.resolved_at;
  let headline = "Happening now, no ETA", cls = "";
  if (done) headline = "Risk cleared";
  else if (t.left != null && t.left <= 0) { headline = "Failure time reached"; cls = "crit"; }
  else if (t.left != null) { headline = `Fails in ~${Math.max(1, Math.round(t.left))} min`; cls = t.left < 10 ? "crit" : t.left < 30 ? "warn" : ""; }
  const trackCls = done || t.failAt == null ? "done" : cls === "crit" ? "crit" : "";
  return `<div class="runway">
    <div class="runway-label"><strong class="num ${cls}">${headline}</strong><span>${t.failAt != null && !done ? `failure ~${clock(t.failAt)}` : `first warning ${ago(i.predicted_at)}`}</span></div>
    <div class="track ${trackCls}" role="img" aria-label="${esc(headline)}"><div class="fill" style="width:${t.pct.toFixed(1)}%"></div>${t.failAt != null ? '<div class="eta"></div>' : ""}</div>
  </div>`;
}

function chip(i) {
  const s = i.resolved_at ? "resolved" : i.status;
  return `<span class="chip ${esc(s)}">${esc(STATUS[s] || s)}</span>`;
}

async function incidents() {
  const main = $("#main");
  main.innerHTML = `<div class="page-head"><div><h1>Incidents</h1><p>Failures the platform predicted, what the AI found, and how much time is left.</p></div>
    <div class="filters" role="group" aria-label="Filter incidents">
      ${["open", "review", "all"].map((f) => `<button type="button" data-f="${f}" aria-pressed="${state.filter === f}">${{ open: "Open", review: "Needs review", all: "All" }[f]}</button>`).join("")}
    </div></div><div id="sum"></div><div id="list">${loading()}</div>`;
  main.querySelectorAll(".filters button").forEach((b) => b.onclick = () => { state.filter = b.dataset.f; incidents(); });
  try {
    state.incidents = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/incidents`);
  } catch (e) { $("#list").innerHTML = errorBox(e); return; }
  const all = state.incidents;
  const open = all.filter((i) => !i.resolved_at);
  const imminent = open.filter((i) => { const l = timing(i).left; return l != null && l < 15; });
  const review = open.filter((i) => i.status !== "verified" && !i.outcome);
  const labelled = all.filter((i) => i.outcome);
  $("#sum").innerHTML = `<div class="summary">
    <div class="imminent"><span class="num">${imminent.length}</span><span>predicted to fail within 15 min</span></div>
    <div><span class="num">${open.length}</span><span>open incidents</span></div>
    <div><span class="num">${review.length}</span><span>waiting for a human decision</span></div>
    <div><span class="num">${labelled.length}</span><span>labelled for learning</span></div></div>`;
  const shown = state.filter === "open" ? open : state.filter === "review" ? review : all;
  shown.sort((a, b) => (timing(a).left ?? 1e9) - (timing(b).left ?? 1e9));
  if (!shown.length) {
    $("#list").innerHTML = `<div class="panel">${state.filter === "all"
      ? empty("No predictions yet", "When detectors raise a candidate incident, it appears here with the AI's root cause and the time left before failure.")
      : empty("Nothing needs attention", "No open predictions match this filter. Switch to All to see resolved incidents.")}</div>`;
    return;
  }
  $("#list").innerHTML = `<ul class="panel incidents">${shown.map((i) => `
    <li class="incident" tabindex="0" data-key="${esc(i.incident_key)}" aria-label="${esc(i.ci_id)}: ${esc(label(i.failure_type))}">
      <div><div class="ci">${esc(i.ci_id)}</div><div class="what">${esc(label(i.failure_type))} · ${esc(i.service)}</div>
        <div class="cause">${esc(i.root_cause)}</div></div>
      ${runway(i)}
      <div class="state">${chip(i)}${i.outcome ? `<span class="outcome">${esc(OUTCOME[i.outcome] || i.outcome)}</span>` : ""}</div>
    </li>`).join("")}</ul>`;
  $("#list").querySelectorAll(".incident").forEach((li) => {
    const open = () => openIncident(li.dataset.key, li);
    li.onclick = open;
    li.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } };
  });
}

let lastFocus = null;
function openDrawer(html, from) {
  lastFocus = from || document.activeElement;
  $("#drawer-body").innerHTML = html;
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#scrim").hidden = false;
  $("#scrim").onclick = closeDrawer;
  document.addEventListener("keydown", escClose);
  $("#drawer .close")?.focus();
}
function escClose(e) { if (e.key === "Escape") closeDrawer(); }
function closeDrawer() {
  if ($("#drawer").getAttribute("aria-hidden") === "true") return;
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").hidden = true;
  document.removeEventListener("keydown", escClose);
  lastFocus?.focus?.();
}

async function openIncident(key, from) {
  const i = state.incidents.find((x) => x.incident_key === key);
  if (!i) return;
  const t = timing(i);
  const canLabel = has("operator") && !i.outcome;
  let playbooks = [];
  if (has("operator")) { try { playbooks = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/playbooks`); } catch { /* optional */ } }
  openDrawer(`
    <header><div><h2 id="drawer-title">${esc(label(i.failure_type))} on ${esc(i.ci_id)}</h2>
      <p class="muted">${esc(i.service)} · first warning ${ago(i.predicted_at)}</p></div>
      <button class="close" type="button" aria-label="Close">×</button></header>
    ${runway(i)}
    <div class="facts">
      <div><span class="num">${t.left != null && !i.resolved_at ? `${Math.max(0, Math.round(t.left))} min` : "—"}</span>time left</div>
      <div><span class="num">${Math.round(i.confidence * 100)}%</span>confidence</div>
      <div><span class="num">${chip(i)}</span>status</div>
    </div>
    <section><h3>Root cause</h3><p>${esc(i.root_cause)}</p></section>
    ${i.recommended_actions.length ? `<section><h3>Recommended fix</h3><ol>${i.recommended_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol></section>` : ""}
    ${i.runbook_ref ? `<section><h3>Runbook</h3><p><code>${esc(i.runbook_ref)}</code></p></section>` : ""}
    ${i.outcome ? `<section><h3>Outcome</h3><p>${esc(OUTCOME[i.outcome])}${i.lead_time_minutes != null ? ` · ${Math.round(i.lead_time_minutes)} min of warning` : ""}</p></section>` : ""}
    ${canLabel ? `<section><h3>Was this prediction right?</h3><p class="muted">Your answer tunes thresholds and runbooks.</p>
      <div class="row-end" style="justify-content:flex-start"><button class="secondary" data-o="true_positive" type="button">Yes, it was real</button>
      <button class="secondary" data-o="false_positive" type="button">No, false alarm</button></div></section>` : ""}
    ${has("operator") && playbooks.length && !i.resolved_at ? `<section><h3>Request an automated fix</h3>
      <label class="field">Playbook<select id="pb">${playbooks.map((p) => `<option>${esc(p)}</option>`).join("")}</select></label>
      <div><button class="primary" id="propose" type="button">Request approval</button></div>
      <p class="muted">A second person with the approver role must approve before it can run.</p></section>` : ""}
    <p class="key">Incident key ${esc(i.incident_key)}</p>`, from);
  $("#drawer .close").onclick = closeDrawer;
  $("#drawer-body").querySelectorAll("[data-o]").forEach((b) => b.onclick = async () => {
    b.disabled = true;
    try {
      await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/incidents/${encodeURIComponent(key)}/outcome`, { method: "POST", body: JSON.stringify({ outcome: b.dataset.o }) });
      toast(b.dataset.o === "true_positive" ? "Marked as real" : "Marked as false alarm");
      closeDrawer(); incidents();
    } catch (e) { b.disabled = false; toast(e.message); }
  });
  const pb = $("#propose");
  if (pb) pb.onclick = async () => {
    pb.disabled = true;
    try {
      await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/remediations`, { method: "POST", body: JSON.stringify({
        incident_key: key, failure_type: i.failure_type, playbook: $("#pb").value, params: { ci_id: i.ci_id } }) });
      toast("Approval requested"); closeDrawer(); refreshApprovalsCount();
    } catch (e) { pb.disabled = false; toast(e.message); }
  };
}

// ------------------------------------------------------------------ approvals
async function refreshApprovalsCount() {
  if (!state.tenant) return;
  try {
    const rows = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/remediations`);
    const n = rows.filter((r) => r.status === "proposed").length;
    const c = $("#approvals-count"); c.hidden = !n; c.textContent = n;
  } catch { /* badge is best-effort */ }
}

async function approvals() {
  const main = $("#main");
  main.innerHTML = `<div class="page-head"><div><h1>Fix approvals</h1><p>Automated fixes need a second person to approve them. Recommend-only failure types can never run from here.</p></div></div><div id="ap">${loading(3)}</div>`;
  let rows;
  try { rows = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/remediations`); } catch (e) { $("#ap").innerHTML = errorBox(e); return; }
  if (!rows.length) { $("#ap").innerHTML = `<div class="panel">${empty("No fix requests", "Open an incident and choose Request approval to propose an allow-listed playbook.")}</div>`; return; }
  const me = state.me.sub;
  $("#ap").innerHTML = `<div class="panel table-wrap"><table>
    <thead><tr><th scope="col">Request</th><th scope="col">Playbook</th><th scope="col">Status</th><th scope="col">Requested by</th><th scope="col">Approved by</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
    <tbody>${rows.map((r) => {
      const canApprove = has("approver") && r.status === "proposed" && r.requested_by !== me;
      const canRun = has("operator") && r.status === "approved" && r.mode === "one_click";
      const why = r.status === "approved" && r.mode !== "one_click" ? `<span class="muted">Recommend-only: apply manually</span>` : "";
      return `<tr>
        <td><strong class="num">#${r.id}</strong><div class="muted">${esc(label(r.failure_type))}</div></td>
        <td><code>${esc(r.playbook)}</code><div class="muted">${esc(Object.entries(r.params).map(([k, v]) => `${k}=${v}`).join(", "))}</div></td>
        <td>${esc(r.status.replace(/^./, (c) => c.toUpperCase()))}${r.result ? `<div class="muted">${esc(r.result)}</div>` : ""}</td>
        <td>${esc(r.requested_by)}</td><td>${esc(r.approved_by || "—")}</td>
        <td><div class="actions">
          ${canApprove ? `<button class="primary" data-a="approve" data-id="${r.id}" type="button">Approve</button><button class="danger" data-a="reject" data-id="${r.id}" type="button">Reject</button>` : ""}
          ${r.status === "proposed" && r.requested_by === me ? `<span class="muted">Waiting for another approver</span>` : ""}
          ${canRun ? `<button class="primary" data-a="execute" data-id="${r.id}" type="button">Run fix</button>` : why}
        </div></td></tr>`;
    }).join("")}</tbody></table></div>`;
  $("#ap").querySelectorAll("[data-a]").forEach((b) => b.onclick = async () => {
    const { a, id } = b.dataset;
    if (a === "execute" && !(await confirmDialog(`Run fix #${id}?`, "The approved playbook runs against the production CI now. The run is audit-logged.", "Run fix"))) return;
    if (a === "reject" && !(await confirmDialog(`Reject fix #${id}?`, "The request is closed and cannot be run.", "Reject"))) return;
    b.disabled = true;
    try {
      await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/remediations/${id}/${a}`, { method: "POST" });
      toast({ approve: "Fix approved", reject: "Fix rejected", execute: "Fix ran" }[a]);
      approvals(); refreshApprovalsCount();
    } catch (e) { b.disabled = false; toast(e.message); }
  });
}

// ------------------------------------------------------------------ quality
function meter(v, target) {
  if (v == null) return `<span class="muted">Not enough labels</span>`;
  return `<div class="meter"><div class="bar-bg"><div class="bar-fg ${v < target ? "low" : ""}" style="width:${(v * 100).toFixed(0)}%"></div>
    <div class="target" style="left:${target * 100}%" title="Target ${target * 100}%"></div></div><span class="num">${Math.round(v * 100)}%</span></div>`;
}

async function quality() {
  const main = $("#main");
  main.innerHTML = `<div class="page-head"><div><h1>Prediction quality</h1><p>How often warnings were real (precision), how many failures were warned about (recall), and how much notice teams got. The line marks the target.</p></div></div><div id="q">${loading(3)}</div>`;
  let rows;
  try { rows = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/kpis`); } catch (e) { $("#q").innerHTML = errorBox(e); return; }
  if (!rows.length) { $("#q").innerHTML = `<div class="panel">${empty("No labelled outcomes yet", "Mark incidents as real or false alarms, or connect the ServiceNow close-out webhook, and quality appears here per failure type.")}</div>`; return; }
  $("#q").innerHTML = `<div class="panel table-wrap"><table>
    <thead><tr><th scope="col">Failure type</th><th scope="col">Precision (target 70%)</th><th scope="col">Recall (target 80%)</th><th scope="col">Median warning</th><th scope="col">Real</th><th scope="col">False alarms</th><th scope="col">Missed</th></tr></thead>
    <tbody>${rows.map((k) => `<tr><td><strong>${esc(label(k.failure_type))}</strong></td>
      <td>${meter(k.precision, 0.7)}</td><td>${meter(k.recall, 0.8)}</td>
      <td class="num">${k.median_lead_time_minutes != null ? `${k.median_lead_time_minutes} min` : "—"}</td>
      <td class="num">${k.true_positives}</td><td class="num">${k.false_positives}</td><td class="num">${k.missed}</td></tr>`).join("")}</tbody></table></div>`;
}

// ------------------------------------------------------------------ audit
async function audit() {
  const main = $("#main");
  main.innerHTML = `<div class="page-head"><div><h1>Audit log</h1><p>Every configuration change, approval, denied run and executed fix for this tenant. Entries cannot be edited.</p></div></div><div id="au">${loading(4)}</div>`;
  let rows;
  try { rows = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/audit?limit=200`); } catch (e) { $("#au").innerHTML = errorBox(e); return; }
  if (!rows.length) { $("#au").innerHTML = `<div class="panel">${empty("No activity yet", "Changes made through this console or the API are recorded here.")}</div>`; return; }
  const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  $("#au").innerHTML = `<div class="panel table-wrap"><table>
    <thead><tr><th scope="col">When</th><th scope="col">Who</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Details</th></tr></thead>
    <tbody>${rows.map((r) => `<tr><td class="num">${esc(fmt.format(new Date(r.ts)))}</td><td>${esc(r.actor)}</td>
      <td><code>${esc(r.action)}</code></td><td>${esc(r.target)}</td>
      <td class="muted">${esc(Object.entries(r.detail).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join("; "))}</td></tr>`).join("")}</tbody></table></div>`;
}

// ------------------------------------------------------------------ start
(async function start() {
  try { state.config = await (await fetch("config.json")).json(); } catch { state.config = {}; }
  try { if (state.config.oidc) await oidcCallback(); } catch (e) { return renderSignIn(e.message); }
  state.token = store.get("token");
  if (!state.token) return renderSignIn();
  try { await boot(); } catch (e) { if (e.status !== 401) renderSignIn(e.message); }
})();
