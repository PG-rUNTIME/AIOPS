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

const ROLES = ["viewer", "operator", "approver", "admin"];
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

function setView(v) { document.body.dataset.view = v; document.body.classList.remove("nav-open"); }

function authShell(inner) {
  const prod = state.config.environment === "prod";
  return `<div class="auth">
    <section class="auth-brand" aria-label="About AIOps">
      <img src="brand/logo/cassava-logo-white.png" alt="Cassava Technologies" width="130" height="36">
      <div>
        <h2>Know it will break before it does.</h2>
        <p class="lead">Predictive AIOps for your estate: early warnings, AI-explained root cause, and fixes with a human in the loop.</p>
      </div>
      <ul class="auth-points">
        <li>Failures predicted 5–15 minutes ahead, with the evidence behind each one</li>
        <li>Tickets opened before anyone is paged</li>
        <li>Every approval and change recorded in an audit log</li>
      </ul>
      <small>${prod ? "" : "Non-production environment · "}© Cassava Technologies</small>
    </section>
    <section class="auth-form"><div class="auth-card">${inner}</div></section>
  </div>`;
}

function renderSignIn(message = "") {
  setView("auth");
  if (state.config.auth === "local") return renderLocalSignIn(message);
  const oidc = !!state.config.oidc;
  $("#main").innerHTML = authShell(`
    <div><h1>Sign in</h1><p class="sub">${oidc ? "Use your company account." : "Paste an access token to continue."}</p></div>
    ${message ? `<div class="error" role="alert">${esc(message)}</div>` : ""}
    ${oidc ? `<button class="primary btn-wide" id="sso" type="button">Continue with single sign-on</button>` : `
      <label class="field">Access token
        <textarea id="tok" spellcheck="false" autocomplete="off" placeholder="Paste a token from your identity provider"></textarea>
      </label>
      <button class="primary btn-wide" id="use" type="button">Sign in</button>`}`);
  if (oidc) $("#sso").onclick = () => oidcLogin().catch((e) => renderSignIn(e.message));
  else $("#use").onclick = async () => {
    state.token = $("#tok").value.trim();
    if (!state.token) return renderSignIn("Paste an access token first.");
    try { await boot(); store.set("token", state.token); } catch (e) { if (e.status !== 401) renderSignIn(e.message); }
  };
}

function renderLocalSignIn(message) {
  $("#main").innerHTML = authShell(`
    <div><h1>Welcome back</h1><p class="sub">Sign in to see what is about to fail, and what to do about it.</p></div>
    <div id="auth-err" aria-live="polite">${message ? `<div class="error" role="alert">${esc(message)}</div>` : ""}</div>
    <form id="login" class="form-grid" novalidate>
      <label class="field">Username
        <input id="lu" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
      </label>
      <label class="field">Password
        <span class="pw"><input id="lp" name="password" type="password" autocomplete="current-password" required>
          <button type="button" id="peek" aria-pressed="false">Show</button></span>
      </label>
      <button class="primary btn-wide" id="lgo" type="submit">Sign in</button>
    </form>
    <p class="auth-foot">Forgot your password? Ask an administrator to reset it.</p>`);
  $("#peek").onclick = () => {
    const show = $("#lp").type === "password";
    $("#lp").type = show ? "text" : "password"; $("#peek").textContent = show ? "Hide" : "Show"; $("#peek").setAttribute("aria-pressed", String(show));
  };
  const fail = (m) => { $("#auth-err").innerHTML = `<div class="error" role="alert">${esc(m)}</div>`; $("#lgo").disabled = false; $("#lgo").textContent = "Sign in"; };
  $("#login").onsubmit = async (ev) => {
    ev.preventDefault();
    const username = $("#lu").value.trim(), password = $("#lp").value;
    if (!username || !password) return fail("Enter your username and password.");
    $("#lgo").disabled = true; $("#lgo").innerHTML = `<span class="spinner"></span>Signing in`;
    try {
      const res = await fetch(`${API}/v1/auth/login`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }),
      });
      const body = res.headers.get("content-type")?.includes("json") ? await res.json() : {};
      if (!res.ok) return fail(body.detail || `Sign-in failed (${res.status}).`);
      state.token = body.access_token; store.set("token", state.token);
      await boot();
    } catch (e) { if (e.status !== 401) fail(e.message || "Sign-in failed. Check your connection and try again."); }
  };
}

// ------------------------------------------------------------------ shell
const initials = (n) => (String(n).match(/[a-z0-9]+/gi) || ["?"]).slice(0, 2).map((x) => x[0]).join("");

async function boot() {
  state.me = await api("/v1/me");
  const tenants = await api("/v1/tenants");
  if (!tenants.length) return renderSignIn("Your account has no tenants. Ask an admin to grant you access.");
  const sel = $("#tenant");
  sel.innerHTML = tenants.map((t) => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join("");
  state.tenant = tenants.some((t) => t.id === store.get("tenant")) ? store.get("tenant") : tenants[0].id;
  sel.value = state.tenant;
  sel.onchange = () => { state.tenant = sel.value; store.set("tenant", sel.value); route(); };
  const role = [...state.me.roles].sort((a, b) => ROLES.indexOf(b) - ROLES.indexOf(a))[0] || "viewer";
  $("#user").textContent = state.me.sub; $("#role").textContent = role;
  $("#avatar").textContent = initials(state.me.sub);
  $("#pop-user").textContent = state.me.sub; $("#pop-role").textContent = `${role} · ${state.me.tenants.includes("*") ? "all tenants" : state.me.tenants.join(", ")}`;
  const env = $("#env"); env.textContent = state.config.environment === "prod" ? "Production" : "Development"; env.classList.toggle("prod", state.config.environment === "prod");
  const local = state.config.auth === "local";
  $("#chpw").hidden = !local; $("#chpw").onclick = () => { closeUserMenu(); changePassword(); };
  $("#signout").onclick = () => { closeUserMenu(); signOut("You have signed out."); };
  $("#users-tab").hidden = !(local && has("admin"));
  const um = $("#usermenu");
  um.onclick = (e) => { e.stopPropagation(); const open = um.getAttribute("aria-expanded") !== "true"; um.setAttribute("aria-expanded", String(open)); $("#usermenu-pop").hidden = !open; };
  document.onclick = (e) => { if (!e.target.closest(".usermenu")) closeUserMenu(); if (!e.target.closest(".side, #menu")) document.body.classList.remove("nav-open"); };
  document.onkeydown = (e) => { if (e.key === "Escape") { closeUserMenu(); document.body.classList.remove("nav-open"); } };
  $("#menu").onclick = (e) => { e.stopPropagation(); document.body.classList.toggle("nav-open"); };
  $("#year").textContent = new Date().getFullYear(); $("#ver").textContent = state.config.version ? `v${state.config.version}` : "";
  $("#foot-env").textContent = env.textContent; $("#foot-env").classList.toggle("prod", env.classList.contains("prod"));
  checkStatus(); clearInterval(checkStatus.h); checkStatus.h = setInterval(checkStatus, 60000);
  setView("app");
  window.onhashchange = route;
  route();
}

function closeUserMenu() { $("#usermenu").setAttribute("aria-expanded", "false"); $("#usermenu-pop").hidden = true; }

function route() {
  closeDrawer();
  document.body.classList.remove("nav-open");
  window.scrollTo(0, 0);
  const path = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
  const name = path.startsWith("incidents/") ? "incidents" : path;
  clearLive();
  document.querySelectorAll(".nav a").forEach((a) => { if (a.dataset.route === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  const views = { overview, incidents, approvals, quality, audit, users, connections };
  if (path.startsWith("incidents/")) {
    const key = decodeURIComponent(path.slice("incidents/".length));
    incidentPage.last = null; incidentPage(key);
    wsTimer = setInterval(() => { if (!document.hidden && !document.querySelector("dialog[open]")) incidentPage(key, true); }, 15000);
  } else {
    (views[name] || overview)();
    if (name === "incidents" || name === "overview") {
      wsTimer = setInterval(() => { if (!document.hidden && !document.querySelector("dialog[open]") && $("#drawer").getAttribute("aria-hidden") === "true") (views[name])(); }, 30000);
    }
  }
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
      ${["open", "review", "mine", "all"].map((f) => `<button type="button" data-f="${f}" aria-pressed="${state.filter === f}">${{ open: "Open", review: "Needs review", mine: "Assigned to me", all: "All" }[f]}</button>`).join("")}
    </div></div><div id="sum"></div><div id="list">${loading()}</div>`;
  main.querySelectorAll(".filters button").forEach((b) => b.onclick = () => { state.filter = b.dataset.f; incidents(); });
  try {
    state.incidents = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/incidents`);
  } catch (e) { $("#list").innerHTML = errorBox(e); return; }
  const all = state.incidents;
  const open = all.filter(isOpen);
  const imminent = open.filter((i) => { const l = timing(i).left; return l != null && l < 15; });
  const review = open.filter((i) => i.status !== "verified" && !i.outcome);
  const mine = open.filter((i) => i.workflow?.assignee === state.me.sub);
  const labelled = all.filter((i) => i.outcome);
  if (all.length) $("#sum").innerHTML = `<div class="summary">
    <div class="imminent"><span class="num">${imminent.length}</span><span>predicted to fail within 15 min</span></div>
    <div><span class="num">${open.length}</span><span>open incidents</span></div>
    <div><span class="num">${review.length}</span><span>waiting for a human decision</span></div>
    <div><span class="num">${labelled.length}</span><span>labelled for learning</span></div></div>`;
  const shown = state.filter === "open" ? open : state.filter === "review" ? review : state.filter === "mine" ? mine : all;
  shown.sort((a, b) => (timing(a).left ?? 1e9) - (timing(b).left ?? 1e9));
  if (!all.length) $("#sum").innerHTML = await getStarted();
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
      <div class="state">${chip(i)}${wfChip(i.workflow)}${i.workflow?.assignee ? `<span class="outcome">${esc(i.workflow.assignee)}</span>` : ""}${i.outcome ? `<span class="outcome">${esc(OUTCOME[i.outcome] || i.outcome)}</span>` : ""}</div>
    </li>`).join("")}</ul>`;
  $("#list").querySelectorAll(".incident").forEach((li) => {
    const go = () => { location.hash = `#/incidents/${encodeURIComponent(li.dataset.key)}`; };
    li.onclick = go;
    li.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } };
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

// ------------------------------------------------------------------ investigation workspace
const isOpen = (i) => !i.resolved_at && i.workflow?.state !== "resolved";
const WF = { new: "New", acknowledged: "Acknowledged", resolved: "Resolved" };
const wfChip = (w) => `<span class="chip wf-${esc(w?.state || "new")}">${esc(WF[w?.state || "new"])}</span>`;
const incPath = (key) => `/v1/tenants/${encodeURIComponent(state.tenant)}/incidents/${encodeURIComponent(key)}`;
const VERDICT_WORD = { verified: "verified", unverified: "not reviewed", needs_human: "needs review", noise: "noise", resolved: "resolved" };
const SYS_TITLE = { first_signal: "First warning signal", risk_cleared: "Risk cleared: detectors are quiet" };
const compact = (v) => { const a = Math.abs(v); return a >= 1e12 ? `${(v / 1e12).toFixed(1)}T` : a >= 1e9 ? `${(v / 1e9).toFixed(1)}G` : a >= 1e6 ? `${(v / 1e6).toFixed(1)}M` : a >= 1e3 ? `${(v / 1e3).toFixed(1)}k` : String(Math.round(v * 100) / 100); };
const hhmm = (t) => new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(t * 1000));
const copyBtn = (text) => `<button class="ghost copy" type="button" data-copy="${esc(text)}" aria-label="Copy">Copy</button>`;

function showTip(x, y, value, title) {
  const t = $("#tip");
  t.replaceChildren(Object.assign(document.createElement("strong"), { textContent: value }), Object.assign(document.createElement("span"), { textContent: title }));
  t.hidden = false;
  t.style.left = `${Math.min(Math.max(8, x - t.offsetWidth / 2), innerWidth - t.offsetWidth - 8)}px`; t.style.top = `${Math.max(8, y - t.offsetHeight - 14)}px`;
}

// The metric against its failure threshold, with the projected crossing. One series, one hue.
function metricChart(box, s) {
  const W = 680, H = 250, m = { l: 48, r: 30, t: 20, b: 30 };
  const pts = s.points, t0 = pts[0][0], lastP = pts[pts.length - 1];
  const tCross = s.eta_minutes != null ? s.now + s.eta_minutes * 60 : null;
  const t1 = Math.max(lastP[0], s.now, tCross ?? 0);
  const vals = pts.map((p) => p[1]);
  const th = s.threshold;
  let lo = Math.min(...vals, th ?? Infinity), hi = Math.max(...vals, th ?? -Infinity);
  const pad = (hi - lo) * 0.1 || 0.1; lo -= pad; hi += pad;
  const ratio = hi <= 1.6 && lo >= -0.6;
  const fv = (v) => (ratio ? `${(v * 100).toFixed(Math.abs(v) >= 0.995 && Math.abs(v) < 1.0001 ? 1 : 0)}%` : compact(v));
  const X = (t) => m.l + ((t - t0) / (t1 - t0 || 1)) * (W - m.l - m.r), Y = (v) => m.t + (1 - (v - lo) / (hi - lo || 1)) * (H - m.t - m.b);
  const line = pts.map((p, k) => `${k ? "L" : "M"}${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join("");
  const area = `${line}L${X(lastP[0]).toFixed(1)},${H - m.b}L${X(t0).toFixed(1)},${H - m.b}Z`;
  const grid = [0, 1, 2, 3].map((k) => { const v = lo + ((hi - lo) * k) / 3; return `<line x1="${m.l}" x2="${W - m.r}" y1="${Y(v)}" y2="${Y(v)}" class="gl"/><text x="${m.l - 8}" y="${Y(v) + 4}" text-anchor="end" class="ax">${esc(fv(v))}</text>`; }).join("");
  const xt = [0, 1, 2, 3, 4].map((k) => { const t = t0 + ((t1 - t0) * k) / 4; return `<text x="${X(t)}" y="${H - 8}" text-anchor="${k === 4 ? "end" : k === 0 ? "start" : "middle"}" class="ax">${esc(hhmm(t))}</text>`; }).join("");
  const thr = th != null ? `<line x1="${m.l}" x2="${W - m.r}" y1="${Y(th)}" y2="${Y(th)}" class="thr"/><text x="${m.l + 6}" y="${Y(th) - 6}" class="thr-l">Failure threshold ${esc(fv(th))}</text>` : "";
  const proj = tCross != null && th != null ? `<line x1="${X(lastP[0])}" y1="${Y(lastP[1])}" x2="${X(tCross)}" y2="${Y(th)}" class="proj"/>
      <polygon points="${X(tCross) - 7},${Y(th) - 14} ${X(tCross) + 7},${Y(th) - 14} ${X(tCross)},${Y(th) - 2}" class="eta-mark"/>
      <text x="${X(tCross) - 12}" y="${Y(th) - 6}" text-anchor="end" class="ax strong">Predicted ~${esc(hhmm(tCross))}</text>` : "";
  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="${esc(s.metric)} over the last hour against its failure threshold">
      ${grid}${xt}<path d="${area}" class="area"/>${thr}<path d="${line}" class="ln"/>${proj}
      <line x1="${X(s.now)}" x2="${X(s.now)}" y1="${m.t}" y2="${H - m.b}" class="now"/><text x="${X(s.now) - 5}" y="${H - m.b - 6}" text-anchor="end" class="ax">Now</text>
      <circle cx="${X(lastP[0])}" cy="${Y(lastP[1])}" r="4.5" class="dot"/>
      <line id="xh" y1="${m.t}" y2="${H - m.b}" class="xh" hidden/><circle id="xd" r="4.5" class="dot" hidden/>
      <rect x="${m.l}" y="${m.t}" width="${W - m.l - m.r}" height="${H - m.t - m.b}" fill="transparent" id="hit"/></svg>`;
  const svg = $("svg", box), hit = $("#hit", box), xh = $("#xh", box), xd = $("#xd", box);
  const move = (e) => {
    const r = svg.getBoundingClientRect(), vx = ((e.clientX - r.left) / r.width) * W;
    const tt = t0 + ((vx - m.l) / (W - m.l - m.r)) * (t1 - t0);
    const p = pts.reduce((b, q) => (Math.abs(q[0] - tt) < Math.abs(b[0] - tt) ? q : b), pts[0]);
    xh.setAttribute("x1", X(p[0])); xh.setAttribute("x2", X(p[0])); xh.hidden = false;
    xd.setAttribute("cx", X(p[0])); xd.setAttribute("cy", Y(p[1])); xd.hidden = false;
    showTip(r.left + (X(p[0]) / W) * r.width, r.top + (Y(p[1]) / H) * r.height, fv(p[1]), hhmm(p[0]));
  };
  hit.addEventListener("pointermove", move);
  hit.addEventListener("pointerleave", () => { $("#tip").hidden = true; xh.hidden = true; xd.hidden = true; });
}

function seriesTable(s) {
  const step = Math.max(1, Math.floor(s.points.length / 12));
  const rows = s.points.filter((_, k) => k % step === 0 || k === s.points.length - 1);
  return tbl(["Time", "Value"], rows.map((p) => [hhmm(p[0]), p[1]]));
}

function timeline(ws) {
  const ev = [];
  (ws.detail?.events || []).forEach((e) => ev.push({ ts: e.ts, kind: "sys", title: e.kind === "verdict" ? `AI verdict: ${VERDICT_WORD[e.status] || e.status}` : SYS_TITLE[e.kind] || e.kind,
    text: e.kind === "verdict" ? `${Math.round(e.confidence * 100)}% confidence${e.eta_minutes != null ? ` · fails in ~${Math.round(e.eta_minutes)} min` : ""} · ${e.model}` : "" }));
  const verb = { ack: "acknowledged this", assign: null, note: "added a note", resolve: "resolved this", reopen: "reopened this" };
  ws.activity.forEach((a) => ev.push({ ts: a.ts, who: a.actor, kind: a.kind, title: a.kind === "assign" ? (a.detail.assignee ? `assigned this to ${a.detail.assignee}` : "unassigned this") : verb[a.kind], text: a.detail.text || a.detail.resolution || "" }));
  ws.remediations.forEach((r) => ev.push({ ts: r.created_at, who: r.requested_by, kind: "fix", title: `requested the fix ${r.playbook}`, text: `${r.status}${r.approved_by ? ` · approved by ${r.approved_by}` : ""}${r.result ? ` · ${r.result}` : ""}` }));
  return ev.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
}

function aiBanner(v, i) {
  if (!v) return "";
  const st = v.status;
  if (st === "verified") return `<div class="banner ok"><strong>Evidence-checked.</strong> Every claim below is backed by a query the AI actually ran.</div>`;
  if (st === "noise") return `<div class="banner ok"><strong>Judged to be noise.</strong> The AI looked at the evidence and does not expect a failure.</div>`;
  if (st === "unverified") return `<div class="banner warn"><strong>The AI did not review this.</strong> What you see is detector output only.${v.downgrade_reasons?.length ? ` ${esc(v.downgrade_reasons.join("; "))}` : ""}</div>`;
  return `<div class="banner warn"><strong>The AI's answer was not trusted.</strong> It could not back its claims with evidence, so a person should review.
    ${v.downgrade_reasons?.length ? `<ul>${v.downgrade_reasons.slice(0, 4).map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}</div>`;
}

let wsTimer = null;
function clearLive() { clearInterval(wsTimer); wsTimer = null; }

async function incidentPage(key, quiet = false) {
  const main = $("#main");
  const drafts = { note: $("#note")?.value || "", open: [...document.querySelectorAll("details[open]")].map((d) => d.dataset.k) };
  if (!quiet) main.innerHTML = `<div class="crumbs"><a href="#/incidents">← Incidents</a></div>${loading(4)}`;
  let ws;
  try { ws = await api(incPath(key)); } catch (e) { main.innerHTML = `<div class="crumbs"><a href="#/incidents">← Incidents</a></div>${errorBox(e.status === 502 ? { message: "This incident could not be found." } : e)}`; return; }
  const sig = JSON.stringify(ws);
  if (quiet && incidentPage.last === sig) return;
  incidentPage.last = sig;
  const i = ws.incident, v = ws.detail?.verdict, w = ws.workflow, t = timing(i);
  const canAct = has("operator");
  const open = isOpen(i);
  let playbooks = [];
  if (canAct) { try { playbooks = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/playbooks`); } catch { /* optional */ } }
  const trace = v?.tool_trace || [];
  const sigs = ws.detail?.signals || [];
  main.innerHTML = `
    <div class="crumbs"><a href="#/incidents">← Incidents</a></div>
    <header class="ws-head">
      <div><h1>${esc(label(i.failure_type))} on ${esc(i.ci_id)}</h1>
        <p class="muted">${esc(i.service)} · first warning ${ago(i.predicted_at)} · ${i.resolved_at ? "risk cleared" : t.left != null ? `fails in ~${Math.max(0, Math.round(t.left))} min` : "no ETA"}</p>
        <div class="chips">${chip(i)}${wfChip(w)}${w.assignee ? `<span class="badge">Assigned to ${esc(w.assignee)}</span>` : ""}${i.outcome ? `<span class="badge">${esc(OUTCOME[i.outcome] || i.outcome)}</span>` : ""}</div></div>
      ${canAct ? `<div class="ws-actions">
        ${w.state === "new" ? `<button class="primary" id="a-ack" type="button">Acknowledge</button>` : ""}
        ${w.state !== "resolved" ? `<button class="secondary" id="a-assign" type="button">${w.assignee ? "Reassign" : "Assign"}</button><button class="secondary" id="a-resolve" type="button">Resolve</button>` : `<button class="secondary" id="a-reopen" type="button">Reopen</button>`}
      </div>` : ""}
    </header>
    ${w.state === "resolved" ? `<div class="banner ok"><strong>Resolved by ${esc(w.resolved_by)}</strong>${w.resolution ? `: ${esc(w.resolution)}` : ""}</div>` : ""}
    <div class="ws-grid">
      <div class="ws-main">
        <section class="card"><header><div><h2>Metric vs failure threshold</h2><p class="muted" id="chart-sub">Loading the series…</p></div><button class="ghost view-toggle" id="vt" type="button" hidden>View table</button></header><div id="chart" class="chart-body"><div class="skeleton" style="height:200px"></div></div></section>
        <section class="card"><header><div><h2>AI analysis</h2><p class="muted">${v ? `${esc(v.model_id)} · ${Math.round(i.confidence * 100)}% confidence${v.tokens_used ? ` · ${v.tokens_used.toLocaleString()} tokens` : ""}${v.latency_ms ? ` · ${(v.latency_ms / 1000).toFixed(0)} s` : ""}` : "Summary"}</p></div></header>
          <div class="pad">${aiBanner(v, i)}
            <h3>Root cause</h3><p class="prose">${esc(i.root_cause)}</p>
            ${i.recommended_actions.length ? `<h3>Recommended fix</h3><ol class="steps-list">${i.recommended_actions.map((a) => `<li><span>${esc(a)}</span>${copyBtn(a)}</li>`).join("")}</ol>` : ""}
            ${i.runbook_ref ? `<h3>Runbook</h3><p><code>${esc(i.runbook_ref)}</code></p>` : ""}
            ${!ws.detail ? `<p class="muted">Detailed investigation data was not captured for this incident (it was raised before this view existed). New incidents include the full evidence and the AI's steps.</p>` : ""}
          </div></section>
        ${v?.evidence?.length ? `<section class="card"><header><div><h2>Evidence</h2><p class="muted">Queries the AI ran and the exact output it relied on</p></div></header><div class="pad evid">${v.evidence.map((e) => `<div class="ev"><div class="ev-q"><code>${esc(e.query || e.log_ref || "")}</code>${copyBtn(e.query || e.log_ref || "")}</div><pre>${esc(e.excerpt)}</pre></div>`).join("")}</div></section>` : ""}
        ${trace.length ? `<section class="card"><header><div><h2>How the AI investigated</h2><p class="muted">${trace.length} read-only step${trace.length > 1 ? "s" : ""}, in order</p></div></header><ol class="trace">${trace.map((s, k) => `<li class="${s.ok ? "" : "bad"}"><span class="n">${k + 1}</span><div>
          <div class="tr-h"><strong>${esc(s.tool.replaceAll("_", " "))}</strong>${s.source ? `<span class="badge">${esc(s.source)}</span>` : ""}${s.ok ? "" : `<span class="chip fail">Failed</span>`}</div>
          ${s.thought ? `<p class="muted">${esc(s.thought)}</p>` : ""}${s.query ? `<div class="ev-q"><code>${esc(s.query)}</code>${copyBtn(s.query)}</div>` : ""}
          <details data-k="t${k}"><summary>Result</summary><pre>${esc(s.result_preview || "(empty)")}</pre></details></div></li>`).join("")}</ol></section>` : ""}
        <section class="card"><header><div><h2>Timeline</h2><p class="muted">What happened, newest first</p></div></header><div class="pad">
          ${canAct ? `<div class="note-box"><textarea id="note" rows="2" maxlength="2000" placeholder="Add a note for the team…" aria-label="Add a note"></textarea><button class="secondary" id="a-note" type="button">Add note</button></div>` : ""}
          <ol class="tl">${timeline(ws).map((e) => `<li class="${esc(e.kind)}"><i aria-hidden="true"></i><div><div><strong>${e.who ? `${esc(e.who)} ` : ""}${esc(e.title)}</strong> <span class="muted">${ago(e.ts)}</span></div>${e.text ? `<p class="${e.kind === "note" ? "note-text" : "muted"}">${esc(e.text)}</p>` : ""}</div></li>`).join("") || `<li class="sys"><i></i><div class="muted">No events yet.</div></li>`}</ol></div></section>
      </div>
      <aside class="ws-side">
        <section class="card"><header><div><h2>At a glance</h2></div></header><div class="pad glance">
          ${runway(i)}
          <dl><dt>Confidence</dt><dd>${Math.round(i.confidence * 100)}%</dd><dt>Service</dt><dd>${esc(i.service)}</dd><dt>Host</dt><dd>${esc(i.ci_id)}</dd><dt>Incident</dt><dd class="key">${esc(i.incident_key)}</dd></dl>
          ${sigs.length ? `<h3>What the detectors saw</h3><ul class="sigs">${sigs.slice(0, 6).map((g) => `<li><strong>${esc(g.detector)}</strong> ${esc(g.metric || g.template || "")}${g.value != null ? ` <span class="muted">now ${esc(g.value)}${g.threshold != null ? ` of ${esc(g.threshold)}` : ""}</span>` : ""}</li>`).join("")}</ul>` : ""}
        </div></section>
        ${ws.detail?.recent_changes?.length ? `<section class="card"><header><div><h2>Recent changes</h2><p class="muted">Often the root cause</p></div></header><div class="pad"><ul class="sigs">${ws.detail.recent_changes.map((c) => `<li><strong>${esc(c.kind)}</strong> ${esc(c.summary)} <span class="muted">${ago(c.ts)}</span></li>`).join("")}</ul></div></section>` : ""}
        ${canAct && open ? `<section class="card"><header><div><h2>Fix</h2><p class="muted">Needs a second person's approval</p></div></header><div class="pad">
          ${ws.remediations.length ? `<ul class="sigs">${ws.remediations.map((r) => `<li><code>${esc(r.playbook)}</code> <span class="chip ${r.status === "executed" ? "ok" : r.status === "rejected" || r.status === "failed" ? "fail" : "untested"}">${esc(r.status)}</span></li>`).join("")}</ul>` : ""}
          ${playbooks.length ? `<label class="field">Playbook<select id="pb">${playbooks.map((p) => `<option>${esc(p)}</option>`).join("")}</select></label><button class="primary" id="propose" type="button">Request approval</button>` : `<p class="muted">No automated playbooks are available.</p>`}</div></section>` : ""}
        ${canAct && !i.outcome ? `<section class="card"><header><div><h2>Was this prediction right?</h2><p class="muted">Your answer tunes thresholds and runbooks</p></div></header><div class="pad row-start">
          <button class="secondary" data-o="true_positive" type="button">Yes, it was real</button><button class="secondary" data-o="false_positive" type="button">No, false alarm</button></div></section>` : ""}
      </aside>
    </div>`;
  // restore what the person was doing across a live refresh
  if (drafts.note) $("#note").value = drafts.note;
  drafts.open.forEach((k) => document.querySelector(`details[data-k="${k}"]`)?.setAttribute("open", ""));
  main.querySelectorAll(".copy").forEach((b) => b.onclick = async () => { try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; }, 1400); } catch { toast("Copy is not available here."); } });
  const run = (fn) => async () => { try { await fn(); } catch (e) { toast(e.message); } incidentPage.last = null; incidentPage(key, true); };
  const post = (p, body) => api(`${incPath(key)}/${p}`, { method: "POST", body: body ? JSON.stringify(body) : undefined });
  $("#a-ack")?.addEventListener("click", run(() => post("ack")));
  $("#a-reopen")?.addEventListener("click", run(() => post("reopen")));
  $("#a-note")?.addEventListener("click", run(async () => { const t = $("#note").value.trim(); if (!t) return; await post("notes", { text: t }); $("#note").value = ""; drafts.note = ""; }));
  $("#a-assign")?.addEventListener("click", run(async () => {
    let people = []; try { people = await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/assignees`); } catch { /* optional */ }
    const names = [...new Set([state.me.sub, ...people.map((p) => p.username)])];
    const v = await formDialog("Assign this incident", `<label class="field">Assign to<select name="assignee"><option value="">Unassigned</option>${names.map((n) => `<option value="${esc(n)}"${n === w.assignee ? " selected" : ""}>${esc(n)}${n === state.me.sub ? " (me)" : ""}</option>`).join("")}</select></label>`, "Assign");
    if (v) await post("assign", { assignee: v.assignee || null });
  }));
  $("#a-resolve")?.addEventListener("click", run(async () => {
    const v = await formDialog("Resolve this incident", `<label class="field">What fixed it? <small>Optional, but it helps the next person.</small><textarea name="resolution" rows="3" maxlength="2000"></textarea></label>`, "Resolve");
    if (v) await post("resolve", { resolution: v.resolution?.trim() || null });
  }));
  main.querySelectorAll("[data-o]").forEach((b) => b.onclick = run(async () => { await api(`${incPath(key)}/outcome`, { method: "POST", body: JSON.stringify({ outcome: b.dataset.o }) }); toast(b.dataset.o === "true_positive" ? "Marked as real" : "Marked as false alarm"); }));
  $("#propose")?.addEventListener("click", run(async () => { await api(`/v1/tenants/${encodeURIComponent(state.tenant)}/remediations`, { method: "POST", body: JSON.stringify({ incident_key: key, failure_type: i.failure_type, playbook: $("#pb").value, params: { ci_id: i.ci_id } }) }); toast("Approval requested"); refreshApprovalsCount(); }));
  // the chart loads separately so the page is usable straight away
  try {
    const s = await api(`${incPath(key)}/series`);
    if (!s.available) { $("#chart").innerHTML = `<div class="empty small"><p>${esc(s.reason)}</p></div>`; $("#chart-sub").textContent = ""; return; }
    $("#chart-sub").textContent = `From ${s.source}${s.eta_minutes != null ? ` · predicted to cross the threshold in ~${Math.round(s.eta_minutes)} min` : ""}`;
    const card = $("#chart").parentElement; $("#vt").hidden = false;
    withTable(card, () => seriesTable(s), (b) => metricChart(b, s));
  } catch { $("#chart").innerHTML = `<div class="empty small"><p>The series could not be loaded.</p></div>`; }
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

// ------------------------------------------------------------------ users & roles (local accounts)
const ROLE_HELP = {
  viewer: "Read-only: incidents, prediction quality, audit log, configuration.",
  operator: "Viewer, plus label outcomes, edit CIs, propose tuning, request and run approved fixes.",
  approver: "Operator, plus approve or reject fix requests (four-eyes).",
  admin: "Approver, plus thresholds, routing rules, model config, remediation policy and user management.",
};

// Modal form: returns the entered values, or null when cancelled. `validate` may return an error string.
function formDialog(title, bodyHtml, ok, validate) {
  const d = $("#form-dialog"), err = $("#form-error");
  $("#form-title").textContent = title; $("#form-body").innerHTML = bodyHtml; $("#form-ok").textContent = ok;
  err.hidden = true;
  return new Promise((resolve) => {
    const submit = (ev) => {
      if (ev.submitter?.value !== "ok") return;
      const values = Object.fromEntries(new FormData($("#form-dialog-form")));
      const problem = validate?.(values);
      if (problem) { ev.preventDefault(); err.textContent = problem; err.hidden = false; return; }
      d.returnValue = "ok"; d.dataset.values = JSON.stringify(values);
    };
    $("#form-dialog-form").addEventListener("submit", submit, { once: true });
    d.addEventListener("close", () => {
      $("#form-dialog-form").removeEventListener("submit", submit);
      const okd = d.returnValue === "ok"; const v = okd ? JSON.parse(d.dataset.values) : null;
      d.dataset.values = ""; $("#form-body").innerHTML = ""; resolve(v);
    }, { once: true });
    d.returnValue = ""; d.showModal();
  });
}

const pwField = (name, labelText, auto) =>
  `<label class="field">${esc(labelText)}<input name="${name}" type="password" autocomplete="${auto}" required></label>`;
const roleOptions = (sel) => ROLES.map((r) => `<option value="${r}"${r === sel ? " selected" : ""}>${r}</option>`).join("");
const MIN_PW = 12;
const pwProblem = (p) => (p.length < MIN_PW ? `Password must be at least ${MIN_PW} characters.` : null);

async function changePassword() {
  const v = await formDialog("Change password",
    pwField("current_password", "Current password", "current-password") + pwField("new_password", "New password (12+ characters)", "new-password") + pwField("confirm", "Confirm new password", "new-password"),
    "Change password",
    (x) => pwProblem(x.new_password) || (x.new_password !== x.confirm ? "The new passwords do not match." : null));
  if (!v) return;
  try {
    const out = await api("/v1/auth/change-password", { method: "POST", body: JSON.stringify({ current_password: v.current_password, new_password: v.new_password }) });
    state.token = out.access_token; store.set("token", state.token);
    toast("Password changed.");
  } catch (e) { toast(e.message); }
}

async function users() {
  const main = $("#main");
  if (!has("admin") || state.config.auth !== "local") { main.innerHTML = `<div class="panel">${empty("Not available", "User management needs an administrator account with local sign-in enabled.")}</div>`; return; }
  main.innerHTML = `<div class="page-head"><div><h1>Users</h1><p>Accounts that can sign in to this console. Role and tenant changes apply on the next request; disabling an account signs it out immediately.</p></div>
    <button class="primary" id="add-user" type="button">Add user</button></div>
    <div id="us">${loading(4)}</div>
    <div class="panel"><h2>Roles</h2><dl class="roles">${ROLES.map((r) => `<dt>${r}</dt><dd>${esc(ROLE_HELP[r])}</dd>`).join("")}</dl></div>`;
  $("#add-user").onclick = addUser;
  let rows;
  try { rows = await api("/v1/users"); } catch (e) { $("#us").innerHTML = errorBox(e); return; }
  const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  $("#us").innerHTML = `<div class="panel table-wrap"><table>
    <thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Tenants</th><th scope="col">Status</th><th scope="col">Last sign-in</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
    <tbody>${rows.map((u) => {
      const self = u.username === state.me.sub;
      return `<tr data-u="${esc(u.username)}">
        <td><strong>${esc(u.username)}</strong>${u.display_name ? `<div class="muted">${esc(u.display_name)}</div>` : ""}${self ? ` <span class="muted">(you)</span>` : ""}</td>
        <td><select class="u-role" aria-label="Role for ${esc(u.username)}"${self ? " disabled" : ""}>${roleOptions(u.role)}</select></td>
        <td>${u.tenants.map((t) => `<code>${esc(t)}</code>`).join(" ")}</td>
        <td>${u.disabled ? "Disabled" : u.locked ? "Locked" : "Active"}</td>
        <td class="num">${u.last_login ? esc(fmt.format(new Date(u.last_login))) : "Never"}</td>
        <td class="row-end">
          <button class="ghost u-pw" type="button">Reset password</button>
          ${u.locked ? `<button class="ghost u-unlock" type="button">Unlock</button>` : ""}
          ${self ? "" : `<button class="ghost u-toggle" type="button">${u.disabled ? "Enable" : "Disable"}</button><button class="ghost danger u-del" type="button">Delete</button>`}
        </td></tr>`;
    }).join("")}</tbody></table></div>`;
  const act = async (fn) => { try { await fn(); } catch (e) { toast(e.message); } users(); };
  document.querySelectorAll("#us tr[data-u]").forEach((tr) => {
    const name = tr.dataset.u, u = rows.find((x) => x.username === name), url = `/v1/users/${encodeURIComponent(name)}`;
    const patch = (body) => api(url, { method: "PATCH", body: JSON.stringify(body) });
    tr.querySelector(".u-role").onchange = (ev) => act(async () => { await patch({ role: ev.target.value }); toast(`${name} is now ${ev.target.value}.`); });
    tr.querySelector(".u-pw").onclick = () => act(async () => {
      const v = await formDialog(`Reset password for ${name}`, pwField("new_password", "New password (12+ characters)", "new-password"), "Reset password", (x) => pwProblem(x.new_password));
      if (!v) return;
      await api(`${url}/password`, { method: "POST", body: JSON.stringify({ new_password: v.new_password }) });
      toast(`Password reset for ${name}. Their sessions were signed out.`);
    });
    tr.querySelector(".u-unlock")?.addEventListener("click", () => act(() => patch({ unlock: true })));
    tr.querySelector(".u-toggle")?.addEventListener("click", () => act(async () => {
      if (!u.disabled && !(await confirmDialog(`Disable ${name}?`, "They will be signed out immediately and cannot sign in until re-enabled.", "Disable"))) return;
      await patch({ disabled: !u.disabled });
    }));
    tr.querySelector(".u-del")?.addEventListener("click", () => act(async () => {
      if (!(await confirmDialog(`Delete ${name}?`, "This permanently removes the account. Audit entries they created are kept.", "Delete"))) return;
      await api(url, { method: "DELETE" });
    }));
  });
}

async function addUser() {
  let tenants = [];
  try { tenants = await api("/v1/tenants"); } catch { /* shown by the form validation below */ }
  const platform = (state.me.tenants || []).includes("*");
  const v = await formDialog("Add user", `
      <label class="field">Username<input name="username" autocomplete="off" autocapitalize="none" required pattern="[a-z0-9][a-z0-9._-]{2,63}" title="3-64 characters: lowercase letters, digits, dot, underscore, hyphen"></label>
      <label class="field">Display name (optional)<input name="display_name" autocomplete="off"></label>
      <label class="field">Role<select name="role">${roleOptions("viewer")}</select></label>
      <fieldset class="field"><legend>Tenants</legend>
        ${platform ? `<label class="check"><input type="checkbox" name="all" value="1"> All tenants (platform user)</label>` : ""}
        ${tenants.map((t) => `<label class="check"><input type="checkbox" name="t:${esc(t.id)}" value="1"> ${esc(t.name)} <span class="muted">${esc(t.id)}</span></label>`).join("") || `<span class="muted">No tenants yet.</span>`}
      </fieldset>
      ${pwField("password", "Initial password (12+ characters)", "new-password")}`,
    "Create user",
    (x) => pwProblem(x.password) || (!x.all && !Object.keys(x).some((k) => k.startsWith("t:")) ? "Choose at least one tenant." : null));
  if (!v) return;
  const body = {
    username: v.username.trim().toLowerCase(), password: v.password, role: v.role, display_name: v.display_name || null,
    tenants: v.all ? ["*"] : Object.keys(v).filter((k) => k.startsWith("t:")).map((k) => k.slice(2)),
  };
  try { await api("/v1/users", { method: "POST", body: JSON.stringify(body) }); toast(`Created ${body.username}.`); } catch (e) { toast(e.message); }
  users();
}

// ------------------------------------------------------------------ overview (dashboard)
async function checkStatus() {
  const dot = $("#status .dot"), txt = $("#status-text");
  try {
    const r = await fetch(`${API}/readyz`, { cache: "no-store" });
    dot.className = `dot ${r.ok ? "ok" : "fail"}`; txt.textContent = r.ok ? "All systems operational" : "Control plane degraded";
  } catch { dot.className = "dot fail"; txt.textContent = "Control plane unreachable"; }
}

// One shared tooltip. Content is set with textContent: labels come from API data and are untrusted.
function tip(el, title, value) {
  const t = $("#tip");
  const show = (x, y) => {
    t.replaceChildren(Object.assign(document.createElement("strong"), { textContent: value }), Object.assign(document.createElement("span"), { textContent: title }));
    t.hidden = false;
    const w = t.offsetWidth, h = t.offsetHeight;
    t.style.left = `${Math.min(Math.max(8, x - w / 2), innerWidth - w - 8)}px`; t.style.top = `${Math.max(8, y - h - 12)}px`;
  };
  const at = () => { const b = el.getBoundingClientRect(); return [b.left + b.width / 2, b.top]; };
  el.addEventListener("pointermove", (e) => show(e.clientX, el.getBoundingClientRect().top));
  el.addEventListener("pointerleave", () => { t.hidden = true; });
  el.addEventListener("focus", () => show(...at()));
  el.addEventListener("blur", () => { t.hidden = true; });
}
const niceMax = (n) => { if (n <= 4) return 4; const p = 10 ** Math.floor(Math.log10(n)); const m = [1, 2, 2.5, 5, 10].find((f) => f * p >= n); return m * p; };

// Column chart: one series, one hue, <=24px thick marks, 4px rounded cap, hairline grid.
function columnChart(box, days) {
  const max = niceMax(Math.max(0, ...days.map((d) => d.value))), peak = Math.max(...days.map((d) => d.value));
  box.innerHTML = `<div class="cols" role="img" aria-label="Predictions per day, last ${days.length} days">
    <div class="grid" aria-hidden="true">${[1, 0.5, 0].map((f) => `<div class="gl"><span>${Math.round(max * f)}</span></div>`).join("")}</div>
    <div class="bars">${days.map((d, i) => `<div class="col" tabindex="0" data-i="${i}" aria-label="${esc(d.title)}: ${d.value}">
        <div class="mark" style="height:${(d.value / max) * 100}%">${d.value && d.value === peak ? `<b>${d.value}</b>` : ""}</div>
        <small>${(days.length - 1 - i) % 3 === 0 ? esc(d.label) : ""}</small></div>`).join("")}</div></div>`;
  box.querySelectorAll(".col").forEach((c) => { const d = days[c.dataset.i]; tip(c, d.title, `${d.value} prediction${d.value === 1 ? "" : "s"}`); });
}

// Ranked horizontal bars (part-to-whole that must be compared): one hue, value at the tip.
function rankedBars(box, rows, total) {
  const max = Math.max(...rows.map((r) => r.value));
  box.innerHTML = `<ul class="ranked">${rows.map((r, i) => `<li tabindex="0" data-i="${i}" aria-label="${esc(r.label)}: ${r.value}">
      <span class="rl">${esc(r.label)}</span><span class="rt"><i style="width:${(r.value / max) * 100}%"></i></span><span class="rv num">${r.value}</span></li>`).join("")}</ul>`;
  box.querySelectorAll("li").forEach((li) => { const r = rows[li.dataset.i]; tip(li, r.label, `${r.value} · ${Math.round((r.value / total) * 100)}% of predictions`); });
}

// "View as table" keeps every value reachable without hovering.
function withTable(card, toTable, draw) {
  const body = card.querySelector(".chart-body"), btn = card.querySelector(".view-toggle");
  let table = false;
  const render = () => { if (table) body.innerHTML = toTable(); else draw(body); btn.textContent = table ? "View chart" : "View table"; btn.setAttribute("aria-pressed", String(table)); };
  btn.onclick = () => { table = !table; render(); };
  render();
}
const tbl = (head, rows) => `<div class="table-wrap"><table><thead><tr>${head.map((h) => `<th scope="col">${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td class="num">${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;

const tile = (href, value, text, cls = "") => `<a class="tile ${cls}" href="${href}"><span class="num">${value}</span><span>${esc(text)}</span></a>`;
const cardShell = (title, sub, extra = "") => `<section class="card"><header><div><h2>${esc(title)}</h2>${sub ? `<p class="muted">${esc(sub)}</p>` : ""}</div>${extra}</header>`;

async function overview() {
  const main = $("#main"), tenant = encodeURIComponent(state.tenant);
  const tname = $("#tenant").selectedOptions[0]?.textContent || state.tenant;
  main.innerHTML = `<div class="page-head"><div><h1>Overview</h1><p>${esc(tname)} at a glance: what is about to fail, how well predictions are performing, and the health of connected systems.</p></div>
    <div class="row-end"><span class="muted" id="upd"></span><button class="secondary" id="refresh" type="button">Refresh</button></div></div><div id="ov">${loading(3)}</div>`;
  $("#refresh").onclick = overview;
  const [inc, kpi, rem, con, aud] = await Promise.allSettled([
    api(`/v1/tenants/${tenant}/incidents`), api(`/v1/tenants/${tenant}/kpis`), api(`/v1/tenants/${tenant}/remediations`),
    api(`/v1/tenants/${tenant}/connections`), api(`/v1/tenants/${tenant}/audit?limit=6`)]);
  if ([inc, kpi, rem, con, aud].every((r) => r.status === "rejected")) { $("#ov").innerHTML = errorBox(inc.reason); return; }
  const ok = (r) => (r.status === "fulfilled" ? r.value : null);
  const incs = ok(inc), kpis = ok(kpi), rems = ok(rem), conns = ok(con), audits = ok(aud);
  const open = (incs || []).filter(isOpen);
  const soon = open.filter((i) => { const l = timing(i).left; return l != null && l < 15; });
  const review = open.filter((i) => i.status !== "verified" && !i.outcome);
  const pending = (rems || []).filter((r) => r.status === "proposed").length;
  const leads = (incs || []).map((i) => i.lead_time_minutes).filter((x) => x != null).sort((a, b) => a - b);
  const median = leads.length ? leads[Math.floor(leads.length / 2)] : null;
  const unavailable = `<div class="error" role="alert">This section is unavailable right now. Try Refresh.</div>`;

  $("#ov").innerHTML = `
    <div class="tiles">
      ${incs ? tile("#/incidents", soon.length, "predicted to fail within 15 min", soon.length ? "crit" : "") + tile("#/incidents", open.length, "open incidents") + tile("#/incidents", review.length, "waiting for a human decision", review.length ? "warn" : "")
        : `<div class="tile">${unavailable}</div>`}
      ${rems ? tile("#/approvals", pending, "fix requests awaiting approval", pending ? "warn" : "") : ""}
      ${incs ? tile("#/quality", median != null ? `${Math.round(median)}<small> min</small>` : "—", "median warning before failure") : ""}
    </div>
    <div class="grid2">
      ${cardShell("Predictions, last 14 days", "Candidate incidents raised per day", `<button class="ghost view-toggle" id="vt1" type="button" aria-pressed="false"></button>`)}<div class="chart-body" id="c1"></div></section>
      ${cardShell("By failure type", "Share of predictions in the last 14 days", `<button class="ghost view-toggle" id="vt2" type="button" aria-pressed="false"></button>`)}<div class="chart-body" id="c2"></div></section>
    </div>
    <div class="grid2">
      ${cardShell("Needs attention", "Open incidents, least time left first", `<a href="#/incidents" class="more">All incidents</a>`)}<div id="attn"></div></section>
      ${cardShell("Prediction quality", "From incidents your team labelled", `<a href="#/quality" class="more">Details</a>`)}<div id="qual"></div></section>
    </div>
    <div class="grid2">
      ${cardShell("Data sources", "Connected systems and their last test", `<a href="#/connections" class="more">Manage</a>`)}<div id="src"></div></section>
      ${cardShell("Recent activity", "Latest changes and decisions", `<a href="#/audit" class="more">Audit log</a>`)}<div id="act"></div></section>
    </div>`;
  $("#upd").textContent = `Updated ${clock(Date.now())}`;

  // charts
  const DAYS = 14, day0 = new Date(); day0.setHours(0, 0, 0, 0);
  const fmtDay = new Intl.DateTimeFormat(undefined, { day: "numeric", month: "short" }), fmtLong = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "numeric", month: "short" });
  const days = Array.from({ length: DAYS }, (_, k) => { const d = new Date(day0); d.setDate(d.getDate() - (DAYS - 1 - k)); return { start: d.getTime(), label: fmtDay.format(d), title: fmtLong.format(d), value: 0 }; });
  const recent = (incs || []).filter((i) => Date.parse(i.predicted_at) >= days[0].start);
  recent.forEach((i) => { const t = Date.parse(i.predicted_at); const d = days.findLast((x) => x.start <= t); if (d) d.value++; });
  if (!incs) { $("#c1").innerHTML = unavailable; $("#c2").innerHTML = unavailable; $("#vt1").hidden = $("#vt2").hidden = true; }
  else if (!recent.length) {
    $("#c1").innerHTML = `<div class="empty small"><p>No predictions in the last 14 days.</p></div>`; $("#c2").innerHTML = `<div class="empty small"><p>Nothing to break down yet.</p></div>`; $("#vt1").hidden = $("#vt2").hidden = true;
  } else {
    withTable($("#c1").parentElement, () => tbl(["Day", "Predictions"], days.map((d) => [d.title, d.value])), (b) => columnChart(b, days));
    const by = {}; recent.forEach((i) => { by[i.failure_type] = (by[i.failure_type] || 0) + 1; });
    const rows = Object.entries(by).map(([k, v]) => ({ label: label(k), value: v })).sort((a, b) => b.value - a.value);
    withTable($("#c2").parentElement, () => tbl(["Failure type", "Predictions"], rows.map((r) => [r.label, r.value])), (b) => rankedBars(b, rows, recent.length));
  }

  // needs attention
  const attn = [...open].sort((a, b) => (timing(a).left ?? 1e9) - (timing(b).left ?? 1e9)).slice(0, 5);
  $("#attn").innerHTML = !incs ? unavailable : attn.length ? `<ul class="mini">${attn.map((i) => `<li><a href="#/incidents/${encodeURIComponent(i.incident_key)}"><div><strong>${esc(i.ci_id)}</strong> <span class="muted">${esc(label(i.failure_type))}</span></div>${runway(i)}</a></li>`).join("")}</ul>`
    : empty("All clear", "No open predictions right now.");

  // quality
  const tp = (kpis || []).reduce((a, k) => a + k.true_positives, 0), fp = (kpis || []).reduce((a, k) => a + k.false_positives, 0), ms = (kpis || []).reduce((a, k) => a + k.missed, 0);
  $("#qual").innerHTML = !kpis ? unavailable : tp + fp + ms === 0 ? empty("No labelled outcomes yet", "Mark incidents as real or false alarms to measure precision and recall.")
    : `<div class="qual"><div><span>Precision <small class="muted">target 70%</small></span>${meter(tp + fp ? tp / (tp + fp) : null, 0.7)}</div>
        <div><span>Recall <small class="muted">target 80%</small></span>${meter(tp + ms ? tp / (tp + ms) : null, 0.8)}</div>
        <p class="muted">${tp} real · ${fp} false alarm${fp === 1 ? "" : "s"} · ${ms} missed</p></div>`;

  // sources
  const good = (conns || []).filter((c) => c.enabled && c.last_test_ok === true), bad = (conns || []).filter((c) => c.enabled && c.last_test_ok === false), untested = (conns || []).filter((c) => c.enabled && c.last_test_ok == null);
  $("#src").innerHTML = !conns ? unavailable : !conns.length ? empty("No data sources", has("admin") ? "Connect your logs, metrics and dashboards to get started." : "An administrator can connect data sources.")
    : `<div class="srcs"><div><span class="dot ok"></span><strong class="num">${good.length}</strong> connected</div><div><span class="dot fail"></span><strong class="num">${bad.length}</strong> failing</div><div><span class="dot untested"></span><strong class="num">${untested.length}</strong> not tested</div></div>
      ${bad.length ? `<ul class="mini plain">${bad.map((c) => `<li><strong>${esc(c.name)}</strong><span class="muted">${esc(c.last_test_message || "Test failed")}</span></li>`).join("")}</ul>` : ""}`;

  // activity
  const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  $("#act").innerHTML = !audits ? unavailable : !audits.length ? empty("No activity yet", "Changes and decisions are recorded here.")
    : `<ul class="mini plain">${audits.map((a) => `<li><div><strong>${esc(a.actor)}</strong> <code>${esc(a.action)}</code> <span class="muted">${esc(a.detail?.name || a.target)}</span></div><span class="muted num">${esc(fmt.format(new Date(a.ts)))}</span></li>`).join("")}</ul>`;
}

// ------------------------------------------------------------------ connections (data sources)
const CATEGORIES = ["logs", "metrics", "traces", "dashboards", "other"];
const CAT_LABEL = { logs: "Logs", metrics: "Metrics", traces: "Traces", dashboards: "Dashboards", other: "Other" };
const AUTH_LABEL = { none: "No authentication", basic: "Username and password", bearer: "Bearer token", header: "Custom header" };
const connPath = () => `/v1/tenants/${encodeURIComponent(state.tenant)}/connections`;
async function loadKinds() { if (!state.kinds) state.kinds = await api("/v1/connection-kinds"); return state.kinds; }

function health(c) {
  if (!c.enabled) return { cls: "off", dot: "", html: "Disabled" };
  if (c.last_test_ok === true) return { cls: "ok", dot: "ok", html: `<strong>Connected</strong> · tested ${ago(c.last_test_at)}` };
  if (c.last_test_ok === false) return { cls: "fail", dot: "fail", html: `<strong>Failed</strong> · ${esc(c.last_test_message || "")}` };
  return { cls: "untested", dot: "untested", html: "Not tested yet" };
}

function kindTiles() {
  return `<div class="kinds">${state.kinds.map((k) => `<button class="kind" type="button" data-kind="${esc(k.id)}">
    <span class="cat">${esc(CAT_LABEL[k.category])}</span><strong>${esc(k.label)}</strong><span>${esc(k.hint)}</span></button>`).join("")}</div>`;
}

async function connections() {
  const main = $("#main");
  const admin = has("admin");
  main.innerHTML = `<div class="page-head"><div><h1>Connections</h1>
    <p>Register and verify the systems your logs, metrics, traces and dashboards live in. Credentials are encrypted and never shown again.</p></div>
    ${admin ? `<button class="primary" id="add-conn" type="button">Add connection</button>` : ""}</div><div id="cn">${loading(3)}</div>`;
  let rows;
  try { [rows] = await Promise.all([api(connPath()), loadKinds()]); } catch (e) { $("#cn").innerHTML = errorBox(e); return; }
  if (admin) $("#add-conn").onclick = () => pickKind();
  if (!rows.length) {
    $("#cn").innerHTML = admin
      ? `<div class="panel pad"><h2>Connect your first data source</h2>
          <p class="muted" style="margin:6px 0 18px">Choose a system to connect. You can test it before saving, and edit or delete it any time.</p>${kindTiles()}</div>`
      : `<div class="panel">${empty("No connections yet", "An administrator can connect log, metric and dashboard systems for this tenant.")}</div>`;
    $("#cn").querySelectorAll("[data-kind]").forEach((b) => b.onclick = () => connForm(b.dataset.kind));
    return;
  }
  const by = Object.groupBy ? Object.groupBy(rows, (r) => r.category) : rows.reduce((a, r) => ((a[r.category] ||= []).push(r), a), {});
  const kindLabel = Object.fromEntries(state.kinds.map((k) => [k.id, k.label]));
  $("#cn").innerHTML = CATEGORIES.filter((c) => by[c]?.length).map((c) => `
    <div class="section-title"><h2>${CAT_LABEL[c]}</h2><span>${by[c].length}</span></div>
    <ul class="panel conns">${by[c].map((r) => { const h = health(r); return `
      <li class="conn" data-id="${esc(r.id)}">
        <span class="dot ${h.dot}" aria-hidden="true"></span>
        <div><div class="name">${esc(r.name)} <span class="badge">${esc(kindLabel[r.kind] || r.kind)}</span>${r.auth_type !== "none" ? `<span class="badge">${r.has_secret ? "Credential saved" : AUTH_LABEL[r.auth_type]}</span>` : ""}</div>
          <div class="url">${esc(r.url)}</div></div>
        <div class="health ${h.cls}">${h.html}</div>
        <div class="actions">
          ${has("operator") ? `<button class="ghost" data-a="test" type="button">Test</button>` : ""}
          ${admin ? `<button class="ghost" data-a="edit" type="button">Edit</button><button class="ghost danger" data-a="delete" type="button">Delete</button>` : ""}
        </div></li>`; }).join("")}</ul>`).join("");
  $("#cn").querySelectorAll(".conn").forEach((li) => {
    const c = rows.find((r) => r.id === li.dataset.id);
    li.querySelector('[data-a="edit"]')?.addEventListener("click", () => connForm(c.kind, c));
    li.querySelector('[data-a="delete"]')?.addEventListener("click", async () => {
      if (!(await confirmDialog(`Delete ${c.name}?`, "The saved connection and its credential are removed. Data already collected is not deleted.", "Delete"))) return;
      try { await api(`${connPath()}/${c.id}`, { method: "DELETE" }); toast(`Deleted ${c.name}.`); } catch (e) { toast(e.message); }
      connections();
    });
    const t = li.querySelector('[data-a="test"]');
    if (t) t.onclick = async () => {
      t.disabled = true; t.textContent = "Testing…";
      try { const r = await api(`${connPath()}/${c.id}/test`, { method: "POST" }); toast(r.ok ? `${c.name}: ${r.message}` : `${c.name}: ${r.message}`); } catch (e) { toast(e.message); }
      connections();
    };
  });
}

function pickKind() {
  openDrawer(`<header><div><h2 id="drawer-title">Add a connection</h2><p class="muted">What do you want to connect?</p></div>
    <button class="close" type="button" aria-label="Close">×</button></header>${kindTiles()}`);
  $("#drawer .close").onclick = closeDrawer;
  $("#drawer-body").querySelectorAll("[data-kind]").forEach((b) => b.onclick = () => connForm(b.dataset.kind));
}

function connForm(kindId, ex) {
  const k = state.kinds.find((x) => x.id === kindId);
  const edit = !!ex;
  const keep = { username: ex?.username || "", header_name: ex?.header_name || "", secret: "" };
  openDrawer(`<header><div><h2 id="drawer-title">${edit ? "Edit" : "Add"} ${esc(k.label)}</h2><p class="muted">${esc(k.hint)}</p></div>
      <button class="close" type="button" aria-label="Close">×</button></header>
    ${edit ? "" : `<button class="ghost back" id="back" type="button">← Choose a different type</button>`}
    <form id="cf" class="form-grid" novalidate>
      <label class="field">Name<input name="name" required maxlength="100" placeholder="e.g. Production ${esc(k.label)}" value="${esc(ex?.name || "")}"></label>
      <label class="field">URL<input name="url" required inputmode="url" spellcheck="false" placeholder="${esc(k.example_url)}" value="${esc(ex?.url || "")}">
        <small>Where it listens, including the port. Put credentials below, not in the URL.</small></label>
      <label class="field">Authentication<select name="auth_type">${Object.entries(AUTH_LABEL).map(([v, l]) => `<option value="${v}"${(ex?.auth_type || "none") === v ? " selected" : ""}>${l}</option>`).join("")}</select></label>
      <div id="auth-fields" class="form-grid"></div>
      ${k.extra_fields.map((f) => `<label class="field">${esc(f.label)}<input name="x:${esc(f.key)}" value="${esc(ex?.extra?.[f.key] || "")}"></label>`).join("")}
      ${(k.bool_fields || []).map((f) => `<label class="check"><input type="checkbox" name="b:${esc(f.key)}"${ex?.extra?.[f.key] === "true" ? " checked" : ""}><span>${esc(f.label)}</span></label>`).join("")}
      <label class="check"><input type="checkbox" name="verify_tls"${ex?.verify_tls === false ? "" : " checked"}><span>Verify the TLS certificate<br><small class="muted">Turn off only for self-signed certificates on trusted internal hosts.</small></span></label>
      <label class="check"><input type="checkbox" name="enabled"${ex?.enabled === false ? "" : " checked"}><span>Enabled</span></label>
      <div id="tr" aria-live="polite"></div>
      <div class="row-end"><button type="button" class="secondary" id="ttest">Test connection</button>
        <button type="submit" class="primary" id="csave">${edit ? "Save changes" : "Add connection"}</button></div>
    </form>`);
  $("#drawer .close").onclick = closeDrawer;
  if (!edit) $("#back").onclick = pickKind;
  const form = $("#cf");
  const secretPh = edit && ex.has_secret ? "Saved. Leave blank to keep it" : "";
  const renderAuth = () => {
    const t = form.auth_type.value, box = $("#auth-fields");
    box.innerHTML = t === "basic" ? `<label class="field">Username<input name="username" autocomplete="off" value="${esc(keep.username)}"></label>
        <label class="field">Password<input name="secret" type="password" autocomplete="new-password" placeholder="${esc(secretPh)}"></label>`
      : t === "bearer" ? `<label class="field">Token<input name="secret" type="password" autocomplete="new-password" placeholder="${esc(secretPh)}"></label>`
      : t === "header" ? `<label class="field">Header name<input name="header_name" autocomplete="off" placeholder="X-API-Key" value="${esc(keep.header_name)}"></label>
        <label class="field">Header value<input name="secret" type="password" autocomplete="new-password" placeholder="${esc(secretPh)}"></label>` : "";
  };
  form.auth_type.onchange = () => { keep.username = form.username?.value ?? keep.username; keep.header_name = form.header_name?.value ?? keep.header_name; renderAuth(); };
  renderAuth();
  const collect = () => {
    const f = form, type = f.auth_type.value;
    const extra = {};
    k.extra_fields.forEach((x) => { const v = f.elements[`x:${x.key}`].value.trim(); if (v) extra[x.key] = v; });
    (k.bool_fields || []).forEach((x) => { extra[x.key] = f.elements[`b:${x.key}`].checked ? "true" : "false"; });
    return {
      name: f.name.value.trim(), kind: k.id, url: f.url.value.trim(), auth_type: type,
      username: type === "basic" ? (f.username?.value.trim() || null) : null,
      header_name: type === "header" ? (f.header_name?.value.trim() || null) : null,
      secret: type !== "none" && f.secret?.value ? f.secret.value : null,
      verify_tls: f.verify_tls.checked, enabled: f.enabled.checked, extra,
    };
  };
  const problem = (b) => !b.name ? "Give the connection a name." : !/^https?:\/\/\S+$/i.test(b.url) ? "Enter a URL starting with http:// or https://." : null;
  const show = (cls, html) => { $("#tr").innerHTML = html ? `<div class="testbox ${cls}" role="${cls === "fail" ? "alert" : "status"}">${html}</div>` : ""; };
  $("#ttest").onclick = async () => {
    const b = collect(), p = problem(b);
    if (p) return show("fail", esc(p));
    $("#ttest").disabled = true; show("busy", "Testing the connection…");
    try {
      const r = await api(`${connPath()}/test`, { method: "POST", body: JSON.stringify({ ...b, id: ex?.id || null }) });
      show(r.ok ? "ok" : "fail", `<strong>${r.ok ? "Connected" : "Not connected"}</strong>${r.latency_ms != null ? ` · ${r.latency_ms} ms` : ""}<br>${esc(r.message)}`);
    } catch (e) { show("fail", esc(e.message)); }
    $("#ttest").disabled = false;
  };
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    const b = collect(), p = problem(b);
    if (p) return show("fail", esc(p));
    $("#csave").disabled = true;
    try {
      await api(edit ? `${connPath()}/${ex.id}` : connPath(), { method: edit ? "PUT" : "POST", body: JSON.stringify(b) });
      toast(edit ? "Connection updated." : "Connection added. Use Test to check it.");
      closeDrawer(); connections();
    } catch (e) { $("#csave").disabled = false; show("fail", esc(e.message)); }
  };
}

// ------------------------------------------------------------------ get started (empty tenant)
async function getStarted() {
  let n = 0;
  try { n = (await api(connPath())).length; } catch { /* optional */ }
  const admin = has("admin"), local = state.config.auth === "local";
  const step = (i, done, title, text, href, cta) => `<li class="step ${done ? "done" : ""}"><span class="n">${done ? "✓" : i}</span>
    <div><h3>${esc(title)}</h3><p>${esc(text)}</p></div>${href ? `<a class="secondary" style="text-decoration:none;padding:8px 14px;border:1px solid var(--cassava-mist);border-radius:6px;font:700 13px var(--font-display);color:var(--cassava-navy)" href="${href}">${esc(cta)}</a>` : ""}</li>`;
  return `<div class="panel" style="margin-bottom:22px"><h2 style="padding:18px 20px 4px">Get started</h2><ol class="steps">
    ${step(1, n > 0, "Connect your data sources", n ? `${n} connection${n > 1 ? "s" : ""} registered.` : "Register the log, metric and dashboard systems this tenant relies on.", "#/connections", n ? "Manage" : "Add a connection")}
    ${admin && local ? step(2, false, "Invite your team", "Create accounts and choose what each person can do.", "#/users", "Manage users") : ""}
    ${step(admin && local ? 3 : 2, false, "Wait for the first prediction", "When detectors flag a candidate incident it appears here with the AI's root cause and the time left.", "", "")}
  </ol></div>`;
}

// ------------------------------------------------------------------ start
(async function start() {
  try { state.config = await (await fetch("config.json")).json(); } catch { state.config = {}; }
  try { if (state.config.oidc) await oidcCallback(); } catch (e) { return renderSignIn(e.message); }
  state.token = store.get("token");
  if (!state.token) return renderSignIn();
  try { await boot(); } catch (e) { if (e.status !== 401) renderSignIn(e.message); }
})();
