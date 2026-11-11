# ADR-0014: Operator console and the Cassava brand system

- Status: accepted · Date: 2026-11-11

## Context
Operators need one place to see predicted incidents, label outcomes and approve fixes. Grafana
covers telemetry, but not workflows with RBAC (four-eyes approval, labelling). All visual output
must follow the Cassava brand (theme "Cassava": navy #001C57, mint #00F19C, Montserrat/Arial).

## Decision
- A dependency-free static console (`ui/console`: HTML, CSS, one ES module) served by
  control-plane-api at `/console`, talking only to the control-plane API on the same origin.
  No build step, no npm runtime dependencies, nothing to patch in a supply-chain sense.
- The control plane proxies the feedback service (`/v1/tenants/{t}/incidents|kpis`, outcome
  labelling) so every read and write is authenticated, RBAC-checked, tenant-scoped and audited.
- Sign-in: OIDC authorization code + PKCE (public client) when configured; pasted bearer token in dev.
  Tokens live in `sessionStorage` only; authorisation is always enforced server-side.
- `brand/` is the single source of tokens, fonts (Montserrat WOFF2, SIL OFL) and logos, reused by
  the console, Grafana dashboard headers/series colours and the demo media.
- Mint is used only on navy (it fails contrast on white); on light surfaces the deep mint
  `#00B377` and navy carry state. Amber/red were added for warnings because the theme has none.

## Consequences
Grafana OSS cannot be re-skinned (white-labelling is an Enterprise feature); dashboards carry a
branded header panel and brand series colours instead.
