# ADR-0013: OIDC bearer tokens with hierarchical RBAC

- Status: accepted · Date: 2026-11-11

## Decision
JWTs verified against the IdP JWKS (issuer, audience, exp/iat/sub required); roles
viewer < operator < approver < admin from a configurable claim path (e.g. Keycloak
`realm_access.roles`); tenant scope from a `tenants` claim (`*` = platform admin).
A `dev` HS256 mode exists for Compose and is refused when `environment=prod`.
