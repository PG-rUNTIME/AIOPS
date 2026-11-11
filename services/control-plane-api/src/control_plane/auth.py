"""OAuth2/OIDC bearer authentication with role-based access and tenant scoping.

* ``oidc`` mode: JWT verified against the IdP's JWKS (Keycloak, Entra ID, Okta…),
  issuer and audience checked; roles from ``roles_claim`` (dotted path, e.g.
  ``realm_access.roles`` for Keycloak), tenants from ``tenants_claim``.
* ``dev`` mode: HS256 tokens signed with a local secret (``make token``). Refused
  when ``environment`` is ``prod``.
Roles are hierarchical: viewer < operator < approver < admin.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Literal

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, SecretStr

ROLES = ("viewer", "operator", "approver", "admin")
Role = Literal["viewer", "operator", "approver", "admin"]


class AuthSettings(BaseModel):
    mode: Literal["oidc", "dev"] = "oidc"
    issuer: str | None = None
    audience: str = "aiops-control-plane"
    jwks_url: str | None = None
    roles_claim: str = "roles"
    tenants_claim: str = "tenants"
    dev_secret: SecretStr | None = None


@dataclass(frozen=True)
class Principal:
    sub: str
    roles: frozenset[str]
    tenants: frozenset[str]

    def level(self) -> int:
        return max((ROLES.index(r) for r in self.roles if r in ROLES), default=-1)

    def has(self, role: Role) -> bool:
        return self.level() >= ROLES.index(role)

    def can_access(self, tenant: str) -> bool:
        return "*" in self.tenants or tenant in self.tenants


def _claim(claims: dict[str, Any], path: str) -> Any:
    cur: Any = claims
    for part in path.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


class Authenticator:
    def __init__(self, s: AuthSettings, environment: str) -> None:
        if s.mode == "dev" and environment == "prod":
            raise RuntimeError("dev auth mode is not allowed in prod")
        if s.mode == "dev" and (s.dev_secret is None or len(s.dev_secret.get_secret_value()) < 32):
            raise RuntimeError("AIOPS_AUTH__DEV_SECRET must be set to at least 32 characters")
        if s.mode == "oidc" and not (s.issuer and s.jwks_url):
            raise RuntimeError("oidc mode requires AIOPS_AUTH__ISSUER and AIOPS_AUTH__JWKS_URL")
        self.s = s

    @cached_property
    def _jwks(self) -> jwt.PyJWKClient:
        if not self.s.jwks_url:
            raise RuntimeError("AIOPS_AUTH__JWKS_URL required in oidc mode")
        return jwt.PyJWKClient(self.s.jwks_url, cache_keys=True)

    def decode(self, token: str) -> Principal:
        try:
            if self.s.mode == "dev":
                assert self.s.dev_secret is not None
                claims = jwt.decode(
                    token,
                    self.s.dev_secret.get_secret_value(),
                    options={"require": ["exp", "iat", "sub"]},
                    algorithms=["HS256"],
                    audience=self.s.audience,
                )
            else:
                key = self._jwks.get_signing_key_from_jwt(token).key
                claims = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256", "ES256", "PS256"],
                    audience=self.s.audience,
                    issuer=self.s.issuer,
                    options={"require": ["exp", "iat", "sub"]},
                )
        except jwt.PyJWTError as e:
            raise HTTPException(401, f"invalid token: {e}") from e
        roles = _claim(claims, self.s.roles_claim) or []
        tenants = _claim(claims, self.s.tenants_claim) or []
        if isinstance(tenants, str):
            tenants = [tenants]
        return Principal(str(claims["sub"]), frozenset(roles), frozenset(tenants))


_bearer = HTTPBearer(auto_error=False)


def principal_dep(auth: Authenticator) -> Callable[..., Awaitable[Principal]]:
    async def dep(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
        if creds is None:
            raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        return auth.decode(creds.credentials)

    return dep


def require(
    role: Role, current: Callable[..., Awaitable[Principal]]
) -> Callable[..., Awaitable[Principal]]:
    async def dep(request: Request, p: Principal = Depends(current)) -> Principal:
        if not p.has(role):
            raise HTTPException(403, f"requires role {role}")
        tenant = request.path_params.get("tenant_id")
        if tenant is not None and not p.can_access(tenant):
            raise HTTPException(403, "no access to tenant")
        return p

    return dep


def dev_token(
    secret: str,
    sub: str,
    roles: list[str],
    tenants: list[str],
    audience: str = "aiops-control-plane",
    ttl: int = 3600,
) -> str:
    import time

    now = int(time.time())
    return jwt.encode(
        {
            "sub": sub,
            "roles": roles,
            "tenants": tenants,
            "aud": audience,
            "iat": now,
            "exp": now + ttl,
        },
        secret,
        algorithm="HS256",
    )
