"""Bearer-token authentication (OIDC) and mapping of claims to principals.

Only HUMAN roles can be granted through tokens. Workers and agents get their
principals inside the platform; partners authenticate with signed webhooks.
"""

from __future__ import annotations

import time
from typing import Any

import jwt

from sentinel.api.settings import Settings
from sentinel.security.principals import Principal, PrincipalKind, Role

HUMAN_ROLES = frozenset({Role.REVIEWER, Role.COMPLIANCE_OFFICER, Role.CUSTOMS_FILER, Role.AUDITOR})
MFA_METHODS = {"mfa", "otp", "hwk", "swk", "fido", "webauthn"}
MAX_TOKEN_LIFETIME = 3600


class AuthError(Exception):
    pass


class TokenVerifier:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._jwks = None if settings.is_dev else jwt.PyJWKClient(settings.oidc_jwks_url, cache_keys=True)

    def _decode(self, token: str) -> dict[str, Any]:
        opts = {"require": ["exp", "iat", "sub"]}
        if self._s.is_dev:
            return jwt.decode(token, self._s.dev_jwt_secret, algorithms=["HS256"], audience=self._s.oidc_audience,
                              issuer="sentinel-dev", options=opts)
        key = self._jwks.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["RS256", "ES256", "PS256"], audience=self._s.oidc_audience,
                          issuer=self._s.oidc_issuer, options=opts, leeway=30)

    def principal(self, authorization: str | None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthError("missing bearer token")
        try:
            claims = self._decode(authorization.removeprefix("Bearer ").strip())
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {type(exc).__name__}") from None
        if claims["exp"] - claims["iat"] > MAX_TOKEN_LIFETIME + 60:
            raise AuthError("token lifetime too long")
        if self._s.require_mfa and not (set(claims.get("amr", [])) & MFA_METHODS):
            raise AuthError("multi-factor authentication required")
        roles = set()
        for r in claims.get(self._s.roles_claim, []):
            try:
                role = Role(r)
            except ValueError:
                continue
            if role in HUMAN_ROLES:
                roles.add(role)
        if not roles:
            raise AuthError("no recognised roles")
        try:
            return Principal(id=str(claims["sub"]), kind=PrincipalKind.HUMAN,
                             tenant_id=str(claims.get(self._s.tenant_claim, "")), roles=frozenset(roles))
        except ValueError as exc:
            raise AuthError("invalid tenant claim") from exc


def issue_dev_token(settings: Settings, sub: str, tenant: str, roles: list[str], name: str) -> str:
    if not settings.is_dev:
        raise RuntimeError("dev tokens are only available in dev mode")
    now = int(time.time())
    return jwt.encode({"sub": sub, "name": name, "tenant": tenant, "roles": roles, "amr": ["pwd", "otp"],
                       "iat": now, "exp": now + 3600, "iss": "sentinel-dev", "aud": settings.oidc_audience},
                      settings.dev_jwt_secret, algorithm="HS256")
