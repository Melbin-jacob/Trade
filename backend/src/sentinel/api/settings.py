"""Runtime settings from the environment (12-factor). Secrets come from the
platform's secret manager as environment variables - never from files in the repo."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    env: str = field(default_factory=lambda: os.environ.get("SENTINEL_ENV", "production"))
    oidc_issuer: str = field(default_factory=lambda: os.environ.get("SENTINEL_OIDC_ISSUER", ""))
    oidc_audience: str = field(default_factory=lambda: os.environ.get("SENTINEL_OIDC_AUDIENCE", "trade-lane-sentinel"))
    oidc_jwks_url: str = field(default_factory=lambda: os.environ.get("SENTINEL_OIDC_JWKS_URL", ""))
    oidc_client_id: str = field(default_factory=lambda: os.environ.get("SENTINEL_OIDC_CLIENT_ID", ""))
    tenant_claim: str = field(default_factory=lambda: os.environ.get("SENTINEL_TENANT_CLAIM", "tenant"))
    roles_claim: str = field(default_factory=lambda: os.environ.get("SENTINEL_ROLES_CLAIM", "roles"))
    require_mfa: bool = field(default_factory=lambda: os.environ.get("SENTINEL_REQUIRE_MFA", "true") == "true")
    dev_jwt_secret: str = field(default_factory=lambda: os.environ.get("SENTINEL_DEV_JWT_SECRET", ""))
    cors_origins: list[str] = field(default_factory=lambda: _list("SENTINEL_CORS_ORIGINS"))
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.environ.get("SENTINEL_RATE_LIMIT_PER_MIN", "120")))
    max_upload_mb: int = field(default_factory=lambda: int(os.environ.get("SENTINEL_MAX_UPLOAD_MB", "25")))
    trusted_hosts: list[str] = field(default_factory=lambda: _list("SENTINEL_TRUSTED_HOSTS", "*"))

    @property
    def is_dev(self) -> bool:
        return self.env == "dev"

    def validate(self) -> None:
        if self.is_dev:
            if len(self.dev_jwt_secret) < 32:
                raise RuntimeError("dev mode needs SENTINEL_DEV_JWT_SECRET of at least 32 characters")
            return
        if self.dev_jwt_secret:
            raise RuntimeError("SENTINEL_DEV_JWT_SECRET must not be set outside dev")
        if not (self.oidc_issuer.startswith("https://") and self.oidc_jwks_url.startswith("https://")):
            raise RuntimeError("production requires HTTPS SENTINEL_OIDC_ISSUER and SENTINEL_OIDC_JWKS_URL")
        if "*" in self.cors_origins:
            raise RuntimeError("wildcard CORS is not allowed in production")
