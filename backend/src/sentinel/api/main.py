"""Production entrypoint: ``uvicorn sentinel.api.main:app``.

Every adapter is configured from the environment (injected by the platform's
secret manager). TLS 1.3 terminates at the ingress/load balancer; uvicorn runs
behind it on a private network.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from sentinel.agents.claude import ClaudeJsonLlm
from sentinel.api.app import create_app, mount_frontend
from sentinel.api.settings import Settings
from sentinel.crypto.envelope import LocalKms
from sentinel.dispatch.outbox import SmtpEmailSender
from sentinel.dispatch.customs import FileDropCustomsGateway
from sentinel.ingestion.scanner import ClamdScanner
from sentinel.ledger.signing import Ed25519Signer, KeyRing
from sentinel.platform import build_platform
from sentinel.regulatory.sanctions import OfacFileProvider
from sentinel.regulatory.tariff import HttpTariffProvider, StaticTariffSchedule
from sentinel.storage.blobs import FilesystemBlobStore
from sentinel.tenancy import Counterparty, TenantConfig, TenantDirectory


def _env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"missing required environment variable {name}")
    return v


def load_tenants(path: Path) -> TenantDirectory:
    """Tenant registry JSON (non-secret config); webhook secrets come from env by reference."""
    data = json.loads(path.read_text())
    tenants = []
    for t in data["tenants"]:
        tenants.append(TenantConfig(
            tenant_id=t["tenant_id"], kms_key_ref=t["kms_key_ref"], data_region=t["data_region"],
            counterparties=tuple(Counterparty(c["name"], c["role"], c["email"], frozenset(c["domains"]))
                                 for c in t.get("counterparties", [])),
            webhook_secrets={p: _env(env).encode() for p, env in t.get("webhook_secret_env", {}).items()},
            inbound_email_domains=frozenset(t.get("inbound_email_domains", [])),
            home_country=t.get("home_country", "CA"),
        ))
    return TenantDirectory(tenants)


def build_from_env():
    settings = Settings()
    tenants = load_tenants(Path(_env("SENTINEL_TENANTS_FILE")))

    if os.environ.get("SENTINEL_DATABASE_DSN"):
        import psycopg

        from sentinel.ledger.postgres import PostgresLedgerStore

        dsn = os.environ["SENTINEL_DATABASE_DSN"]
        if "sslmode=verify-full" not in dsn:
            raise RuntimeError("database DSN must use sslmode=verify-full")
        store = PostgresLedgerStore(lambda: psycopg.connect(dsn))
    else:
        raise RuntimeError("SENTINEL_DATABASE_DSN is required in production")

    # Ledger signing key: Ed25519 PEM from the secret manager (swap for a KMS signer).
    key = load_pem_private_key(base64.b64decode(_env("SENTINEL_LEDGER_SIGNING_KEY_B64")), password=None)
    signer = Ed25519Signer(_env("SENTINEL_LEDGER_KEY_ID"), key)  # type: ignore[arg-type]
    keyring = KeyRing()
    keyring.add(signer.key_id, signer.public_key())
    for kid, pem_b64 in json.loads(os.environ.get("SENTINEL_LEDGER_RETIRED_KEYS", "{}")).items():
        keyring.add(kid, load_pem_private_key(base64.b64decode(pem_b64), None).public_key())  # type: ignore[union-attr]

    # Key-encryption keys per tenant (replace LocalKms with a cloud KMS adapter where available).
    kms = LocalKms({ref: base64.b64decode(k) for ref, k in json.loads(_env("SENTINEL_KMS_KEYS_JSON")).items()})

    tariff = (HttpTariffProvider(os.environ["SENTINEL_TARIFF_API_URL"], _env("SENTINEL_TARIFF_API_KEY"))
              if os.environ.get("SENTINEL_TARIFF_API_URL")
              else StaticTariffSchedule.from_csv(Path(_env("SENTINEL_TARIFF_CSV")).read_text()))

    platform = build_platform(
        tenants=tenants, store=store, signer=signer, keyring=keyring,
        raw_blobs=FilesystemBlobStore(Path(_env("SENTINEL_BLOB_DIR"))), kms=kms,
        llm_factory=lambda audit: ClaudeJsonLlm(audit=audit, model=os.environ.get("SENTINEL_CLAUDE_MODEL", "claude-opus-5-5")),
        scanner=ClamdScanner(unix_socket=os.environ.get("SENTINEL_CLAMD_SOCKET", "/var/run/clamav/clamd.ctl")),
        sanctions=OfacFileProvider(Path(_env("SENTINEL_SANCTIONS_DIR"))),
        tariff=tariff,
        email=SmtpEmailSender(_env("SENTINEL_SMTP_HOST"), int(os.environ.get("SENTINEL_SMTP_PORT", "587")),
                              _env("SENTINEL_SMTP_USER"), _env("SENTINEL_SMTP_PASSWORD"), _env("SENTINEL_SMTP_FROM")),
        customs=FileDropCustomsGateway(Path(_env("SENTINEL_CUSTOMS_OUTBOX_DIR"))),
        company_name=os.environ.get("SENTINEL_COMPANY_NAME", "Trade Compliance"),
    )
    return platform, settings


def _app():
    if os.environ.get("SENTINEL_ENV") == "dev":
        from sentinel.api.demo import create_demo_app

        return create_demo_app()
    platform, settings = build_from_env()
    app = create_app(platform, settings, run_pipeline_inline=False)  # the worker process advances shipments
    mount_frontend(app)
    return app


app = _app() if os.environ.get("SENTINEL_AUTOLOAD", "1") == "1" else None
