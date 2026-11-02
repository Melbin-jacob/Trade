# Deployment

Two processes run from the same image:

- **api**: `uvicorn sentinel.api.main:app`. Serves the review API and the built dashboard.
- **worker**: `python -m sentinel.worker`. Advances shipments by tailing each tenant's ledger.

Put TLS 1.3 on the ingress or load balancer. The containers run as a non-root
user on a private network.

## Environment

Inject secrets from your secret manager. Never commit them.

| Variable | Purpose |
|---|---|
| `SENTINEL_ENV` | `production` (default) or `dev` (demo only) |
| `SENTINEL_OIDC_ISSUER`, `SENTINEL_OIDC_JWKS_URL`, `SENTINEL_OIDC_AUDIENCE`, `SENTINEL_OIDC_CLIENT_ID` | Identity provider. HTTPS is required, and the dashboard uses authorization code + PKCE |
| `SENTINEL_TENANT_CLAIM`, `SENTINEL_ROLES_CLAIM` | Token claims that carry the tenant and the roles (`reviewer`, `compliance_officer`, `customs_filer`, `auditor`) |
| `SENTINEL_REQUIRE_MFA` | `true` (default). Tokens must carry an MFA `amr` value |
| `SENTINEL_CORS_ORIGINS`, `SENTINEL_TRUSTED_HOSTS`, `SENTINEL_RATE_LIMIT_PER_MIN`, `SENTINEL_MAX_UPLOAD_MB` | HTTP hardening |
| `SENTINEL_TENANTS_FILE` | Tenant registry JSON (example below) |
| `SENTINEL_DATABASE_DSN` | Postgres DSN. Must include `sslmode=verify-full` |
| `SENTINEL_LEDGER_KEY_ID`, `SENTINEL_LEDGER_SIGNING_KEY_B64` | Ed25519 PEM (base64) that signs the ledger. Replace with a KMS/HSM `Signer` where available |
| `SENTINEL_LEDGER_RETIRED_KEYS` | JSON `{key_id: pem_b64}` so entries signed before a key rotation still verify |
| `SENTINEL_KMS_KEYS_JSON` | JSON `{kms_key_ref: base64 32-byte key}`, the per-tenant key-encryption keys (or a cloud KMS adapter) |
| `SENTINEL_BLOB_DIR` | Encrypted object storage mount. Swap `FilesystemBlobStore` for S3/GCS/Azure |
| `SENTINEL_CLAMD_SOCKET` | ClamAV daemon socket |
| `SENTINEL_SANCTIONS_DIR` | Directory refreshed by a scheduled job running `sentinel.regulatory.sanctions.download_ofac` |
| `SENTINEL_TARIFF_API_URL` + `SENTINEL_TARIFF_API_KEY`, or `SENTINEL_TARIFF_CSV` | Destination tariff source |
| `SENTINEL_SMTP_HOST/PORT/USER/PASSWORD/FROM` | Outbound mail (STARTTLS, TLS 1.3 minimum) |
| `SENTINEL_CUSTOMS_OUTBOX_DIR` | Declarations dropped here for broker/EDI pickup (CARM, ACE, ICS2) |
| `ANTHROPIC_API_KEY` (or workload identity), `SENTINEL_CLAUDE_MODEL` | Claude access. Default model is `claude-opus-5-5` |
| `SENTINEL_COMPANY_NAME` | Signature line on correction emails |

## Tenant registry

```json
{
  "tenants": [{
    "tenant_id": "acme_trading",
    "kms_key_ref": "kms://acme-trading",
    "data_region": "ca-central-1",
    "home_country": "CA",
    "inbound_email_domains": ["fazendaboavista.example"],
    "webhook_secret_env": {"port-montreal": "SENTINEL_WEBHOOK_ACME_PORT_MONTREAL"},
    "counterparties": [
      {"name": "Fazenda Boa Vista", "role": "supplier", "email": "export@fazendaboavista.example",
       "domains": ["fazendaboavista.example"]}
    ]
  }]
}
```

Provision each tenant's database schema and role once:

```sql
SELECT sentinel_admin.provision_tenant('acme_trading', 'kms://acme-trading', 'ca-central-1');
```

## Before you scale out

These run in a single process today. Move them to shared infrastructure before
running more than one replica:

- **Co-sign requests** are held in memory. Move them to Postgres.
- **Rate-limit buckets** are per process. Move them to Redis.
- **Orchestrator and dispatcher checkpoints** are in memory. They are safe to
  lose, because the dispatcher claims each action idempotently in the ledger,
  but persist them to avoid re-scanning the chain on restart.
