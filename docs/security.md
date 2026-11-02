# Security & governance model

Status legend: ✅ implemented and tested · 🏗 infrastructure/config you provide · ⚠️ known limitation

## Agent boundaries and approval gates

| Control | Implementation | Status |
|---|---|---|
| **Agent execution boundary** | `Principal` refuses to be constructed if an AGENT holds more than `shipment:read` / `remediation:propose`, or if any non-human holds an approve, override, file or cancel permission. Every worker runs under its own least-privilege principal (`platform.worker_principals`). | ✅ |
| **No tools for LLMs** | Claude is called with no tools and a strict output schema. Every LLM component returns data, and the kernel decides what to do with it. | ✅ |
| **Confirmation gates** | External effects (email, customs filing) happen only from approved ledger events, through the outbox dispatcher. | ✅ |
| **Content-bound approval** | The approval carries the SHA-256 of the exact draft the reviewer saw. The dispatcher re-verifies it against the proposal before sending. | ✅ |
| **Four-eyes approval** | Releasing a hold and waiving a critical issue need two different humans. The API runs this as request + co-sign, and a requester cannot co-sign their own request. | ✅ |
| **Fail closed** | A missing extraction, validation or screening result, a sanctions-list outage, a tariff outage, or a scanner outage all block the shipment. None of them clear it. | ✅ |

## LLM-specific threats

| Control | Implementation | Status |
|---|---|---|
| **Prompt injection** | Document text is fenced as untrusted and the system prompt says it is data. There are no tools, and outputs must match a schema. Values the extractor returns that don't appear in the source text get low confidence scores. | ✅ |
| **Hallucinated values** | Confidence is computed deterministically: the quoted evidence must exist in the OCR text, the value must appear in that quote, it must pass format validation (e.g. ISO 6346 check digit), and the cross-check must agree. The LLM never scores itself. | ✅ |
| **Redirected emails** | Recipients come from the tenant's counterparty directory, never from documents or the LLM. The dispatcher re-checks the domain allowlist. | ✅ |
| **Unsafe drafts** | Drafts are rejected if they contain links, banking or credential requests, or don't cover every issue. A deterministic template is used instead. The dispatcher also runs DLP checks for card numbers, IBANs and credentials. | ✅ |
| **Refusals and truncation** | `stop_reason` is checked: refusal or `max_tokens` raises an error and never yields partial data. Server-side refusal fallbacks are enabled (`fallbacks: "default"`). | ✅ |

## Audit trail

| Control | Implementation | Status |
|---|---|---|
| **Append-only audit ledger** | Per-tenant SHA-256 hash chain over domain-separated canonical JSON, signed with Ed25519. Recorded events: state transitions, document versions, intake decisions, LLM calls, external API calls, dispatches, co-sign requests and document views. | ✅ |
| **Database-level immutability** | Triggers block UPDATE, DELETE and TRUNCATE, even for the table owner, and gap-free chain linkage is enforced. | ✅ |
| **Signing keys** | `Signer` is an interface. Retired key IDs remain verifiable after rotation. | ✅ / 🏗 KMS/HSM signer |

## Identity and tenant isolation

| Control | Implementation | Status |
|---|---|---|
| **Identity** | OIDC JWT verification (RS/ES/PS256 via JWKS; issuer, audience and expiry checked; lifetime ≤ 1h). MFA `amr` is required. Only human roles are accepted from tokens. The dashboard signs in with authorization code + PKCE and keeps the token in sessionStorage. | ✅ |
| **Tenant isolation** | Each tenant gets its own schema and NOLOGIN role, plus FORCE row-level security. Blobs are bound to the tenant through AES-GCM associated data. Cross-tenant access returns "not found". | ✅ |
| **Partner webhooks** | HMAC-SHA256 over timestamp + nonce + body, with a 5-minute window and replay cache. | ✅ |
| **Inbound email** | Sender domain must be on the allowlist, and DMARC/DKIM/SPF must pass as stamped by *our* MTA (authserv-id pinned). | ✅ |

## Files and transport

| Control | Implementation | Status |
|---|---|---|
| **Untrusted files** | File type is detected from magic bytes against an allowlist. Size is limited. PDFs with JavaScript, Launch, EmbeddedFile or XFA content, or encryption, are quarantined. ClamAV scans every file and failure is fail-closed. | ✅ |
| **Encryption at rest** | AES-256-GCM envelope encryption with a fresh data key per object, wrapped by the tenant's key. | ✅ / 🏗 cloud KMS + storage CMK |
| **Encryption in transit** | TLS 1.3 at the ingress. Postgres uses `sslmode=verify-full`. SMTP has TLS 1.3 as its minimum version. HTTPS is required for tariff and IdP endpoints. | ✅ code / 🏗 ingress |
| **HTTP hardening** | HSTS, CSP, frame-deny, nosniff, no-store on the API, body-size limits, per-client rate limiting, trusted hosts, strict CORS. Errors never leak internals. | ✅ |

## Operations

| Control | Implementation | Status |
|---|---|---|
| **Data access logging** | Viewing an original document is recorded in the ledger. | ✅ |
| **Supply chain** | Pinned frontend dependencies, `npm audit` in CI, slim non-root runtime image, least-privilege CI token. | ✅ / 🏗 SBOM + image signing |
| **Multi-replica state** | Co-sign requests and rate-limit buckets are in memory (see deployment.md). | ⚠️ |
