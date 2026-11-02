# Security & governance model

Status legend: ✅ implemented in this repo · 🔜 planned module · 🏗 infrastructure/config

| Control | Implementation | Status |
|---|---|---|
| **Agent execution boundary** | `Principal` refuses to be constructed if an AGENT holds anything beyond `shipment:read` and `remediation:propose`, or if any non-human holds an approval, override, filing or cancel permission. | ✅ |
| **Confirmation gates** | External effects happen only after a human-approved ledger event. The dispatcher reads them through a transactional outbox. | ✅ gate / 🔜 dispatcher |
| **Four-eyes approval** | Releasing a hold and waiving a critical issue require two different human principals. | ✅ |
| **Content-bound approval** | Approval carries the SHA-256 of the reviewed draft and is rejected if it does not match the proposal. | ✅ |
| **Append-only audit ledger** | Per-tenant SHA-256 hash chain with domain-separated canonical JSON and Ed25519 signatures. `verify_chain()` detects edits, deletions, reordering and re-hashed forgeries. | ✅ |
| **Database-level immutability** | Triggers block UPDATE, DELETE and TRUNCATE, including for the table owner. The head-row lock enforces gap-free linkage. A superuser *could* disable the triggers, which is why entries are also signed with a key the database cannot reach. | ✅ |
| **Signing keys** | `Signer` is an interface: Ed25519 locally, KMS/HSM in production. Old key IDs stay on the keyring so historical entries still verify. | ✅ interface / 🏗 KMS |
| **Tenant isolation** | A schema and a NOLOGIN role per tenant, with grants limited to SELECT and INSERT. FORCE row-level security on `app.tenant_id` acts as a second lock. Cross-tenant access returns "not found". | ✅ |
| **Encryption in transit** | TLS 1.3 only (`ssl_min_protocol_version=TLSv1.3`). Mutual TLS between services through the mesh. | 🏗 |
| **Encryption at rest** | AES-256 storage encryption with a customer-managed key. Document blobs are envelope-encrypted with a per-tenant key (`tenants.kms_key_ref`). | 🏗 / 🔜 |
| **Data residency** | `tenants.data_region` pins storage and LLM inference to a region. | ✅ schema / 🔜 routing |
| **Prompt injection** | Document text is treated as untrusted data. Agents have no tools that write, outputs must match a schema, and kernel guards reject proposals that reference unknown issues. | ✅ kernel side / 🔜 agent side |
| **Deterministic arithmetic** | Floats are rejected in hashed payloads. Weights and amounts use `Decimal`, and units are converted with exact factors. | ✅ |
| **Identity** | OIDC + MFA for people; a workload identity for each service. | 🔜 API gateway |
| **Outbound data controls** | Recipients must be on the shipment's known-party allowlist. DLP scanning, no first contact with new domains, egress allowlist. | 🔜 dispatcher |
| **Supply chain** | Pinned dependencies, SBOM, signed images, least-privilege CI token (`permissions: contents: read`). | ✅ CI / 🏗 |
| **Resilience** | A sanctions or tariff outage means no clearance, so the shipment cannot proceed (fail closed). Circuit breakers on external APIs. | ✅ kernel / 🔜 adapters |
