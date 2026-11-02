# Trade-Lane Sentinel

An autonomous agent platform for cross-border compliance checks and document
discrepancy reconciliation in global supply chains. It reads Commercial
Invoices, Bills of Lading, Packing Lists and certificates, checks them against
each other and against tariff, sanctions and import rules, drafts correction
requests to suppliers and shipping lines, and sends every external action
through a human approval gate with a signed audit trail.

## Try the demo

```bash
docker compose --profile demo up --build
```

Without Docker:

```bash
cd frontend && npm ci && npm run build && cd ../backend
pip install -e ".[dev]"
SENTINEL_ENV=dev uvicorn sentinel.api.main:app --port 8000
```

Open http://localhost:8000 and pick a persona. The demo starts with five
shipments, one per review path:

| Shipment | Scenario | Who acts |
|---|---|---|
| SHP-2026-000123 | Packing-list gross weight typo (4,960 entered as 4,690): B/L mismatch, and net weight above gross. The agent has drafted a correction email. Demurrage is accruing. | Alex Lee approves the draft, then uploads the corrected packing list (`/api/v1/dev/sample/corrected-packing-list`). |
| SHP-2026-000124 | Clean shipment, ready for filing. | Sam Patel files the declaration. |
| SHP-2026-000125 | Mangoes into Canada without a phytosanitary certificate (import rule). | Reviewer approves the request for the missing document. |
| SHP-2026-000126 | Consignee matches a (fictitious) sanctions entry, so the shipment is on hold. | Emma Davis requests release; Jane Doe co-signs. |
| SHP-2026-000127 | An extracted invoice total isn't backed by the page text, so its confidence is capped and it is flagged. | A reviewer confirms the value. |

The demo uses a scripted stand-in for Claude, so it needs no API key. To use
real Claude extraction and drafting, set `SENTINEL_DEMO_USE_CLAUDE=1` and
provide Anthropic credentials.

## Architecture

```
 Email / S3 / Port APIs ─► Ingestion gateway ─► Extraction ─► Rule engine + Screening ─► Remediation agent
   (DMARC, HMAC, prefix)    (sniff, AV scan,     (OCR + Claude,   (Decimal checks, OFAC,     (proposes only)
                             classify, encrypt)   grounded scores)  tariff, import rules)          │
                                     │                                                         ▼
                      Signed hash-chained ledger ◄── every event ──  HITL dashboard ─► Approval gate ─► Dispatcher
                      (system of record)                             (diff, decision tree,   (4-eyes,      (allowlist, DLP,
                                                                      single-click approve)   content hash)  idempotent)
```

**Thin agent, thick kernel.** Claude extracts values into a strict schema,
matches goods descriptions that are worded differently, and drafts emails.
Deterministic Python does every calculation, every confidence score, every
state change and every permission check. Agents can only read and propose.

See [docs/architecture.md](docs/architecture.md),
[docs/security.md](docs/security.md) and
[docs/deployment.md](docs/deployment.md).

## Repository layout

```
backend/src/sentinel/
  core/          canonical JSON for hashing (floats rejected)
  domain/        document schemas, ExtractedField[T], ISO 6346 / HS validation
  security/      principals, roles, agent permission boundary
  ledger/        hash-chained Ed25519-signed ledger, Postgres adapter, audit helper
  kernel/        Master Shipment state machine (event-sourced) + command service
  crypto/        AES-256-GCM envelope encryption (KMS port)
  storage/       encrypted, tenant-bound blob store
  ingestion/     file inspection, ClamAV, classifier, email/S3/webhook channels, gateway
  extraction/    OCR engines, LLM schema view, grounding-based confidence, pipeline
  rules/         deterministic rule engine, semantic matcher, validation runner
  regulatory/    sanctions screening, tariff + import rule packs, circuit breaker
  agents/        Claude client wrapper, remediation drafter
  dispatch/      outbox dispatcher (email/customs), filing payload builder
  orchestration/ ledger-tailing orchestrator
  api/           FastAPI app, OIDC auth, middleware, read models, co-signing, demo
  platform.py    composition root;  worker.py  background worker
frontend/        React + TypeScript dashboard (Vite)
db/migrations/   tenant provisioning, append-only ledger enforced in SQL
```

## Tests

```bash
cd backend && pytest                       # 91 tests: unit, pipeline, API, end-to-end
SENTINEL_TEST_DSN=postgresql://... pytest  # + 5 Postgres integration tests
```
