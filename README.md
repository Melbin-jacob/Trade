# Trade-Lane Sentinel

An autonomous agent platform for cross-border compliance checks and document
discrepancy reconciliation in global supply chains. It checks Commercial
Invoices, Bills of Lading, Packing Lists and certificates against each other,
screens shipments against tariff and sanctions rules, drafts corrections, and
sends every external action through a human approval gate with an audit trail.

> **Status:** Module 1 (the core kernel) is in place. See the [roadmap](#roadmap).

## Design principles

- **Thin agent, thick kernel.** LLMs read, match meaning and draft text. Python
  and SQL code does every calculation, state change and permission check.
- **The ledger is the system of record.** Shipment state is rebuilt by replaying
  a hash-chained, signed, append-only event ledger, so the audit trail always
  matches what operators saw.
- **Fail closed.** A shipment is ready for filing only when the *current*
  document set has been extracted, validated, cleared by screening, and has no
  open issues.

## Repository layout

```
backend/
  src/sentinel/
    core/canonical.py        deterministic JSON used for hashing and signing (rejects floats)
    domain/identifiers.py    ISO 6346 container check digits, HS codes, ISO 4217/3166 codes
    domain/fields.py         ExtractedField[T] with confidence score, source location and the 98% threshold
    domain/documents.py      Invoice / B/L / Packing List / CoO / Phytosanitary schemas
    security/principals.py   roles, permissions, agent read-only boundary
    ledger/chain.py          hash-chained, Ed25519-signed ledger and verify_chain()
    ledger/postgres.py       Postgres adapter (tenant role + RLS for each transaction)
    kernel/shipment.py       Master Shipment aggregate + state machine (event-sourced)
    kernel/service.py        commands: authorize -> guard -> append -> evolve
  tests/                     unit tests + Postgres integration tests
db/migrations/               tenant provisioning, append-only ledger enforced in SQL
docs/                        architecture and security model
frontend/                    HITL review dashboard (coming next)
```

## Running the tests

```bash
cd backend
pip install -e ".[dev]"
pytest
```

The Postgres integration tests run when `SENTINEL_TEST_DSN` is set:

```bash
SENTINEL_TEST_DSN="postgresql://postgres:pw@localhost:5432/postgres" pytest
```

## Roadmap

| # | Module | Status |
|---|--------|--------|
| 1 | Shipment schemas, signed event ledger, state machine, tenant-isolated DB | ✅ |
| 2 | Ingestion gateway (email/S3/port APIs, quarantine, malware scan) | ⏳ |
| 3 | Hybrid OCR + schema-bound LLM extraction, confidence calibration | ⏳ |
| 4 | Deterministic rule engine (weights, totals, counts, container/HS cross-checks) | ⏳ |
| 5 | Regulatory adapters (tariff, sanctions, import rules) with circuit breakers | ⏳ |
| 6 | Remediation drafter agent + outbox dispatcher (email/ERP/customs) | ⏳ |
| 7 | HITL dashboard: decision tree, side-by-side diff, single-click approval | ⏳ |
| 8 | FastAPI gateway: OIDC, mTLS, rate limiting | ⏳ |
