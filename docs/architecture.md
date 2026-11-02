# Architecture

## Component view

```
 Email / Object storage / Port APIs
            │
   ┌────────▼─────────┐  quarantine → AV scan → file-type check → SHA-256
   │ Ingestion Gateway│──► encrypted blob store (per-tenant CMK)
   └────────┬─────────┘
            │ document.version_registered
   ┌────────▼───────────────────────────────────────────┐
   │ Extraction: layout/OCR → schema-bound LLM          │
   │ → ExtractedField[T] with confidence + source box   │
   └────────┬───────────────────────────────────────────┘
            │ extraction.completed (review_flags < 98%)
   ┌────────▼──────────── THICK KERNEL ─────────────────┐
   │ ShipmentService  →  Ledger (hash chain + Ed25519)  │
   │ Rule engine (Decimal arithmetic, ISO 6346, HS)     │
   │ Screening adapters (sanctions, tariff, import)     │
   └────────┬──────────────────────▲────────────────────┘
            │ read                 │ proposals only
   ┌────────▼─────── THIN AGENTS ──┴────────────────────┐
   │ Analyzer (read) · Semantic matcher · Drafter       │
   └────────┬───────────────────────────────────────────┘
            │ remediation.proposed
   ┌────────▼─────────┐   ┌─────────────────────────────┐
   │ Approval gate    │◄──│ HITL dashboard              │
   └────────┬─────────┘   └─────────────────────────────┘
            │ approved events (transactional outbox)
     Dispatcher → ERP / customs / outbound email
```

## Master Shipment state machine

The authoritative definition is the `TRANSITIONS` table in
`backend/src/sentinel/kernel/shipment.py`. It maps each event to the states it
may fire from and the permission it requires.

| Event | From | Permission | Who |
|---|---|---|---|
| `document.version_registered` | any state before filing | `document:ingest` | ingestion service |
| `extraction.completed` | EXTRACTING | `extraction:record` | extraction service |
| `validation.completed` | VALIDATING | `validation:record` | rule engine |
| `screening.completed` | any active state | `screening:record` | screening service |
| `remediation.proposed` | EXCEPTION_OPEN | `remediation:propose` | drafter **agent** |
| `remediation.approved` / `rejected` | REMEDIATION_PENDING_APPROVAL | `remediation:approve` | human |
| `exception.issues_waived` | EXCEPTION_OPEN, PENDING | `exception:override` | human (2 people if critical) |
| `hold.released` | COMPLIANCE_HOLD | `hold:release` | **two** compliance officers |
| `filing.submitted` | READY_FOR_FILING | `filing:submit` | human filer |

### Key properties
- **Versioned documents.** Each document version is identified by the SHA-256
  of its bytes, which the kernel computes itself. A new version supersedes the
  previous one, and earlier versions are never removed.
- **Document-set fingerprint.** `docset_hash` covers the latest version of every
  document. Validation and screening results apply only to the exact set they
  were run against, so a corrected packing list automatically invalidates the
  earlier validation and screening.
- **The 98% confidence threshold is enforced in the kernel.** Low-confidence
  fields from extraction become `low_confidence:*` issues inside the aggregate,
  even if the rule engine reports nothing.
- **Sanctions holds are sticky.** New paperwork does not lift a hold. Only two
  different compliance officers can release it, and a written justification is
  required.
- **Approval is tied to content.** The approver submits the hash of the draft
  they reviewed. If it does not match the proposed draft, the approval is
  rejected.

## Pipeline (modules 2-8)

| Stage | Module | Deterministic or LLM | Writes |
|---|---|---|---|
| Intake | `ingestion/` | deterministic | `intake.*`, `document.version_registered` |
| Extraction | `extraction/` | OCR + Claude (schema-bound), deterministic scoring | `llm_call.completed`, `extraction.completed` |
| Validation | `rules/` + `regulatory/rulepacks.py` | deterministic; Claude only labels ambiguous description pairs | `validation.completed`, `external_call.completed` |
| Screening | `regulatory/screening.py` | deterministic (Jaro-Winkler + embargo list) | `screening.completed` |
| Remediation | `agents/remediation.py` | Claude drafts the email; recipients and guardrails are deterministic | `remediation.proposed` |
| Human review | `api/` + `frontend/` | human | `remediation.approved/rejected`, `exception.issues_waived`, `hold.released`, `filing.submitted` |
| Dispatch | `dispatch/outbox.py` | deterministic | `dispatch.claimed/sent/blocked/failed` |

The orchestrator (`orchestration/orchestrator.py`) tails each tenant's ledger and
wakes the worker for the shipment's current state. Each worker re-checks its
preconditions through the kernel, so running a step twice or out of order is
rejected rather than applied.

## Confidence scoring (98% threshold)

```
score = min(OCR confidence of the tokens the evidence quote spans)
        capped at 40 if the quote is not in the OCR text (possible hallucination)
        capped at 70 if the value is not visible inside the quote
        capped at 60 if an independent extractor disagrees (e.g. container regex)
        value = null, score 0 if the value fails its validator (ISO 6346, HS, ISO 4217...)
then    calibrated through a piecewise-linear curve fitted on labelled samples
```

Born-digital PDFs read from the text layer score 99.9 when grounded. Scanned
pages use Tesseract word confidences. Anything below 98 becomes a
`low_confidence:*` issue that a human must confirm.
