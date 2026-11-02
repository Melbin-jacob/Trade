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
