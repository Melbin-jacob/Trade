"""Master Shipment aggregate and its state machine.

The aggregate is *event-sourced*: its state is a pure fold over the shipment's
ledger entries. Nothing here performs I/O or authorization - that is the job
of ``sentinel.kernel.service`` - which keeps replay deterministic.

State diagram
-------------

    (open) ──► AWAITING_DOCUMENTS ──document──► EXTRACTING ──all extracted──► VALIDATING
                                                   ▲                             │
             new document version (any active) ────┘          ┌──────────────────┼───────────────┐
                                                              ▼                  ▼               ▼
                                                       EXCEPTION_OPEN     READY_FOR_FILING   (await screening)
                                                         │      ▲               │
                                          agent proposes │      │ rejected      │ human files
                                                         ▼      │               ▼
                                              REMEDIATION_PENDING_APPROVAL     FILED ──► CLOSED
                                                         │ human approves
                                                         ▼
                                                 AWAITING_CORRECTION ── new document version ──► EXTRACTING

    screening HIT (any active, incl. FILED) ──► COMPLIANCE_HOLD ──4-eyes release──► VALIDATING
    cancel (any non-terminal, human) ──► CANCELLED
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from sentinel.core.canonical import canonical_json
from sentinel.domain.documents import DocumentType
from sentinel.ledger.chain import LedgerEntry
from sentinel.security.principals import Permission

AGGREGATE_TYPE = "shipment"

REQUIRED_DOCUMENTS: frozenset[DocumentType] = frozenset(
    {DocumentType.COMMERCIAL_INVOICE, DocumentType.BILL_OF_LADING, DocumentType.PACKING_LIST}
)


class ShipmentState(StrEnum):
    AWAITING_DOCUMENTS = "awaiting_documents"
    EXTRACTING = "extracting"
    VALIDATING = "validating"
    EXCEPTION_OPEN = "exception_open"
    REMEDIATION_PENDING_APPROVAL = "remediation_pending_approval"
    AWAITING_CORRECTION = "awaiting_correction"
    COMPLIANCE_HOLD = "compliance_hold"
    READY_FOR_FILING = "ready_for_filing"
    FILED = "filed"
    CLOSED = "closed"
    CANCELLED = "cancelled"


S = ShipmentState
TERMINAL = frozenset({S.CLOSED, S.CANCELLED})
ACTIVE = frozenset(ShipmentState) - TERMINAL
PRE_FILING = ACTIVE - {S.FILED}


class Ev(StrEnum):
    OPENED = "shipment.opened"
    DOCUMENT_REGISTERED = "document.version_registered"
    EXTRACTION_COMPLETED = "extraction.completed"
    VALIDATION_COMPLETED = "validation.completed"
    SCREENING_COMPLETED = "screening.completed"
    REMEDIATION_PROPOSED = "remediation.proposed"
    REMEDIATION_APPROVED = "remediation.approved"
    REMEDIATION_REJECTED = "remediation.rejected"
    ISSUES_WAIVED = "exception.issues_waived"
    HOLD_RELEASED = "hold.released"
    FILING_SUBMITTED = "filing.submitted"
    CLOSED = "shipment.closed"
    CANCELLED = "shipment.cancelled"


@dataclass(frozen=True)
class TransitionRule:
    allowed_from: frozenset[ShipmentState]
    permission: Permission


#: Single source of truth for *who* may emit *which* event from *which* state.
TRANSITIONS: dict[Ev, TransitionRule] = {
    Ev.DOCUMENT_REGISTERED: TransitionRule(PRE_FILING, Permission.DOCUMENT_INGEST),
    Ev.EXTRACTION_COMPLETED: TransitionRule(frozenset({S.EXTRACTING}), Permission.EXTRACTION_RECORD),
    Ev.VALIDATION_COMPLETED: TransitionRule(frozenset({S.VALIDATING}), Permission.VALIDATION_RECORD),
    Ev.SCREENING_COMPLETED: TransitionRule(ACTIVE, Permission.SCREENING_RECORD),
    Ev.REMEDIATION_PROPOSED: TransitionRule(frozenset({S.EXCEPTION_OPEN}), Permission.REMEDIATION_PROPOSE),
    Ev.REMEDIATION_APPROVED: TransitionRule(
        frozenset({S.REMEDIATION_PENDING_APPROVAL}), Permission.REMEDIATION_APPROVE
    ),
    Ev.REMEDIATION_REJECTED: TransitionRule(
        frozenset({S.REMEDIATION_PENDING_APPROVAL}), Permission.REMEDIATION_APPROVE
    ),
    Ev.ISSUES_WAIVED: TransitionRule(
        frozenset({S.EXCEPTION_OPEN, S.REMEDIATION_PENDING_APPROVAL}), Permission.EXCEPTION_OVERRIDE
    ),
    Ev.HOLD_RELEASED: TransitionRule(frozenset({S.COMPLIANCE_HOLD}), Permission.HOLD_RELEASE),
    Ev.FILING_SUBMITTED: TransitionRule(frozenset({S.READY_FOR_FILING}), Permission.FILING_SUBMIT),
    Ev.CLOSED: TransitionRule(frozenset({S.FILED}), Permission.SHIPMENT_CLOSE),
    Ev.CANCELLED: TransitionRule(ACTIVE - {S.FILED}, Permission.SHIPMENT_CANCEL),
}


class InvalidTransition(RuntimeError):
    pass


@dataclass(frozen=True)
class DocumentVersion:
    doc_type: DocumentType
    version: int
    content_sha256: str
    supersedes_sha256: str | None
    source_channel: str
    ledger_sequence: int


@dataclass
class ShipmentAggregate:
    tenant_id: str
    shipment_id: str
    version: int = 0
    state: ShipmentState | None = None
    reference: str | None = None
    free_time_expires_at: str | None = None  # demurrage clock (ISO-8601)
    documents: dict[DocumentType, list[DocumentVersion]] = field(default_factory=dict)
    pending_extraction: set[str] = field(default_factory=set)  # content hashes
    extraction_flags: dict[str, list[str]] = field(default_factory=dict)  # content hash -> field paths
    validated_docset: str | None = None
    validation_issues: dict[str, dict[str, Any]] = field(default_factory=dict)
    waived: dict[str, str] = field(default_factory=dict)  # issue id -> justification
    screened_clear_docset: str | None = None
    pending_proposal: dict[str, Any] | None = None
    history: list[tuple[int, str, str]] = field(default_factory=list)  # (seq, event, state)

    # ------------------------------------------------------------------ #
    # Derived views
    # ------------------------------------------------------------------ #

    def latest(self, doc_type: DocumentType) -> DocumentVersion | None:
        versions = self.documents.get(doc_type)
        return versions[-1] if versions else None

    @property
    def docset_hash(self) -> str:
        """Fingerprint of the exact set of latest document versions."""
        latest = {t.value: v[-1].content_sha256 for t, v in sorted(self.documents.items()) if v}
        return hashlib.sha256(canonical_json(latest)).hexdigest()

    @property
    def issues(self) -> dict[str, dict[str, Any]]:
        """Rule-engine issues plus kernel-generated low-confidence issues.

        The <98% confidence rule is enforced HERE, deterministically, so a
        misbehaving or misconfigured rule engine cannot silently drop it.
        """
        out = dict(self.validation_issues)
        for doc_type, versions in self.documents.items():
            if not versions:
                continue
            for path in self.extraction_flags.get(versions[-1].content_sha256, []):
                issue_id = f"low_confidence:{doc_type.value}:{path}"
                out[issue_id] = {
                    "id": issue_id,
                    "kind": "low_confidence",
                    "severity": "warning",
                    "message": f"{doc_type.value} field {path} below confidence threshold",
                }
        return out

    @property
    def open_issues(self) -> dict[str, dict[str, Any]]:
        return {k: v for k, v in self.issues.items() if k not in self.waived}

    @property
    def missing_documents(self) -> frozenset[DocumentType]:
        return REQUIRED_DOCUMENTS - {t for t, v in self.documents.items() if v}

    def blocking_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.pending_extraction:
            reasons.append(f"{len(self.pending_extraction)} document(s) awaiting extraction")
        if self.missing_documents:
            reasons.append("missing: " + ", ".join(sorted(d.value for d in self.missing_documents)))
        if self.validated_docset != self.docset_hash:
            reasons.append("current document set not yet validated")
        if self.open_issues:
            reasons.append(f"{len(self.open_issues)} open issue(s)")
        if self.screened_clear_docset != self.docset_hash:
            reasons.append("current document set not cleared by sanctions/regulatory screening")
        return reasons

    # ------------------------------------------------------------------ #
    # Evolve (pure)
    # ------------------------------------------------------------------ #

    @classmethod
    def replay(cls, tenant_id: str, shipment_id: str, entries: list[LedgerEntry]) -> "ShipmentAggregate":
        agg = cls(tenant_id=tenant_id, shipment_id=shipment_id)
        for e in entries:
            agg.apply(e)
        return agg

    def apply(self, e: LedgerEntry) -> None:
        if e.aggregate_version != self.version + 1:
            raise InvalidTransition(f"out-of-order event v{e.aggregate_version} for v{self.version}")
        p = e.payload
        ev = Ev(e.event_type)

        if ev is Ev.OPENED:
            self.state = S.AWAITING_DOCUMENTS
            self.reference = p["reference"]
            self.free_time_expires_at = p.get("free_time_expires_at")

        elif ev is Ev.DOCUMENT_REGISTERED:
            dt = DocumentType(p["doc_type"])
            versions = self.documents.setdefault(dt, [])
            versions.append(
                DocumentVersion(
                    doc_type=dt,
                    version=p["version"],
                    content_sha256=p["content_sha256"],
                    supersedes_sha256=p.get("supersedes_sha256"),
                    source_channel=p["source_channel"],
                    ledger_sequence=e.sequence,
                )
            )
            if p.get("supersedes_sha256"):
                self.pending_extraction.discard(p["supersedes_sha256"])
            self.pending_extraction.add(p["content_sha256"])
            self.pending_proposal = None
            if self.state is not S.COMPLIANCE_HOLD:  # a hold survives new paperwork
                self.state = S.EXTRACTING

        elif ev is Ev.EXTRACTION_COMPLETED:
            self.pending_extraction.discard(p["content_sha256"])
            self.extraction_flags[p["content_sha256"]] = list(p["review_flags"])
            if not self.pending_extraction:
                self.state = S.VALIDATING

        elif ev is Ev.VALIDATION_COMPLETED:
            self.validated_docset = p["docset_hash"]
            self.validation_issues = {i["id"]: i for i in p["issues"]}
            self.waived = {k: v for k, v in self.waived.items() if k in self.issues}
            self._settle()

        elif ev is Ev.SCREENING_COMPLETED:
            if p["result"] == "hit":
                self.screened_clear_docset = None
                self.state = S.COMPLIANCE_HOLD
            else:
                self.screened_clear_docset = p["docset_hash"]
                self._settle()

        elif ev is Ev.REMEDIATION_PROPOSED:
            self.pending_proposal = dict(p)
            self.state = S.REMEDIATION_PENDING_APPROVAL

        elif ev is Ev.REMEDIATION_APPROVED:
            self.state = S.AWAITING_CORRECTION

        elif ev is Ev.REMEDIATION_REJECTED:
            self.pending_proposal = None
            self.state = S.EXCEPTION_OPEN

        elif ev is Ev.ISSUES_WAIVED:
            for issue_id in p["issue_ids"]:
                self.waived[issue_id] = p["justification"]
            if not self.open_issues:
                self.pending_proposal = None
                self.state = S.VALIDATING
                self._settle()

        elif ev is Ev.HOLD_RELEASED:
            self.screened_clear_docset = p["docset_hash"]
            self.state = S.EXTRACTING if self.pending_extraction else S.VALIDATING
            self._settle()

        elif ev is Ev.FILING_SUBMITTED:
            self.state = S.FILED

        elif ev is Ev.CLOSED:
            self.state = S.CLOSED

        elif ev is Ev.CANCELLED:
            self.state = S.CANCELLED

        self.version = e.aggregate_version
        self.history.append((e.sequence, ev.value, self.state.value if self.state else ""))

    def _settle(self) -> None:
        """Re-derive the post-validation state from facts. Fail-closed."""
        if self.state not in (S.VALIDATING, S.EXCEPTION_OPEN, S.READY_FOR_FILING):
            return
        current = self.docset_hash
        if self.validated_docset != current:
            self.state = S.VALIDATING
        elif self.open_issues or self.missing_documents:
            self.state = S.EXCEPTION_OPEN
        elif self.screened_clear_docset != current:
            self.state = S.VALIDATING
        else:
            self.state = S.READY_FOR_FILING
