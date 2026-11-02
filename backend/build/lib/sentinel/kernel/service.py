"""Shipment command service - the only code path that writes to the ledger.

Every command follows the same pipeline:

    authenticate (caller) -> authorize (permission + tenant) -> load (replay)
    -> check transition table -> check guards -> append signed event -> evolve

Nothing here calls an external system. Approved external actions (customs
filing, ERP update, outbound email) are picked up from the ledger by the
dispatcher via the transactional-outbox pattern, so an action can only ever
happen if its approval is already in the audit trail.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from sentinel.core.canonical import canonical_json
from sentinel.domain.documents import DocumentType, TradeDocument
from sentinel.ledger.chain import EventDraft, Ledger
from sentinel.kernel.shipment import (
    AGGREGATE_TYPE,
    TRANSITIONS,
    Ev,
    InvalidTransition,
    ShipmentAggregate,
)
from sentinel.security.principals import (
    AuthorizationError,
    Permission,
    Principal,
    PrincipalKind,
)

MIN_JUSTIFICATION_CHARS = 20


class GuardViolation(InvalidTransition):
    pass


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"  # waiving requires a second approver


class EvidenceRef(BaseModel):
    """Points at the exact spot on a document version - drives the diff viewer."""

    model_config = ConfigDict(frozen=True)

    doc_type: DocumentType
    content_sha256: str
    field_path: str  # e.g. "lines[3].gross_weight"
    value: str | None = None


class Issue(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(pattern=r"^[a-z0-9_:\.\[\]\-]{3,200}$")
    kind: Literal["discrepancy", "regulatory", "missing_document", "format"]
    severity: Severity
    rule_id: str
    message: str
    evidence: list[EvidenceRef] = []


class RemediationAction(StrEnum):
    EMAIL_DRAFT = "email_draft"
    API_CORRECTION = "api_correction"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ShipmentService:
    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    # ------------------------------------------------------------------ #
    # Plumbing
    # ------------------------------------------------------------------ #

    def load(self, principal: Principal, tenant_id: str, shipment_id: str) -> ShipmentAggregate:
        principal.require(Permission.SHIPMENT_READ, tenant_id)
        return self._load(tenant_id, shipment_id)

    def _load(self, tenant_id: str, shipment_id: str) -> ShipmentAggregate:
        entries = self._ledger.store.read_aggregate(tenant_id, shipment_id)
        if not entries:
            raise AuthorizationError("not found")
        return ShipmentAggregate.replay(tenant_id, shipment_id, entries)

    def _execute(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        event: Ev,
        build: Any,  # Callable[[ShipmentAggregate], dict] - runs guards, returns payload
        extra_actor: dict[str, str] | None = None,
    ) -> ShipmentAggregate:
        rule = TRANSITIONS[event]
        principal.require(rule.permission, tenant_id)
        agg = self._load(tenant_id, shipment_id)
        if agg.state not in rule.allowed_from:
            raise InvalidTransition(f"{event.value} not allowed from {agg.state}")
        payload = build(agg)
        actor = principal.audit_ref() | (extra_actor or {})
        entries = self._ledger.append(
            tenant_id=tenant_id,
            aggregate_type=AGGREGATE_TYPE,
            aggregate_id=shipment_id,
            expected_version=agg.version,
            actor=actor,
            events=[EventDraft(event.value, payload)],
        )
        for e in entries:
            agg.apply(e)
        return agg

    @staticmethod
    def _require_justification(text: str) -> None:
        if len(text.strip()) < MIN_JUSTIFICATION_CHARS:
            raise GuardViolation(f"justification must be at least {MIN_JUSTIFICATION_CHARS} characters")

    @staticmethod
    def _require_second_approver(first: Principal, second: Principal, permission: Permission) -> None:
        if second.kind is not PrincipalKind.HUMAN:
            raise GuardViolation("second approver must be human")
        if second.id == first.id:
            raise GuardViolation("four-eyes rule: approvers must be different people")
        second.require(permission, first.tenant_id)

    # ------------------------------------------------------------------ #
    # Commands
    # ------------------------------------------------------------------ #

    def open_shipment(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        reference: str,
        free_time_expires_at: datetime | None = None,
    ) -> ShipmentAggregate:
        principal.require(Permission.DOCUMENT_INGEST, tenant_id)
        entries = self._ledger.append(
            tenant_id=tenant_id,
            aggregate_type=AGGREGATE_TYPE,
            aggregate_id=shipment_id,
            expected_version=0,  # ConcurrencyConflict if it already exists
            actor=principal.audit_ref(),
            events=[EventDraft(Ev.OPENED.value, {"reference": reference, "free_time_expires_at": free_time_expires_at})],
        )
        return ShipmentAggregate.replay(tenant_id, shipment_id, entries)

    def register_document(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        doc_type: DocumentType,
        content: bytes,
        source_channel: Literal["email", "object_storage", "port_api", "manual_upload"],
        storage_uri: str,
    ) -> ShipmentAggregate:
        # The hash is computed here from the bytes - never trusted from the caller.
        content_sha256 = sha256_hex(content)

        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            latest = agg.latest(doc_type)
            if latest and latest.content_sha256 == content_sha256:
                raise GuardViolation("identical to the current version (duplicate delivery)")
            return {
                "doc_type": doc_type,
                "version": (latest.version + 1) if latest else 1,
                "content_sha256": content_sha256,
                "supersedes_sha256": latest.content_sha256 if latest else None,
                "byte_length": len(content),
                "source_channel": source_channel,
                "storage_uri": storage_uri,
            }

        return self._execute(principal, tenant_id, shipment_id, Ev.DOCUMENT_REGISTERED, build)

    def record_extraction(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        content_sha256: str,
        document: TradeDocument,
        pipeline_version: str,
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            latest = agg.latest(document.doc_type)
            if latest is None or latest.content_sha256 != content_sha256:
                raise GuardViolation("extraction is for a stale or unknown document version")
            if content_sha256 not in agg.pending_extraction:
                raise GuardViolation("document version already extracted")
            return {
                "doc_type": document.doc_type,
                "content_sha256": content_sha256,
                "extraction_sha256": sha256_hex(canonical_json(document)),
                "pipeline_version": pipeline_version,
                "review_flags": document.review_flags(),
            }

        return self._execute(principal, tenant_id, shipment_id, Ev.EXTRACTION_COMPLETED, build)

    def record_validation(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        docset_hash: str,
        ruleset_version: str,
        issues: list[Issue],
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            if docset_hash != agg.docset_hash:
                raise GuardViolation("validation ran against a stale document set")
            ids = [i.id for i in issues]
            if len(ids) != len(set(ids)):
                raise GuardViolation("duplicate issue ids")
            return {"docset_hash": docset_hash, "ruleset_version": ruleset_version, "issues": issues}

        return self._execute(principal, tenant_id, shipment_id, Ev.VALIDATION_COMPLETED, build)

    def record_screening(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        docset_hash: str,
        result: Literal["clear", "hit"],
        provider: str,
        list_versions: dict[str, str],
        matches: list[dict[str, str]] | None = None,
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            # Fail closed: a HIT is honoured even for an older document set,
            # but a CLEAR only counts for the exact current set.
            if result == "clear" and docset_hash != agg.docset_hash:
                raise GuardViolation("clear result is for a stale document set")
            if result == "hit" and not matches:
                raise GuardViolation("a hit must include the matched entries")
            return {
                "docset_hash": docset_hash,
                "result": result,
                "provider": provider,
                "list_versions": list_versions,
                "matches": matches or [],
            }

        return self._execute(principal, tenant_id, shipment_id, Ev.SCREENING_COMPLETED, build)

    def propose_remediation(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        issue_ids: list[str],
        action: RemediationAction,
        draft: str,
        recipients: list[str],
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            unknown = set(issue_ids) - set(agg.open_issues)
            if not issue_ids or unknown:
                raise GuardViolation(f"proposal references unknown/closed issues: {sorted(unknown)}")
            return {
                "proposal_id": str(uuid4()),
                "issue_ids": sorted(issue_ids),
                "action": action,
                "draft": draft,
                "draft_sha256": sha256_hex(draft.encode("utf-8")),
                "recipients": sorted(recipients),
                "proposed_by": principal.id,
            }

        return self._execute(principal, tenant_id, shipment_id, Ev.REMEDIATION_PROPOSED, build)

    def approve_remediation(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        proposal_id: str,
        reviewed_draft_sha256: str,
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            prop = agg.pending_proposal
            if not prop or prop["proposal_id"] != proposal_id:
                raise GuardViolation("proposal is not pending")
            if prop["draft_sha256"] != reviewed_draft_sha256:
                # The approver must have seen exactly the text that will be sent.
                raise GuardViolation("approved content does not match the proposed draft")
            if prop["proposed_by"] == principal.id:
                raise GuardViolation("proposer cannot approve their own proposal")
            return {"proposal_id": proposal_id, "draft_sha256": reviewed_draft_sha256}

        return self._execute(principal, tenant_id, shipment_id, Ev.REMEDIATION_APPROVED, build)

    def reject_remediation(
        self, principal: Principal, tenant_id: str, shipment_id: str, proposal_id: str, reason: str
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            if not agg.pending_proposal or agg.pending_proposal["proposal_id"] != proposal_id:
                raise GuardViolation("proposal is not pending")
            self._require_justification(reason)
            return {"proposal_id": proposal_id, "reason": reason}

        return self._execute(principal, tenant_id, shipment_id, Ev.REMEDIATION_REJECTED, build)

    def waive_issues(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        issue_ids: list[str],
        justification: str,
        second_approver: Principal | None = None,
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            self._require_justification(justification)
            open_ = agg.open_issues
            unknown = set(issue_ids) - set(open_)
            if not issue_ids or unknown:
                raise GuardViolation(f"cannot waive unknown/closed issues: {sorted(unknown)}")
            critical = [i for i in issue_ids if open_[i].get("severity") == Severity.CRITICAL]
            if critical:
                if second_approver is None:
                    raise GuardViolation(f"critical issues need a second approver: {critical}")
                self._require_second_approver(principal, second_approver, Permission.EXCEPTION_OVERRIDE)
            return {"issue_ids": sorted(issue_ids), "justification": justification}

        extra = {"second_approver": second_approver.id} if second_approver else None
        return self._execute(principal, tenant_id, shipment_id, Ev.ISSUES_WAIVED, build, extra)

    def release_hold(
        self,
        principal: Principal,
        second_approver: Principal,
        tenant_id: str,
        shipment_id: str,
        justification: str,
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            self._require_justification(justification)
            self._require_second_approver(principal, second_approver, Permission.HOLD_RELEASE)
            return {"docset_hash": agg.docset_hash, "justification": justification}

        return self._execute(
            principal, tenant_id, shipment_id, Ev.HOLD_RELEASED, build, {"second_approver": second_approver.id}
        )

    def submit_filing(
        self,
        principal: Principal,
        tenant_id: str,
        shipment_id: str,
        customs_system: str,
        filing_payload: bytes,
        reviewed_docset_hash: str,
    ) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            if reviewed_docset_hash != agg.docset_hash:
                raise GuardViolation("documents changed since the filer reviewed them")
            if agg.blocking_reasons():
                raise GuardViolation("; ".join(agg.blocking_reasons()))
            return {
                "customs_system": customs_system,
                "filing_payload_sha256": sha256_hex(filing_payload),
                "docset_hash": agg.docset_hash,
            }

        return self._execute(principal, tenant_id, shipment_id, Ev.FILING_SUBMITTED, build)

    def close(self, principal: Principal, tenant_id: str, shipment_id: str) -> ShipmentAggregate:
        return self._execute(principal, tenant_id, shipment_id, Ev.CLOSED, lambda agg: {})

    def cancel(self, principal: Principal, tenant_id: str, shipment_id: str, reason: str) -> ShipmentAggregate:
        def build(agg: ShipmentAggregate) -> dict[str, Any]:
            self._require_justification(reason)
            return {"reason": reason}

        return self._execute(principal, tenant_id, shipment_id, Ev.CANCELLED, build)
