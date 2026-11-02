"""Event-driven orchestrator: tails each tenant's ledger and advances shipments.

Each worker acts under its own least-privilege principal; the orchestrator
itself holds no permissions - it only decides which worker to wake up.
Failures are audited and retried on the next tick; they never skip a step.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.agents.remediation import RemediationDrafter
from sentinel.dispatch.outbox import Dispatcher
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.kernel.shipment import ShipmentAggregate, ShipmentState as S
from sentinel.ledger.audit import AuditLog
from sentinel.ledger.chain import LedgerStore
from sentinel.regulatory.screening import ScreeningService
from sentinel.rules.runner import ValidationRunner

SCREENABLE = {S.VALIDATING, S.EXCEPTION_OPEN, S.REMEDIATION_PENDING_APPROVAL, S.AWAITING_CORRECTION,
              S.READY_FOR_FILING}
ORCHESTRATOR_ACTOR = {"id": "orchestrator", "kind": "service"}


@dataclass
class TickReport:
    advanced: dict[str, list[str]] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(self, *, store: LedgerStore, audit: AuditLog, extraction: ExtractionPipeline,
                 validation: ValidationRunner, screening: ScreeningService, drafter: RemediationDrafter,
                 dispatcher: Dispatcher) -> None:
        self._store, self._audit = store, audit
        self._extraction, self._validation, self._screening = extraction, validation, screening
        self._drafter, self._dispatcher = drafter, dispatcher
        self._checkpoint: dict[str, int] = {}
        self._retry: dict[str, set[str]] = {}

    def _load(self, tenant_id: str, shipment_id: str) -> ShipmentAggregate:
        return ShipmentAggregate.replay(tenant_id, shipment_id, self._store.read_aggregate(tenant_id, shipment_id))

    def _fail(self, agg: ShipmentAggregate, step: str, exc: Exception, report: TickReport) -> None:
        report.failures.append(f"{agg.shipment_id}:{step}:{type(exc).__name__}")
        self._audit.record(tenant_id=agg.tenant_id, actor=ORCHESTRATOR_ACTOR, aggregate_type="pipeline",
                           aggregate_id=f"pipeline:{agg.shipment_id}", event_type="pipeline.step_failed",
                           payload={"step": step, "error": type(exc).__name__, "detail": str(exc)[:500]})

    @staticmethod
    def _proposal_rejected_for_current_validation(agg: ShipmentAggregate) -> bool:
        for _, event, _ in reversed(agg.history):
            if event == "validation.completed":
                return False
            if event == "remediation.rejected":
                return True
        return False

    def advance(self, agg: ShipmentAggregate, report: TickReport) -> ShipmentAggregate:
        steps = report.advanced.setdefault(agg.shipment_id, [])
        for _ in range(12):
            before, step = agg.version, "inspect"
            try:
                if agg.state is S.EXTRACTING and agg.pending_extraction:
                    step = "extract"
                    for sha in sorted(agg.pending_extraction):
                        agg = self._extraction.process(agg, sha)
                elif agg.state is S.VALIDATING and agg.validated_docset != agg.docset_hash:
                    step = "validate"
                    agg, _ = self._validation.run(agg)
                elif agg.state in SCREENABLE and agg.screened_clear_docset != agg.docset_hash \
                        and not self._screened_hit(agg):
                    step = "screen"
                    agg = self._screening.run(agg) or agg
                elif agg.state is S.EXCEPTION_OPEN and agg.pending_proposal is None \
                        and not self._proposal_rejected_for_current_validation(agg):
                    step = "draft_remediation"
                    agg = self._drafter.propose(agg) or agg
                else:
                    return agg
            except Exception as exc:  # audited and retried next tick
                self._fail(agg, step, exc, report)
                return self._load(agg.tenant_id, agg.shipment_id)
            if agg.version == before:
                return agg
            steps.append(step)
        return agg

    def _screened_hit(self, agg: ShipmentAggregate) -> bool:
        """A HIT for the current docset already moved the shipment to hold; don't re-screen."""
        for e in reversed(self._store.read_aggregate(agg.tenant_id, agg.shipment_id)):
            if e.event_type == "screening.completed":
                return e.payload["docset_hash"] == agg.docset_hash and e.payload["result"] == "hit"
        return False

    def tick(self, tenant_id: str) -> TickReport:
        report = TickReport()
        start = self._checkpoint.get(tenant_id, 0) + 1
        touched: list[str] = sorted(self._retry.pop(tenant_id, set()))
        for e in self._store.read_chain(tenant_id, start):
            self._checkpoint[tenant_id] = e.sequence
            if e.aggregate_type == "shipment" and e.aggregate_id not in touched:
                touched.append(e.aggregate_id)
        for shipment_id in touched:
            self.advance(self._load(tenant_id, shipment_id), report)
        for failure in report.failures:
            self._retry.setdefault(tenant_id, set()).add(failure.split(":", 1)[0])
        self._dispatcher.run_once(tenant_id)
        # Our own writes moved the checkpoint forward; that's fine - everything
        # they touched has just been advanced to a stable state.
        self._checkpoint[tenant_id] = self._store.head(tenant_id)[0]
        return report

    def process_shipment(self, tenant_id: str, shipment_id: str) -> ShipmentAggregate:
        agg = self.advance(self._load(tenant_id, shipment_id), TickReport())
        self._dispatcher.run_once(tenant_id)
        return agg
