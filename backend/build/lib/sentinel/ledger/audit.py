"""Audit helper for events that are not shipment state transitions.

Records inter-agent messages, LLM calls, external API calls, intake decisions
and dispatches into the same signed, hash-chained tenant ledger.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sentinel.core.canonical import canonical_json
from sentinel.ledger.chain import ConcurrencyConflict, EventDraft, Ledger, LedgerEntry


def digest(value: Any) -> str:
    """Hash of a value for audit payloads that must not store the value itself."""
    data = value if isinstance(value, bytes) else canonical_json(value)
    return hashlib.sha256(data).hexdigest()


class AuditLog:
    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger

    def record(
        self,
        *,
        tenant_id: str,
        actor: dict[str, str],
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
    ) -> LedgerEntry:
        """Append one event. ``expected_version=0`` makes the write create-only
        (used as an idempotency key, e.g. one dispatch per approval)."""
        for _ in range(5):
            version = (
                expected_version
                if expected_version is not None
                else self._ledger.store.aggregate_version(tenant_id, aggregate_id)
            )
            try:
                return self._ledger.append(
                    tenant_id=tenant_id,
                    aggregate_type=aggregate_type,
                    aggregate_id=aggregate_id,
                    expected_version=version,
                    actor=actor,
                    events=[EventDraft(event_type, payload)],
                )[0]
            except ConcurrencyConflict:
                if expected_version is not None:
                    raise
        raise ConcurrencyConflict(aggregate_id)

    def external_call(
        self, *, tenant_id: str, actor: dict[str, str], system: str, operation: str,
        request: Any, outcome: str, response: Any = None, correlation_id: str,
    ) -> LedgerEntry:
        return self.record(
            tenant_id=tenant_id,
            actor=actor,
            aggregate_type="external_call",
            aggregate_id=f"call:{correlation_id}",
            event_type="external_call.completed",
            payload={
                "system": system,
                "operation": operation,
                "request_sha256": digest(request),
                "response_sha256": digest(response) if response is not None else None,
                "outcome": outcome,
            },
        )
