"""Four-eyes co-signing: one officer requests, a different officer co-signs.

Requests are audited in the ledger. They are held in memory here; move them to
the database before running more than one API replica.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.ledger.audit import AuditLog
from sentinel.security.principals import Principal

TTL = timedelta(hours=24)


@dataclass
class CosignRequest:
    id: str
    tenant_id: str
    kind: str  # release_hold | waive_critical
    shipment_id: str
    requester: Principal
    params: dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def view(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "shipment_id": self.shipment_id, "requested_by": self.requester.id,
                "params": self.params, "created_at": self.created_at.isoformat(),
                "expires_at": (self.created_at + TTL).isoformat()}


class CosignBook:
    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit
        self._items: dict[str, CosignRequest] = {}
        self._lock = threading.Lock()

    def request(self, requester: Principal, kind: str, shipment_id: str, params: dict[str, Any]) -> CosignRequest:
        req = CosignRequest(str(uuid.uuid4()), requester.tenant_id, kind, shipment_id, requester, params)
        with self._lock:
            self._items[req.id] = req
        self._audit.record(tenant_id=req.tenant_id, actor=requester.audit_ref(), aggregate_type="cosign",
                           aggregate_id=f"cosign:{req.id}", event_type="cosign.requested",
                           payload={"kind": kind, "shipment_id": shipment_id, "params": params})
        return req

    def pending(self, tenant_id: str) -> list[CosignRequest]:
        now = datetime.now(timezone.utc)
        with self._lock:
            return [r for r in self._items.values() if r.tenant_id == tenant_id and now - r.created_at < TTL]

    def take(self, tenant_id: str, req_id: str) -> CosignRequest:
        with self._lock:
            req = self._items.get(req_id)
            if req is None or req.tenant_id != tenant_id or datetime.now(timezone.utc) - req.created_at >= TTL:
                raise KeyError(req_id)
            return self._items.pop(req_id)

    def restore(self, req: CosignRequest) -> None:
        with self._lock:
            self._items[req.id] = req
