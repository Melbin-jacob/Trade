"""Sanctions & embargo screening of every party and country on the shipment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sentinel.domain.documents import DocumentType as DT, Party
from sentinel.kernel.service import ShipmentService
from sentinel.kernel.shipment import ShipmentAggregate
from sentinel.ledger.audit import AuditLog
from sentinel.regulatory.resilience import CircuitBreaker
from sentinel.regulatory.sanctions import EMBARGOED_COUNTRIES, SanctionsIndex
from sentinel.rules.engine import DocRef, _v
from sentinel.rules.runner import current_documents
from sentinel.security.principals import Principal
from sentinel.storage.blobs import EncryptedBlobStore


class SanctionsProvider(Protocol):
    def current(self) -> SanctionsIndex: ...


@dataclass(frozen=True)
class ScreenedParty:
    name: str
    role: str
    doc_type: str


def parties_and_countries(docs: dict[DT, DocRef]) -> tuple[list[ScreenedParty], set[str]]:
    parties, countries = [], set()
    for dt, ref in docs.items():
        doc = ref.doc
        for role in ("seller", "buyer", "shipper", "consignee", "notify_party", "carrier", "exporter"):
            p: Party | None = getattr(doc, role, None)
            if p is None:
                continue
            if (name := _v(p.name)):
                parties.append(ScreenedParty(name, role, dt.value))
            if p.country and (c := _v(p.country)):
                countries.add(c)
        for attr in ("port_of_loading", "port_of_discharge"):
            if (loc := _v(getattr(doc, attr, None))):
                countries.add(loc[:2].upper())
        if (o := _v(getattr(doc, "origin_country", None))):
            countries.add(o)
        for ln in getattr(doc, "lines", []):
            if getattr(ln, "country_of_origin", None) and (c := _v(ln.country_of_origin)):
                countries.add(c)
    return parties, countries


class ScreeningService:
    def __init__(self, *, principal: Principal, service: ShipmentService, blobs: EncryptedBlobStore,
                 provider: SanctionsProvider, audit: AuditLog, threshold: float = 0.88,
                 embargoed: frozenset[str] = EMBARGOED_COUNTRIES, breaker: CircuitBreaker | None = None) -> None:
        self._principal, self._service, self._blobs = principal, service, blobs
        self._provider, self._audit, self._threshold, self._embargoed = provider, audit, threshold, embargoed
        self._breaker = breaker or CircuitBreaker("sanctions-lists")

    def run(self, agg: ShipmentAggregate) -> ShipmentAggregate | None:
        """Screen the current document set. Returns None (and records nothing that
        could clear the shipment) if the sanctions source is unavailable."""
        docset = agg.docset_hash
        docs = current_documents(self._blobs, agg)
        parties, countries = parties_and_countries(docs)
        try:
            index = self._breaker.call(self._provider.current)
        except Exception as exc:
            self._audit.external_call(tenant_id=agg.tenant_id, actor=self._principal.audit_ref(),
                                      system="sanctions", operation="load_lists", request={"docset": docset},
                                      outcome=f"error:{type(exc).__name__}", correlation_id=f"{agg.shipment_id}-{docset[:12]}")
            return None
        matches = []
        for p in parties:
            for m in index.search(p.name, self._threshold):
                matches.append({"list": m.entry.list_name, "uid": m.entry.uid, "listed_name": m.matched_name,
                                "party": p.name, "role": p.role, "document": p.doc_type,
                                "program": m.entry.program, "score": f"{m.score:.4f}"})
        for c in sorted(countries & self._embargoed):
            matches.append({"list": "EMBARGO", "uid": f"EMBARGO-{c}", "listed_name": c, "party": c,
                            "role": "country", "document": "-", "program": "comprehensive embargo", "score": "1.0000"})
        return self._service.record_screening(
            self._principal, agg.tenant_id, agg.shipment_id, docset, "hit" if matches else "clear",
            provider="sentinel-screening", list_versions={"sanctions": index.version},
            matches=matches or None,
        )
