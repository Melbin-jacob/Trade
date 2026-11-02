"""Deterministic customs filing payload (canonical JSON) built from validated data.

The same inputs always produce the same bytes, so the hash the filer approves
is exactly the payload the dispatcher transmits.
"""

from __future__ import annotations

from sentinel.core.canonical import canonical_json
from sentinel.domain.documents import DocumentType as DT
from sentinel.kernel.shipment import ShipmentAggregate
from sentinel.rules.engine import DocRef, _v


def build_filing_payload(agg: ShipmentAggregate, docs: dict[DT, DocRef], customs_system: str) -> bytes:
    inv = docs[DT.COMMERCIAL_INVOICE].doc
    bl = docs[DT.BILL_OF_LADING].doc
    pl = docs[DT.PACKING_LIST].doc
    return canonical_json({
        "schema": "sentinel.customs-declaration/1",
        "customs_system": customs_system,
        "shipment_id": agg.shipment_id,
        "reference": agg.reference,
        "docset_hash": agg.docset_hash,
        "importer": _v(inv.buyer.name),
        "exporter": _v(inv.seller.name),
        "bill_of_lading": _v(bl.document_number),
        "vessel": _v(bl.vessel_name),
        "port_of_loading": _v(bl.port_of_loading),
        "port_of_discharge": _v(bl.port_of_discharge),
        "containers": sorted(_v(c.container_number) for c in bl.containers),
        "total_packages": _v(pl.total_packages),
        "gross_weight_kg": _v(pl.total_gross_weight).to_kg(),
        "invoice_number": _v(inv.document_number),
        "invoice_total": _v(inv.invoice_total),
        "lines": [
            {"line_no": ln.line_no, "description": _v(ln.description), "hs_code": _v(ln.hs_code),
             "quantity": _v(ln.quantity), "unit": _v(ln.unit_of_measure), "value": _v(ln.line_total),
             "origin": _v(ln.country_of_origin)}
            for ln in inv.lines
        ],
        "waived_issues": dict(sorted(agg.waived.items())),
    })
