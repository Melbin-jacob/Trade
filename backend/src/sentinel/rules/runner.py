"""Runs the rule engine for a shipment's current document set and records it."""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Callable

from sentinel.core.canonical import canonical_json
from sentinel.extraction.pipeline import load_document
from sentinel.kernel.service import ShipmentService
from sentinel.kernel.shipment import ShipmentAggregate
from sentinel.rules.engine import DocRef, Rule, RuleEngine, ValidationReport
from sentinel.rules.semantic import DescriptionMatcher
from sentinel.security.principals import Principal
from sentinel.storage.blobs import EncryptedBlobStore


def report_key(shipment_id: str, docset_hash: str) -> str:
    return f"validation/{shipment_id.lower()}/{docset_hash}.json"


def current_documents(blobs: EncryptedBlobStore, agg: ShipmentAggregate) -> dict:
    return {
        dt: DocRef(dt, versions[-1].content_sha256,
                   load_document(blobs, agg.tenant_id, agg.shipment_id, versions[-1].content_sha256))
        for dt, versions in agg.documents.items() if versions
    }


class ValidationRunner:
    def __init__(self, *, principal: Principal, service: ShipmentService, blobs: EncryptedBlobStore,
                 engine: RuleEngine, matcher_factory: Callable[[str], DescriptionMatcher] | None = None,
                 rules_factory: Callable[[str], list[Rule]] | None = None) -> None:
        self._principal = principal
        self._service = service
        self._blobs = blobs
        self._engine = engine
        self._matcher_factory = matcher_factory
        self._rules_factory = rules_factory

    def run(self, agg: ShipmentAggregate) -> tuple[ShipmentAggregate, ValidationReport]:
        docset = agg.docset_hash
        docs = current_documents(self._blobs, agg)
        matcher = self._matcher_factory(agg.tenant_id) if self._matcher_factory else None
        extra = self._rules_factory(agg.tenant_id) if self._rules_factory else []
        report = self._engine.evaluate(docs, matcher, extra)
        self._blobs.put(agg.tenant_id, report_key(agg.shipment_id, docset), canonical_json({
            "docset_hash": docset,
            "ruleset_version": report.ruleset_version,
            "issues": report.issues,
            "trace": [dataclasses.asdict(n) for n in report.trace],
        }))
        agg = self._service.record_validation(
            self._principal, agg.tenant_id, agg.shipment_id, docset, report.ruleset_version, report.issues
        )
        return agg, report


def load_report(blobs: EncryptedBlobStore, tenant_id: str, shipment_id: str, docset_hash: str) -> dict[str, Any]:
    return json.loads(blobs.get(tenant_id, report_key(shipment_id, docset_hash)))
