"""Read models for the HITL dashboard (projections over the ledger + encrypted stores)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from pydantic import BaseModel

from sentinel.domain.fields import CONFIDENCE_REVIEW_THRESHOLD, ExtractedField
from sentinel.extraction.pipeline import load_document
from sentinel.kernel.shipment import TERMINAL, TRANSITIONS, Ev, ShipmentAggregate, ShipmentState as S
from sentinel.ledger.chain import LedgerStore
from sentinel.rules.runner import load_report
from sentinel.security.principals import Principal
from sentinel.storage.blobs import EncryptedBlobStore

ACTIONS = {
    "approve_remediation": Ev.REMEDIATION_APPROVED, "reject_remediation": Ev.REMEDIATION_REJECTED,
    "waive_issues": Ev.ISSUES_WAIVED, "release_hold": Ev.HOLD_RELEASED, "submit_filing": Ev.FILING_SUBMITTED,
    "close": Ev.CLOSED, "cancel": Ev.CANCELLED,
}


def _jsonable(v: Any) -> Any:
    if isinstance(v, BaseModel):
        return json.loads(v.model_dump_json())
    if isinstance(v, Decimal):
        return str(v)
    return v


def shipment_ids(store: LedgerStore, tenant_id: str) -> list[str]:
    seen: dict[str, None] = {}
    for e in store.read_chain(tenant_id):
        if e.aggregate_type == "shipment":
            seen[e.aggregate_id] = None
    return list(seen)


def load_all(store: LedgerStore, tenant_id: str) -> list[ShipmentAggregate]:
    by_id: dict[str, list] = {}
    for e in store.read_chain(tenant_id):
        if e.aggregate_type == "shipment":
            by_id.setdefault(e.aggregate_id, []).append(e)
    return [ShipmentAggregate.replay(tenant_id, sid, entries) for sid, entries in by_id.items()]


def free_time(agg: ShipmentAggregate, now: datetime) -> dict[str, Any]:
    if not agg.free_time_expires_at:
        return {"expires_at": None, "days_left": None, "bucket": "unknown"}
    exp = datetime.fromisoformat(agg.free_time_expires_at)
    days = (exp - now).total_seconds() / 86400
    bucket = "demurrage" if days < 0 else ("soon" if days <= 3 else "later")
    return {"expires_at": agg.free_time_expires_at, "days_left": round(days, 1), "bucket": bucket}


def available_actions(agg: ShipmentAggregate, user: Principal) -> list[str]:
    return [name for name, ev in ACTIONS.items()
            if agg.state in TRANSITIONS[ev].allowed_from and TRANSITIONS[ev].permission in user.permissions]


def summary(agg: ShipmentAggregate, now: datetime) -> dict[str, Any]:
    open_ = agg.open_issues
    return {
        "shipment_id": agg.shipment_id, "reference": agg.reference, "state": agg.state.value if agg.state else None,
        "open_issues": len(open_), "critical_issues": sum(i.get("severity") == "critical" for i in open_.values()),
        "documents": {t.value: len(v) for t, v in agg.documents.items()},
        "free_time": free_time(agg, now), "awaiting_approval": agg.pending_proposal is not None,
        "updated_seq": agg.history[-1][0] if agg.history else 0,
    }


def _fields(doc: BaseModel):
    from sentinel.rules.engine import _walk
    return list(_walk(doc))


def dashboard(store: LedgerStore, blobs: EncryptedBlobStore, tenant_id: str, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    aggs = [a for a in load_all(store, tenant_id) if a.state not in TERMINAL]
    with_docs = [a for a in aggs if any(a.documents.values())]

    checks = {"integrity": [0, 0], "regulatory": [0, 0]}
    confident, total_fields = 0, 0
    for a in with_docs:
        if a.validated_docset:
            try:
                rep = load_report(blobs, tenant_id, a.shipment_id, a.validated_docset)
            except FileNotFoundError:
                rep = {"trace": []}
            stack = list(rep["trace"])
            while stack:
                n = stack.pop()
                stack.extend(n["children"])
                if n["children"] or n["outcome"] == "skip":
                    continue
                bucket = "regulatory" if n["rule_id"].startswith(("TARIFF", "PHYTO", "COO_REQ", "ROUGH", "IMPORT")) else "integrity"
                checks[bucket][0] += n["outcome"] == "pass" or n.get("issue_id") in a.waived
                checks[bucket][1] += 1
        for versions in a.documents.values():
            sha = versions[-1].content_sha256
            if sha in a.pending_extraction:
                continue
            try:
                doc = load_document(blobs, tenant_id, a.shipment_id, sha)
            except FileNotFoundError:
                continue
            for _, f in _fields(doc):
                total_fields += 1
                confident += f.value is not None and f.confidence >= CONFIDENCE_REVIEW_THRESHOLD
    screened = sum(1 for a in with_docs if a.screened_clear_docset == a.docset_hash)
    holds = sum(1 for a in aggs if a.state is S.COMPLIANCE_HOLD)

    def pct(n, d):
        return None if d == 0 else int(100 * n / d)  # floor: never round a gap up to 100%

    categories = [
        {"key": "integrity", "label": "Document integrity", "score": pct(*checks["integrity"]),
         "hint": "Cross-document checks passing on current document sets"},
        {"key": "screening", "label": "Sanctions & embargo", "score": pct(screened, len(with_docs)),
         "hint": "Shipments screened clear on their current document set"},
        {"key": "regulatory", "label": "HS, tariff & import rules", "score": pct(*checks["regulatory"]),
         "hint": "Tariff and import-requirement checks passing"},
        {"key": "confidence", "label": "Extraction confidence", "score": pct(confident, total_fields),
         "hint": f"Fields extracted at or above {CONFIDENCE_REVIEW_THRESHOLD}% confidence"},
    ]
    scored = [c["score"] for c in categories if c["score"] is not None]
    overall = round(sum(scored) / len(scored)) if scored else None

    cards = []
    for a in aggs:
        open_ = a.open_issues
        if not open_ and a.state is not S.COMPLIANCE_HOLD:
            continue
        top = sorted(open_.values(), key=lambda i: (i.get("severity") != "critical", i["id"]))
        total = len(a.issues) or 1
        cards.append({
            "shipment_id": a.shipment_id, "reference": a.reference, "state": a.state.value,
            "title": "Sanctions screening hit - shipment on hold" if a.state is S.COMPLIANCE_HOLD
            else (top[0]["message"] if top else "Review required"),
            "description": f"{len(open_)} open issue(s)" + (f"; {len(top) - 1} more" if len(top) > 1 else ""),
            "free_time": free_time(a, now),
            "owner": "Awaiting approval" if a.pending_proposal else ("Compliance officers" if a.state is S.COMPLIANCE_HOLD else "Unassigned"),
            "progress": round(100 * (total - len(open_)) / total),
            "progress_label": "Draft ready for review" if a.pending_proposal else
            ("Waiting for counterparty" if a.state is S.AWAITING_CORRECTION else "Not started"),
        })
    order = {"demurrage": 0, "soon": 1, "later": 2, "unknown": 3}
    cards.sort(key=lambda c: (order[c["free_time"]["bucket"]], c["free_time"]["days_left"] or 0))
    buckets = {b: sum(1 for c in cards if c["free_time"]["bucket"] == b) for b in ("demurrage", "soon", "later")}
    calendar = [{"date": a.free_time_expires_at[:10], "shipment_id": a.shipment_id, "reference": a.reference,
                 "kind": "free_time_expiry"} for a in aggs if a.free_time_expires_at]
    by_state: dict[str, int] = {}
    for a in aggs:
        by_state[a.state.value] = by_state.get(a.state.value, 0) + 1
    return {"generated_at": now.isoformat(), "overall_score": overall, "categories": categories,
            "attention": {"buckets": buckets, "cards": cards}, "calendar": calendar, "states": by_state,
            "holds": holds, "active_shipments": len(aggs)}


def shipment_detail(store: LedgerStore, blobs: EncryptedBlobStore, agg: ShipmentAggregate, user: Principal,
                    now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    entries = store.read_aggregate(agg.tenant_id, agg.shipment_id)
    screening = next((e.payload for e in reversed(entries) if e.event_type == "screening.completed"), None)
    report = None
    if agg.validated_docset:
        try:
            report = load_report(blobs, agg.tenant_id, agg.shipment_id, agg.validated_docset)
        except FileNotFoundError:
            pass
    proposal = None
    if agg.pending_proposal:
        proposal = {**agg.pending_proposal, "draft_parsed": json.loads(agg.pending_proposal["draft"])}
    return {
        **summary(agg, now),
        "docset_hash": agg.docset_hash,
        "blocking_reasons": agg.blocking_reasons(),
        "issues": [{**i, "status": "waived" if k in agg.waived else "open", "waiver": agg.waived.get(k)}
                   for k, i in sorted(agg.issues.items())],
        "documents": [
            {"doc_type": t.value, "versions": [
                {"version": v.version, "content_sha256": v.content_sha256, "source_channel": v.source_channel,
                 "extracted": v.content_sha256 not in agg.pending_extraction, "current": v is vs[-1]}
                for v in vs]}
            for t, vs in sorted(agg.documents.items())
        ],
        "proposal": proposal,
        "screening": screening,
        "decision_tree": report["trace"] if report and report["docset_hash"] == agg.docset_hash else None,
        "ruleset_version": report["ruleset_version"] if report else None,
        "history": [{"sequence": e.sequence, "at": e.recorded_at.isoformat(), "event": e.event_type,
                     "actor": e.actor, "entry_hash": e.entry_hash} for e in entries],
        "actions": available_actions(agg, user),
    }


_SEG = re.compile(r"([a-z_]+)(?:\[(\d+|\*)\])?")


def resolve(doc: Any, path: str) -> list[tuple[str, Any]]:
    """Resolve 'lines[3].gross_weight' / 'containers[*].gross_weight' to (path, node) pairs."""
    nodes = [("", doc)]
    for seg in path.split("."):
        m = _SEG.fullmatch(seg)
        if not m:
            return []
        name, idx = m.groups()
        nxt = []
        for p, n in nodes:
            v = getattr(n, name, None)
            base = f"{p}.{name}" if p else name
            if idx is None:
                nxt.append((base, v))
            elif isinstance(v, list):
                items = enumerate(v) if idx == "*" else ([(int(idx), v[int(idx)])] if int(idx) < len(v) else [])
                nxt += [(f"{base}[{i}]", x) for i, x in items]
        nodes = nxt
    return nodes


def _field_view(f: Any) -> Any:
    if isinstance(f, ExtractedField):
        return {"value": _jsonable(f.value), "confidence": str(f.confidence), "extractor": f.extractor.value,
                "raw_text": f.raw_text, "source": _jsonable(f.source) if f.source else None,
                "needs_review": f.needs_review}
    if isinstance(f, BaseModel):
        return {k: _field_view(getattr(f, k)) for k in type(f).model_fields if k != "doc_type"}
    if isinstance(f, list):
        return [_field_view(x) for x in f]
    return _jsonable(f)


def issue_diff(blobs: EncryptedBlobStore, agg: ShipmentAggregate, issue_id: str) -> dict[str, Any]:
    issue = agg.issues.get(issue_id)
    if issue is None:
        raise KeyError(issue_id)
    sides = []
    for ev in issue.get("evidence", []):
        try:
            doc = load_document(blobs, agg.tenant_id, agg.shipment_id, ev["content_sha256"])
        except FileNotFoundError:
            continue
        # Show the whole enclosing record (e.g. the full invoice line) for side-by-side context.
        container_path = re.sub(r"\.[a-z_]+$", "", ev["field_path"]) if "[" in ev["field_path"] else ""
        context = resolve(doc, container_path) if container_path else []
        sides.append({
            "doc_type": ev["doc_type"], "content_sha256": ev["content_sha256"], "field_path": ev["field_path"],
            "highlight": ev["field_path"].rsplit(".", 1)[-1], "value": ev.get("value"),
            "fields": [{"path": p, "data": _field_view(n)} for p, n in resolve(doc, ev["field_path"])],
            "context": [{"path": p, "data": _field_view(n)} for p, n in context],
        })
    return {"issue": issue, "sides": sides}
