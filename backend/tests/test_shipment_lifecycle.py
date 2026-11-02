import pytest

from sentinel.domain.documents import DocumentType as DT
from sentinel.kernel.service import (
    EvidenceRef,
    GuardViolation,
    Issue,
    RemediationAction,
    Severity,
    sha256_hex,
)
from sentinel.kernel.shipment import InvalidTransition, ShipmentAggregate, ShipmentState as S
from sentinel.ledger.chain import verify_chain
from sentinel.security.principals import AuthorizationError
from tests.conftest import TENANT, bill_of_lading, invoice, packing_list

SHP = "SHP-2026-000123"
DOCS = {
    DT.COMMERCIAL_INVOICE: (b"%PDF invoice v1", invoice),
    DT.PACKING_LIST: (b"%PDF packing v1", packing_list),
    DT.BILL_OF_LADING: (b"%PDF bol v1", bill_of_lading),
}
JUST = "Verified with supplier by phone; weight variance within contract tolerance."


def ingest_all(service, a, docs=DOCS, tenant=TENANT):
    service.open_shipment(a["ingest"], tenant, SHP, reference="PO-778812")
    for dt, (content, _) in docs.items():
        service.register_document(a["ingest"], tenant, SHP, dt, content, "email", f"s3://bucket/{dt}")
    agg = None
    for dt, (content, build) in docs.items():
        agg = service.record_extraction(a["extract"], tenant, SHP, sha256_hex(content), build(), "ocr-2.1")
    return agg


def weight_issue(agg, severity=Severity.WARNING):
    inv, pl = agg.latest(DT.COMMERCIAL_INVOICE), agg.latest(DT.PACKING_LIST)
    return Issue(
        id="weight_mismatch:line4",
        kind="discrepancy",
        severity=severity,
        rule_id="GROSS_WEIGHT_TOLERANCE_0_5PCT",
        message="Line 4 gross weight 24,480 kg (packing list) vs 24,120 kg (B/L)",
        evidence=[
            EvidenceRef(doc_type=DT.PACKING_LIST, content_sha256=pl.content_sha256, field_path="lines[3].gross_weight", value="24480 KG"),
            EvidenceRef(doc_type=DT.COMMERCIAL_INVOICE, content_sha256=inv.content_sha256, field_path="lines[3]", value=None),
        ],
    )


def test_happy_path_to_filed_and_closed(service, ledger, keyring, actors):
    a = actors
    agg = ingest_all(service, a)
    assert agg.state is S.VALIDATING
    agg = service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "rules-2026.11", [])
    assert agg.state is S.VALIDATING  # still waiting on screening: fail-closed
    agg = service.record_screening(a["screen"], TENANT, SHP, agg.docset_hash, "clear", "ofac+eu", {"ofac_sdn": "2026-11-01"})
    assert agg.state is S.READY_FOR_FILING
    agg = service.submit_filing(a["filer"], TENANT, SHP, "CBSA-CARM", b"<filing/>", agg.docset_hash)
    agg = service.close(a["filer"], TENANT, SHP)
    assert agg.state is S.CLOSED

    # Replay from the ledger reproduces exactly the same state, and the chain verifies.
    replayed = ShipmentAggregate.replay(TENANT, SHP, ledger.store.read_aggregate(TENANT, SHP))
    assert replayed.state is S.CLOSED and replayed.version == agg.version
    assert verify_chain(ledger.store.read_chain(TENANT), keyring).ok


def test_discrepancy_remediation_loop(service, actors):
    a = actors
    agg = ingest_all(service, a)
    agg = service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "r1", [weight_issue(agg)])
    agg = service.record_screening(a["screen"], TENANT, SHP, agg.docset_hash, "clear", "ofac", {})
    assert agg.state is S.EXCEPTION_OPEN

    draft = "Dear Tech Solutions, please reissue the packing list: line 4 gross weight ..."
    agg = service.propose_remediation(
        a["drafter"], TENANT, SHP, ["weight_mismatch:line4"], RemediationAction.EMAIL_DRAFT, draft, ["docs@techsol.example"]
    )
    assert agg.state is S.REMEDIATION_PENDING_APPROVAL
    pid = agg.pending_proposal["proposal_id"]

    # Reviewer must approve exactly the text the agent drafted.
    with pytest.raises(GuardViolation):
        service.approve_remediation(a["reviewer"], TENANT, SHP, pid, sha256_hex(b"something else"))
    agg = service.approve_remediation(a["reviewer"], TENANT, SHP, pid, sha256_hex(draft.encode()))
    assert agg.state is S.AWAITING_CORRECTION

    # Supplier sends corrected packing list -> re-extract -> previous validation no longer counts.
    new_pl = b"%PDF packing v2"
    agg = service.register_document(a["ingest"], TENANT, SHP, DT.PACKING_LIST, new_pl, "email", "s3://b/pl2")
    assert agg.state is S.EXTRACTING and agg.latest(DT.PACKING_LIST).version == 2
    agg = service.record_extraction(a["extract"], TENANT, SHP, sha256_hex(new_pl), packing_list(), "ocr-2.1")
    assert "current document set not yet validated" in agg.blocking_reasons()
    agg = service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "r1", [])
    agg = service.record_screening(a["screen"], TENANT, SHP, agg.docset_hash, "clear", "ofac", {})
    assert agg.state is S.READY_FOR_FILING


def test_low_confidence_field_blocks_until_human_confirms(service, actors):
    a = actors
    docs = dict(DOCS)
    docs[DT.COMMERCIAL_INVOICE] = (b"%PDF blurry invoice", lambda: invoice(confidence="91.20"))
    agg = ingest_all(service, a, docs)
    # Rule engine reports nothing - the kernel still enforces the 98% threshold.
    agg = service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "r1", [])
    agg = service.record_screening(a["screen"], TENANT, SHP, agg.docset_hash, "clear", "ofac", {})
    assert agg.state is S.EXCEPTION_OPEN
    assert list(agg.open_issues) == ["low_confidence:commercial_invoice:lines[0].line_total"]
    agg = service.waive_issues(a["reviewer"], TENANT, SHP, list(agg.open_issues), JUST)
    assert agg.state is S.READY_FOR_FILING


def test_stale_results_are_rejected(service, actors):
    a = actors
    agg = ingest_all(service, a)
    old = agg.docset_hash
    service.register_document(a["ingest"], TENANT, SHP, DT.PACKING_LIST, b"%PDF pl v2", "email", "s3://b")
    with pytest.raises(InvalidTransition):  # state is EXTRACTING now
        service.record_validation(a["rules"], TENANT, SHP, old, "r1", [])
    with pytest.raises(GuardViolation):  # extraction of the superseded version
        service.record_extraction(a["extract"], TENANT, SHP, sha256_hex(b"%PDF packing v1"), packing_list(), "x")


def test_duplicate_document_delivery_is_rejected(service, actors):
    a = actors
    service.open_shipment(a["ingest"], TENANT, SHP, reference="PO-1")
    service.register_document(a["ingest"], TENANT, SHP, DT.PACKING_LIST, b"same", "email", "s3://b")
    with pytest.raises(GuardViolation):
        service.register_document(a["ingest"], TENANT, SHP, DT.PACKING_LIST, b"same", "port_api", "s3://b")


def test_sanctions_hit_holds_and_requires_four_eyes(service, actors):
    a = actors
    agg = ingest_all(service, a)
    agg = service.record_screening(
        a["screen"], TENANT, SHP, agg.docset_hash, "hit", "ofac", {}, [{"list": "OFAC SDN", "name": "Tech Solutions Ltd"}]
    )
    assert agg.state is S.COMPLIANCE_HOLD
    # New paperwork does not lift a hold.
    agg = service.register_document(a["ingest"], TENANT, SHP, DT.CERTIFICATE_OF_ORIGIN, b"coo", "email", "s3://b")
    assert agg.state is S.COMPLIANCE_HOLD
    with pytest.raises(GuardViolation):
        service.release_hold(a["officer1"], a["officer1"], TENANT, SHP, JUST)
    with pytest.raises(AuthorizationError):
        service.release_hold(a["officer1"], a["reviewer"], TENANT, SHP, JUST)  # reviewer lacks hold:release
    agg = service.release_hold(a["officer1"], a["officer2"], TENANT, SHP, "False positive: different entity, confirmed by registry number.")
    assert agg.state is S.EXTRACTING  # the CoO still needs extraction


def test_critical_waiver_needs_second_approver(service, actors):
    a = actors
    agg = ingest_all(service, a)
    agg = service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "r1", [weight_issue(agg, Severity.CRITICAL)])
    with pytest.raises(GuardViolation):
        service.waive_issues(a["officer1"], TENANT, SHP, ["weight_mismatch:line4"], JUST)
    agg = service.waive_issues(a["officer1"], TENANT, SHP, ["weight_mismatch:line4"], JUST, second_approver=a["officer2"])
    assert not agg.open_issues
