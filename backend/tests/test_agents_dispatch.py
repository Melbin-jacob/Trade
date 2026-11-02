import json
import uuid
from datetime import datetime, timezone

import pytest

from sentinel.agents.claude import ScriptedLlm
from sentinel.agents.remediation import RemediationDrafter
from sentinel.dispatch.outbox import Dispatcher, RecordingCustomsGateway, RecordingEmailSender, dlp_findings
from sentinel.kernel.service import Issue, Severity, sha256_hex
from sentinel.ledger.chain import EventDraft
from sentinel.security.principals import Principal, PrincipalKind, Role
from tests.conftest import TENANT
from tests.test_shipment_lifecycle import SHP, ingest_all

ISSUE = Issue(id="bl_pl_gross:gross_weight", kind="discrepancy", severity=Severity.CRITICAL, rule_id="BL_PL_GROSS",
              message="Gross weight mismatch: B/L 24,480.00 kg vs packing list 24,210.00 kg")


def exception_open(service, actors):
    agg = ingest_all(service, actors)
    return service.record_validation(actors["rules"], TENANT, SHP, agg.docset_hash, "r1", [ISSUE])


def drafter(service, tenants, actors, response):
    llm = ScriptedLlm({"draft_remediation": response}) if response is not None else None
    return RemediationDrafter(principal=actors["drafter"], service=service, tenants=tenants, llm=llm), llm


GOOD = {"subject": "Packing list correction - PO-778812",
        "body": "Hello, the packing list gross weight (24,210 kg) differs from the B/L (24,480 kg). "
                "Please reissue a corrected packing list. Trade Compliance Team, Acme Trading Inc.",
        "covered_issue_ids": [ISSUE.id]}


def test_llm_draft_used_and_recipient_from_directory(service, tenants, actors):
    agg = exception_open(service, actors)
    d, llm = drafter(service, tenants, actors, GOOD)
    agg = d.propose(agg)
    draft = json.loads(agg.pending_proposal["draft"])
    assert draft["generated_by"] == "llm" and draft["to"] == ["docs@techsol.example"]
    assert "<untrusted>" in llm.calls[0]["user"]


@pytest.mark.parametrize("bad", [
    {**GOOD, "body": GOOD["body"] + " Update your records at https://evil.example/login"},
    {**GOOD, "body": GOOD["body"] + " Also please confirm your IBAN for the refund."},
    {**GOOD, "covered_issue_ids": []},
])
def test_unsafe_llm_output_falls_back_to_template(service, tenants, actors, bad):
    agg = exception_open(service, actors)
    d, _ = drafter(service, tenants, actors, bad)
    draft = json.loads(d.propose(agg).pending_proposal["draft"])
    assert draft["generated_by"] == "template" and "24,210.00 kg" in draft["body"]


def make_dispatcher(store, audit, tenants, blobs):
    p = Principal(id="svc-dispatcher", kind=PrincipalKind.SERVICE, tenant_id=TENANT, roles=frozenset({Role.DISPATCHER}))
    email = RecordingEmailSender()
    return Dispatcher(principal=p, store=store, audit=audit, tenants=tenants, blobs=blobs,
                      email=email, customs=RecordingCustomsGateway()), email


def test_dispatcher_blocks_non_allowlisted_recipient(service, tenants, actors, store, audit, blobs):
    agg = exception_open(service, actors)
    draft = json.dumps({"to": ["ops@attacker.example"], "subject": "x", "body": "y", "issue_ids": [ISSUE.id]})
    agg = service.propose_remediation(actors["drafter"], TENANT, SHP, [ISSUE.id], "email_draft", draft, ["ops@attacker.example"])
    service.approve_remediation(actors["reviewer"], TENANT, SHP, agg.pending_proposal["proposal_id"], sha256_hex(draft.encode()))
    dispatcher, email = make_dispatcher(store, audit, tenants, blobs)
    [r] = dispatcher.run_once(TENANT)
    assert r.outcome == "blocked" and email.sent == []


def test_dispatcher_dlp_and_tamper_detection(service, tenants, actors, store, audit, blobs, ledger):
    agg = exception_open(service, actors)
    draft = json.dumps({"to": ["docs@techsol.example"], "subject": "x", "issue_ids": [ISSUE.id],
                        "body": "Pay with card 4111 1111 1111 1111 please"})
    agg = service.propose_remediation(actors["drafter"], TENANT, SHP, [ISSUE.id], "email_draft", draft, ["docs@techsol.example"])
    service.approve_remediation(actors["reviewer"], TENANT, SHP, agg.pending_proposal["proposal_id"], sha256_hex(draft.encode()))
    dispatcher, email = make_dispatcher(store, audit, tenants, blobs)
    [r] = dispatcher.run_once(TENANT)
    assert r.outcome == "blocked" and "payment card" in r.detail and email.sent == []


def test_dlp_patterns():
    assert dlp_findings("card 4111-1111-1111-1111") == ["payment card number"]
    assert dlp_findings("container CSQU3054383, B/L MEDU1234567, 24,480.00 kg") == []
    assert "IBAN" in dlp_findings("IBAN DE89 3704 0044 0532 0130 00")
