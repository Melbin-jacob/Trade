import pytest
from pydantic import ValidationError

from sentinel.domain.documents import DocumentType as DT
from sentinel.kernel.service import GuardViolation, RemediationAction, sha256_hex
from sentinel.kernel.shipment import InvalidTransition
from sentinel.security.principals import AuthorizationError, Principal, PrincipalKind, Role
from tests.conftest import TENANT
from tests.test_shipment_lifecycle import SHP, ingest_all, weight_issue


@pytest.mark.parametrize("role", [Role.REVIEWER, Role.CUSTOMS_FILER, Role.COMPLIANCE_OFFICER, Role.RULE_ENGINE])
def test_agents_cannot_be_granted_write_roles(role):
    with pytest.raises(ValidationError):
        Principal(id="agent-x", kind=PrincipalKind.AGENT, tenant_id=TENANT, roles=frozenset({role}))


def test_services_cannot_hold_human_only_permissions():
    with pytest.raises(ValidationError):
        Principal(id="svc", kind=PrincipalKind.SERVICE, tenant_id=TENANT, roles=frozenset({Role.REVIEWER}))


def test_analyzer_agent_is_read_only(service, actors):
    a = actors
    ingest_all(service, a)
    assert service.load(a["analyzer"], TENANT, SHP).state is not None
    with pytest.raises(AuthorizationError):
        service.register_document(a["analyzer"], TENANT, SHP, DT.PACKING_LIST, b"x", "email", "s3://b")
    with pytest.raises(AuthorizationError):
        service.propose_remediation(a["analyzer"], TENANT, SHP, ["x"], RemediationAction.EMAIL_DRAFT, "hi", [])


def test_drafter_agent_cannot_approve_or_file(service, actors):
    a = actors
    agg = ingest_all(service, a)
    agg = service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "r1", [weight_issue(agg)])
    agg = service.propose_remediation(
        a["drafter"], TENANT, SHP, ["weight_mismatch:line4"], RemediationAction.EMAIL_DRAFT, "draft", ["x@y.example"]
    )
    pid = agg.pending_proposal["proposal_id"]
    with pytest.raises(AuthorizationError):
        service.approve_remediation(a["drafter"], TENANT, SHP, pid, sha256_hex(b"draft"))
    with pytest.raises(AuthorizationError):
        service.submit_filing(a["drafter"], TENANT, SHP, "ACE", b"x", agg.docset_hash)


def test_cross_tenant_access_looks_like_not_found(service, actors):
    a = actors
    ingest_all(service, a)
    with pytest.raises(AuthorizationError, match="not found"):
        service.load(a["other_tenant"], TENANT, SHP)


def test_cannot_file_while_issues_open(service, actors):
    a = actors
    agg = ingest_all(service, a)
    agg = service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "r1", [weight_issue(agg)])
    with pytest.raises(InvalidTransition):
        service.submit_filing(a["filer"], TENANT, SHP, "ACE", b"x", agg.docset_hash)


def test_waiver_requires_real_justification(service, actors):
    a = actors
    agg = ingest_all(service, a)
    service.record_validation(a["rules"], TENANT, SHP, agg.docset_hash, "r1", [weight_issue(agg)])
    with pytest.raises(GuardViolation):
        service.waive_issues(a["reviewer"], TENANT, SHP, ["weight_mismatch:line4"], "ok")
