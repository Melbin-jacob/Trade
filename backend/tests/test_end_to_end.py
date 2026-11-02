"""Full autonomous loop: ingest -> extract -> validate -> screen -> draft -> approve
-> dispatch -> corrected document -> ready -> file -> customs submission."""

import json

import pytest

from sentinel.devtools import samples
from sentinel.devtools.reference_data import DEMO_ALT_CSV, DEMO_SDN_CSV, DEMO_TARIFF_CSV
from sentinel.devtools.scripted import demo_llm
from sentinel.dispatch.filing import build_filing_payload
from sentinel.dispatch.outbox import RecordingCustomsGateway, RecordingEmailSender, filing_key
from sentinel.domain.documents import DocumentType as DT
from sentinel.extraction.ocr import PdfTextLayerEngine
from sentinel.ingestion.channels import IntakeItem
from sentinel.ingestion.scanner import EicarOnlyScanner
from sentinel.kernel.service import sha256_hex
from sentinel.kernel.shipment import ShipmentState as S
from sentinel.ledger.chain import InMemoryLedgerStore, verify_chain
from sentinel.platform import build_platform
from sentinel.regulatory.sanctions import StaticSanctionsProvider, parse_ofac
from sentinel.regulatory.tariff import StaticTariffSchedule
from sentinel.rules.runner import current_documents
from tests.conftest import TENANT

SHP = "SHP-2026-000123"


@pytest.fixture
def world(tenants, kms, raw_blobs, signer, keyring):
    good = samples.coffee_shipment()
    bad = samples.coffee_shipment()
    bad.lines[1].gross = "4,690.00"
    docs = {
        DT.COMMERCIAL_INVOICE: samples.invoice(good),
        DT.BILL_OF_LADING: samples.bill_of_lading(good),
        DT.CERTIFICATE_OF_ORIGIN: samples.certificate_of_origin(good),
        "pl_v1": samples.packing_list(bad),
        "pl_v2": samples.packing_list(good),
    }
    extractions = {
        "commercial_invoice": [docs[DT.COMMERCIAL_INVOICE][1]],
        "bill_of_lading": [docs[DT.BILL_OF_LADING][1]],
        "certificate_of_origin": [docs[DT.CERTIFICATE_OF_ORIGIN][1]],
        "packing_list": [docs["pl_v1"][1], docs["pl_v2"][1]],
    }
    email, customs = RecordingEmailSender(), RecordingCustomsGateway()
    platform = build_platform(
        tenants=tenants, store=InMemoryLedgerStore(), signer=signer, keyring=keyring, raw_blobs=raw_blobs, kms=kms,
        llm_factory=lambda audit: demo_llm(extractions, audit), scanner=EicarOnlyScanner(),
        sanctions=StaticSanctionsProvider(parse_ofac(DEMO_SDN_CSV, DEMO_ALT_CSV, "demo")),
        tariff=StaticTariffSchedule.from_csv(DEMO_TARIFF_CSV), email=email, customs=customs,
        ocr=PdfTextLayerEngine(),
    )
    return platform, docs, email, customs


def ingest(platform, rt, pdf, name):
    return rt.gateway.ingest(IntakeItem(TENANT, SHP, name, pdf, "email"))


def test_autonomous_reconciliation_loop(world, actors):
    platform, docs, email, customs = world
    rt = platform.runtime(TENANT)
    svc = platform.service
    svc.open_shipment(rt.principals["ingest"], TENANT, SHP, reference="PO-778812")
    for key in (DT.COMMERCIAL_INVOICE, DT.BILL_OF_LADING, DT.CERTIFICATE_OF_ORIGIN, "pl_v1"):
        assert ingest(platform, rt, docs[key][0], str(key)).outcome == "accepted"

    report = rt.orchestrator.tick(TENANT)
    assert report.failures == []
    agg = svc.load(actors["analyzer"], TENANT, SHP)
    assert agg.state is S.REMEDIATION_PENDING_APPROVAL
    assert {i["rule_id"] for i in agg.open_issues.values()} == {"BL_PL_GROSS", "PL_NET_LE_GROSS"}
    draft = json.loads(agg.pending_proposal["draft"])
    assert draft["to"] == ["docs@techsol.example"]  # from the tenant directory, not the documents
    assert "24,210.00 kg" in draft["body"]
    assert email.sent == []  # nothing leaves without a human

    # Human approves the exact draft they reviewed -> dispatcher sends it.
    reviewer = actors["reviewer"]
    svc.approve_remediation(reviewer, TENANT, SHP, agg.pending_proposal["proposal_id"],
                            sha256_hex(agg.pending_proposal["draft"].encode()))
    rt.orchestrator.tick(TENANT)
    assert len(email.sent) == 1 and email.sent[0]["to"] == ["docs@techsol.example"]
    rt.orchestrator.tick(TENANT)
    assert len(email.sent) == 1  # idempotent

    # Supplier replies with a corrected packing list.
    assert ingest(platform, rt, docs["pl_v2"][0], "pl_v2.pdf").outcome == "accepted"
    rt.orchestrator.tick(TENANT)
    agg = svc.load(actors["analyzer"], TENANT, SHP)
    assert agg.state is S.READY_FOR_FILING, agg.blocking_reasons()

    # Filer submits; payload is stored, hash-approved, then transmitted by the dispatcher.
    payload = build_filing_payload(agg, current_documents(platform.blobs, agg), "CBSA-CARM")
    platform.blobs.put(TENANT, filing_key(SHP, sha256_hex(payload)), payload)
    svc.submit_filing(actors["filer"], TENANT, SHP, "CBSA-CARM", payload, agg.docset_hash)
    rt.orchestrator.tick(TENANT)
    assert customs.submissions and customs.submissions[0]["payload"] == payload

    chain = platform.store.read_chain(TENANT)
    assert verify_chain(chain, platform.keyring).ok
    kinds = {e.aggregate_type for e in chain}
    assert {"shipment", "intake", "llm_call", "external_call", "dispatch"} <= kinds


def test_sanctions_hit_blocks_autonomy(world, actors):
    platform, docs, email, _ = world
    s = samples.coffee_shipment()
    s.buyer = "Kestrel Bulk Lines"
    pdf, resp = samples.bill_of_lading(s)
    platform.runtime(TENANT)  # build
    rt = platform.runtime(TENANT)
    # swap in the tainted B/L extraction
    rt.orchestrator._extraction._llm._responses["extract:bill_of_lading"] = lambda user: resp
    platform.service.open_shipment(rt.principals["ingest"], TENANT, SHP, reference="PO-1")
    for content in (docs[DT.COMMERCIAL_INVOICE][0], pdf, docs["pl_v2"][0]):
        ingest(platform, rt, content, "x.pdf")
    rt.orchestrator.tick(TENANT)
    agg = platform.service.load(actors["analyzer"], TENANT, SHP)
    assert agg.state is S.COMPLIANCE_HOLD and agg.pending_proposal is None and email.sent == []
