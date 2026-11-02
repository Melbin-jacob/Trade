from decimal import Decimal

import pytest

from sentinel.agents.claude import ScriptedLlm
from sentinel.devtools import samples
from sentinel.domain.documents import DocumentType as DT
from sentinel.extraction.ocr import PdfTextLayerEngine
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.rules.engine import DocRef, RuleEngine, _transposition
from sentinel.rules.semantic import HybridMatcher, TokenMatcher, party_similarity
from tests.conftest import TENANT

BUILDERS = {DT.COMMERCIAL_INVOICE: samples.invoice, DT.PACKING_LIST: samples.packing_list,
            DT.BILL_OF_LADING: samples.bill_of_lading, DT.CERTIFICATE_OF_ORIGIN: samples.certificate_of_origin}


def extract_all(actors, service, blobs, shipment, overrides=None, only=None):
    docs = {}
    for dt, build in BUILDERS.items():
        if only and dt not in only:
            continue
        pdf, resp = (overrides or {}).get(dt) or build(shipment)
        p = ExtractionPipeline(principal=actors["extract"], service=service, blobs=blobs,
                               ocr=PdfTextLayerEngine(), llm=ScriptedLlm({f"extract:{dt.value}": resp}))
        doc, _ = p.extract(TENANT, dt, pdf)
        docs[dt] = DocRef(dt, f"sha-{dt.value}", doc)
    return docs


def failed(report):
    return sorted(i.rule_id for i in report.issues)


def test_clean_shipment_has_no_issues(actors, service, blobs):
    report = RuleEngine().evaluate(extract_all(actors, service, blobs, samples.coffee_shipment()))
    assert report.issues == []
    assert all(n.outcome in ("pass", "skip") for n in report.trace)


def test_weight_and_container_discrepancies(actors, service, blobs):
    good = samples.coffee_shipment()
    bad = samples.coffee_shipment()
    bad.lines[1].gross = "4,690.00"          # supplier transposed 4960 -> 4690
    bad.lines[0].container = "CSQU3054338"   # transposed check digit
    report = RuleEngine().evaluate(extract_all(
        actors, service, blobs, good, overrides={DT.PACKING_LIST: samples.packing_list(bad)}))
    by_rule = {i.rule_id: i for i in report.issues}
    # 4,690 kg gross is also below the 4,800 kg net weight - a second, independent signal.
    assert set(by_rule) == {"BL_PL_GROSS", "FIELD_FORMAT", "PL_NET_LE_GROSS"}
    gross = by_rule["BL_PL_GROSS"]
    assert "24,480.00 kg" in gross.message and "24,210.00 kg" in gross.message and gross.severity == "warning"  # 1.12% < 2% critical band
    assert {e.doc_type for e in gross.evidence} == {DT.BILL_OF_LADING, DT.PACKING_LIST}
    assert "ISO 6346" in by_rule["FIELD_FORMAT"].message


def test_invoice_arithmetic_and_quantity(actors, service, blobs):
    s = samples.coffee_shipment()
    pdf, resp = samples.invoice(s)
    resp["lines"][0]["quantity"]["value"] = "300"  # contradicts packing list and amount
    report = RuleEngine().evaluate(extract_all(actors, service, blobs, s, overrides={DT.COMMERCIAL_INVOICE: (pdf, resp)}))
    assert {"INV_LINE_ARITHMETIC", "INV_PL_QUANTITY"} <= set(failed(report))


def test_missing_documents_and_origin(actors, service, blobs):
    s = samples.coffee_shipment()
    s.lines[1].origin = "VN"
    report = RuleEngine().evaluate(extract_all(actors, service, blobs, s,
                                               only={DT.COMMERCIAL_INVOICE, DT.CERTIFICATE_OF_ORIGIN}))
    rules = failed(report)
    assert rules.count("DOC_REQUIRED") == 2 and "INV_COO_ORIGIN" in rules


def test_trace_tree_explains_failures(actors, service, blobs):
    bad = samples.coffee_shipment()
    bad.bl_gross_override = "25,480.00"
    report = RuleEngine().evaluate(extract_all(actors, service, blobs, bad))
    node = next(n for n in report.trace if n.outcome == "fail")
    leaf = next(c for c in node.children if c.outcome == "fail")
    assert leaf.inputs["difference_pct"] == "4.08" and leaf.issue_id == report.issues[0].id


def test_transposition_detection():
    assert _transposition("CSQU3054383", "CSQU3054833")
    assert not _transposition("CSQU3054383", "CSQU3054384")


def test_matchers_and_llm_audit(audit, actors):
    assert TokenMatcher().match("Green coffee beans, Arabica", "GREEN COFFEE BEAN arabica").score >= 0.8
    llm = ScriptedLlm({"semantic_match": {"label": "same_goods", "rationale": "Coffea arabica is Arabica coffee"}}, audit)
    m = HybridMatcher(llm, TENANT, actors["analyzer"].audit_ref())
    r = m.match("Green coffee beans, Arabica", "Coffea arabica seeds, unroasted")
    assert r.method == "llm" and r.score == pytest.approx(0.95)
    assert "<untrusted>" in llm.calls[0]["user"]
    assert party_similarity("Acme Trading Inc.", "ACME TRADING INCORPORATED") >= 0.5
