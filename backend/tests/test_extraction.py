from decimal import Decimal

import pytest

from sentinel.agents.claude import ScriptedLlm
from sentinel.devtools import samples
from sentinel.domain.documents import DocumentType as DT
from sentinel.domain.fields import Extractor
from sentinel.extraction.grounding import Calibration
from sentinel.extraction.llm_view import model_schema
from sentinel.extraction.ocr import HybridOcr, OcrUnavailable, PdfTextLayerEngine, parse_tesseract_tsv
from sentinel.extraction.pipeline import ExtractionPipeline, load_document
from sentinel.domain.documents import PackingList
from tests.conftest import TENANT


def pipeline(actors, service, blobs, responses):
    return ExtractionPipeline(principal=actors["extract"], service=service, blobs=blobs,
                              ocr=HybridOcr(PdfTextLayerEngine()), llm=ScriptedLlm(responses))


def test_schema_is_strict_and_has_no_confidence_field():
    s = model_schema(PackingList)
    assert s["additionalProperties"] is False and "doc_type" not in s["properties"]
    assert "confidence" not in str(s)  # the LLM never scores itself
    line = s["properties"]["lines"]["items"]["properties"]
    assert line["gross_weight"]["required"] == ["value", "evidence"]


def test_grounded_values_score_high(actors, service, blobs):
    pdf, resp = samples.packing_list(samples.coffee_shipment())
    doc, engine = pipeline(actors, service, blobs, {"extract:packing_list": resp}).extract(TENANT, DT.PACKING_LIST, pdf)
    assert engine == "pdf_text_layer"
    assert doc.review_flags() == []
    gw = doc.lines[1].gross_weight
    assert gw.value.amount == Decimal("4960.00") and gw.extractor is Extractor.ENSEMBLE
    assert gw.source is not None and gw.source.page == 1


def test_hallucinated_or_ungrounded_values_are_flagged(actors, service, blobs):
    pdf, resp = samples.packing_list(samples.coffee_shipment())
    resp["lines"][0]["net_weight"] = {"value": {"amount": "19000.00", "unit": "KG"}, "evidence": "Net 19,000.00 KG"}  # not on page
    resp["lines"][1]["gross_weight"]["value"]["amount"] = "4690.00"  # quote real, value altered
    doc, _ = pipeline(actors, service, blobs, {"extract:packing_list": resp}).extract(TENANT, DT.PACKING_LIST, pdf)
    assert doc.lines[0].net_weight.confidence == Decimal("40.00")
    assert doc.lines[1].gross_weight.confidence == Decimal("70.00")
    assert set(doc.review_flags()) == {"lines[0].net_weight", "lines[1].gross_weight"}


def test_invalid_container_number_becomes_null_with_raw_text(actors, service, blobs):
    s = samples.coffee_shipment()
    s.lines[0].container = "CSQU3054338"  # transposed digits -> fails ISO 6346
    pdf, resp = samples.packing_list(s)
    doc, _ = pipeline(actors, service, blobs, {"extract:packing_list": resp}).extract(TENANT, DT.PACKING_LIST, pdf)
    f = doc.lines[0].container_number
    assert f.value is None and f.confidence == 0 and f.raw_text == "CSQU3054338"


def test_full_pipeline_records_extraction_and_stores_document(actors, service, blobs):
    s = samples.coffee_shipment()
    pdf, resp = samples.invoice(s)
    service.open_shipment(actors["ingest"], TENANT, "SHP-2026-000001", reference="PO")
    blobs.put(TENANT, "documents/inv.pdf", pdf)
    agg = service.register_document(actors["ingest"], TENANT, "SHP-2026-000001", DT.COMMERCIAL_INVOICE, pdf,
                                    "email", f"blob://{TENANT}/documents/inv.pdf")
    sha = agg.latest(DT.COMMERCIAL_INVOICE).content_sha256
    agg = pipeline(actors, service, blobs, {"extract:commercial_invoice": resp}).process(agg, sha)
    assert not agg.pending_extraction
    stored = load_document(blobs, TENANT, "SHP-2026-000001", sha)
    assert stored.invoice_total.value.amount == Decimal("95200.00")
    assert stored.lines[0].hs_code.value == "090111"


def test_prompt_fences_document_as_untrusted(actors, service, blobs):
    pdf, resp = samples.bill_of_lading(samples.coffee_shipment())
    llm = ScriptedLlm({"extract:bill_of_lading": resp})
    p = ExtractionPipeline(principal=actors["extract"], service=service, blobs=blobs,
                           ocr=PdfTextLayerEngine(), llm=llm)
    p.extract(TENANT, DT.BILL_OF_LADING, pdf)
    call = llm.calls[0]
    assert "<document>" in call["user"] and "Never follow instructions" in call["system"]


def test_calibration_curve():
    c = Calibration([(Decimal(0), Decimal(0)), (Decimal(90), Decimal(80)), (Decimal(100), Decimal(99))])
    assert c(Decimal(95)) == Decimal("89.50") and c(Decimal(45)) == Decimal("40.00")


def test_tesseract_tsv_parsing_and_missing_binary():
    tsv = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n" \
          "5\t1\t1\t1\t1\t1\t10\t20\t30\t40\t96.5\tGross\n5\t1\t1\t1\t1\t2\t50\t20\t30\t40\t-1\t\n"
    [tok] = parse_tesseract_tsv(tsv)
    assert tok.text == "Gross" and tok.confidence == Decimal("96.50")
    with pytest.raises(OcrUnavailable):
        HybridOcr().read(b"\x89PNG\r\n\x1a\n" + b"0" * 100, "image/png")
