import pytest

from sentinel.devtools import samples
from sentinel.devtools.reference_data import DEMO_ALT_CSV, DEMO_SDN_CSV, DEMO_TARIFF_CSV
from sentinel.domain.documents import DocumentType as DT
from sentinel.kernel.service import sha256_hex
from sentinel.kernel.shipment import ShipmentState as S
from sentinel.regulatory.resilience import CircuitBreaker, CircuitOpen
from sentinel.regulatory.rulepacks import import_rules_pack, tariff_pack
from sentinel.regulatory.sanctions import StaticSanctionsProvider, jaro_winkler, parse_ofac, similarity
from sentinel.regulatory.screening import ScreeningService
from sentinel.regulatory.tariff import StaticTariffSchedule
from sentinel.rules.engine import RuleEngine
from tests.conftest import TENANT
from tests.test_rules import extract_all

INDEX = parse_ofac(DEMO_SDN_CSV, DEMO_ALT_CSV, "demo-2026-11-01")
TARIFF = StaticTariffSchedule.from_csv(DEMO_TARIFF_CSV)


def test_name_matching():
    assert jaro_winkler("martha", "marhta") == pytest.approx(0.9611, abs=1e-4)
    assert similarity("Northern Star Maritime Holdings FZE", "NORTHERN STAR MARITIME HOLDINGS FZE") == 1.0
    assert similarity("Arkady Petrovich Volkov", "VOLKOV, Arkady Petrovich") >= 0.95  # token order
    hits = INDEX.search("Nordstar Maritime F.Z.E.")
    assert hits and hits[0].entry.uid == "OFAC-90001"  # via alias
    assert INDEX.search("Fazenda Boa Vista Exportadora Ltda") == []
    assert INDEX.search("Acme Trading Inc.") == []


def test_tariff_prefix_lookup():
    assert TARIFF.lookup("0901110010", "CA").mfn_rate == "Free"
    assert TARIFF.lookup("090199", "CA") is None


def test_import_rules_and_tariff_pack(actors, service, blobs, audit, store):
    s = samples.coffee_shipment()
    s.lines[1].hs = "0804.50"  # mangoes - needs a phytosanitary certificate into CA
    docs = extract_all(actors, service, blobs, s)
    report = RuleEngine().evaluate(docs, extra_rules=[
        import_rules_pack(), tariff_pack(TARIFF, audit, TENANT, actors["rules"].audit_ref())])
    rules = {i.rule_id for i in report.issues}
    assert "PHYTO_REQUIRED" in rules
    assert "TARIFF_HS_VALID" not in rules  # 0804 is in the CA schedule
    assert any(e.event_type == "external_call.completed" for e in store.read_chain(TENANT))


def test_tariff_outage_fails_closed(actors, service, blobs, audit):
    class Down:
        def lookup(self, hs, country):
            raise TimeoutError("tariff API timeout")

    docs = extract_all(actors, service, blobs, samples.coffee_shipment())
    report = RuleEngine().evaluate(docs, extra_rules=[tariff_pack(Down(), audit, TENANT, {"id": "x", "kind": "service"})])
    assert {i.rule_id for i in report.issues} == {"TARIFF_UNAVAILABLE"}


def test_circuit_breaker():
    t = [0.0]
    b = CircuitBreaker("x", failure_threshold=2, reset_after=10, clock=lambda: t[0])

    def boom():
        raise IOError("down")

    for _ in range(2):
        with pytest.raises(IOError):
            b.call(boom)
    with pytest.raises(CircuitOpen):
        b.call(lambda: 1)
    t[0] = 11
    assert b.state == "half_open" and b.call(lambda: 1) == 1 and b.state == "closed"


def _screening_ready(actors, service, blobs, shipment):
    """Ingest + extract the sample docs through the real pipeline, return aggregate."""
    from sentinel.agents.claude import ScriptedLlm
    from sentinel.extraction.ocr import PdfTextLayerEngine
    from sentinel.extraction.pipeline import ExtractionPipeline

    shp = "SHP-2026-000500"
    service.open_shipment(actors["ingest"], TENANT, shp, reference="PO")
    builders = {DT.COMMERCIAL_INVOICE: samples.invoice, DT.PACKING_LIST: samples.packing_list,
                DT.BILL_OF_LADING: samples.bill_of_lading}
    responses, agg = {}, None
    for dt, build in builders.items():
        pdf, resp = build(shipment)
        responses[f"extract:{dt.value}"] = resp
        key = f"documents/{dt.value}.pdf"
        blobs.put(TENANT, key, pdf)
        agg = service.register_document(actors["ingest"], TENANT, shp, dt, pdf, "email", f"blob://{TENANT}/{key}")
    p = ExtractionPipeline(principal=actors["extract"], service=service, blobs=blobs,
                           ocr=PdfTextLayerEngine(), llm=ScriptedLlm(responses))
    for versions in list(agg.documents.values()):
        agg = p.process(agg, versions[-1].content_sha256)
    return agg


def test_screening_clear_and_hit(actors, service, blobs, audit):
    agg = _screening_ready(actors, service, blobs, samples.coffee_shipment())
    svc = ScreeningService(principal=actors["screen"], service=service, blobs=blobs,
                           provider=StaticSanctionsProvider(INDEX), audit=audit)
    agg = svc.run(agg)
    assert agg.screened_clear_docset == agg.docset_hash


def test_screening_hit_puts_shipment_on_hold(actors, service, blobs, audit):
    s = samples.coffee_shipment()
    s.seller = "Northern Star Maritime Holdings F.Z.E."
    agg = _screening_ready(actors, service, blobs, s)
    svc = ScreeningService(principal=actors["screen"], service=service, blobs=blobs,
                           provider=StaticSanctionsProvider(INDEX), audit=audit)
    agg = svc.run(agg)
    assert agg.state is S.COMPLIANCE_HOLD


def test_sanctions_source_down_records_nothing(actors, service, blobs, audit):
    class Down:
        def current(self):
            raise ConnectionError("list mirror unreachable")

    agg = _screening_ready(actors, service, blobs, samples.coffee_shipment())
    svc = ScreeningService(principal=actors["screen"], service=service, blobs=blobs, provider=Down(), audit=audit)
    assert svc.run(agg) is None
    assert service.load(actors["analyzer"], TENANT, agg.shipment_id).screened_clear_docset is None
