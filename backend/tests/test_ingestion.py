import base64
import hashlib
import hmac
import json
from email.message import EmailMessage

import pytest
from cryptography.exceptions import InvalidTag

from sentinel.devtools.pdf import make_pdf
from sentinel.domain.documents import DocumentType as DT
from sentinel.ingestion.channels import (
    ChannelRejected,
    IntakeItem,
    ReplayCache,
    from_object_event,
    from_port_api,
    parse_email,
    verify_webhook,
)
from sentinel.ingestion.gateway import IngestionGateway, Outcome
from sentinel.ingestion.inspection import inspect
from sentinel.ingestion.scanner import EicarOnlyScanner, ScannerUnavailable
from sentinel.kernel.shipment import ShipmentState as S
from tests.conftest import TENANT

SHP = "SHP-2026-000777"
INVOICE_PDF = make_pdf(["COMMERCIAL INVOICE", "Invoice No: INV-9", "Unit Price 12.00", "Incoterm: FOB"])


class DownScanner:
    def scan(self, data):
        raise ScannerUnavailable("clamd not reachable")


@pytest.fixture
def gateway(actors, service, blobs, audit):
    service.open_shipment(actors["ingest"], TENANT, SHP, reference="PO-1")
    return IngestionGateway(principal=actors["ingest"], service=service, blobs=blobs,
                            scanner=EicarOnlyScanner(), audit=audit)


def item(content, **kw):
    return IntakeItem(tenant_id=TENANT, shipment_id=SHP, filename="f.pdf", content=content, channel="email", **kw)


def intake_events(store):
    return [e.event_type for e in store.read_chain(TENANT) if e.aggregate_type == "intake"]


def test_accepts_classifies_encrypts_and_registers(gateway, service, actors, raw_blobs, blobs, store):
    r = gateway.ingest(item(INVOICE_PDF))
    assert r.outcome is Outcome.ACCEPTED and r.doc_type is DT.COMMERCIAL_INVOICE
    stored = raw_blobs.get(f"{TENANT}/{r.storage_key}")
    assert INVOICE_PDF not in stored and b"COMMERCIAL" not in stored  # ciphertext at rest
    assert blobs.get(TENANT, r.storage_key) == INVOICE_PDF
    agg = service.load(actors["analyzer"], TENANT, SHP)
    assert agg.state is S.EXTRACTING
    assert agg.latest(DT.COMMERCIAL_INVOICE).content_sha256 == hashlib.sha256(INVOICE_PDF).hexdigest()
    assert intake_events(store) == ["intake.accepted"]


def test_duplicate_is_reported_not_reregistered(gateway, store):
    gateway.ingest(item(INVOICE_PDF))
    assert gateway.ingest(item(INVOICE_PDF)).outcome is Outcome.DUPLICATE


@pytest.mark.parametrize("content,reason", [
    (b"MZ" + b"\0" * 200, "unsupported"),
    (make_pdf(["COMMERCIAL INVOICE"]).replace(b"/Type /Catalog", b"/Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >>"), "active content"),
    (make_pdf(["COMMERCIAL INVOICE"]) + EicarOnlyScanner.EICAR, "malware"),
    (make_pdf(["Hello world, nothing to see"]), "type unclear"),
])
def test_bad_files_are_quarantined(gateway, store, content, reason):
    r = gateway.ingest(item(content))
    assert r.outcome is Outcome.QUARANTINED and reason in r.reason
    assert intake_events(store) == ["intake.quarantined"]


def test_scanner_outage_fails_closed(actors, service, blobs, audit):
    service.open_shipment(actors["ingest"], TENANT, SHP, reference="PO-1")
    gw = IngestionGateway(principal=actors["ingest"], service=service, blobs=blobs, scanner=DownScanner(), audit=audit)
    assert gw.ingest(item(INVOICE_PDF)).outcome is Outcome.QUARANTINED


def test_unknown_shipment_is_quarantined(gateway):
    r = gateway.ingest(IntakeItem(TENANT, "SHP-2026-999999", "f.pdf", INVOICE_PDF, "email"))
    assert r.outcome is Outcome.QUARANTINED


def test_ciphertext_bound_to_tenant_and_key(blobs, raw_blobs):
    blobs.put(TENANT, "documents/a", b"secret bill of lading")
    raw_blobs.put(f"{TENANT}/documents/b", raw_blobs.get(f"{TENANT}/documents/a"))
    with pytest.raises(InvalidTag):
        blobs.get(TENANT, "documents/b")
    with pytest.raises(ValueError):
        blobs.put(TENANT, "../globex_freight/x", b"x")


def test_inspection_rejects_oversize():
    assert not inspect(b"%PDF-" + b"0" * (26 * 1024 * 1024)).ok


# --------------------------------------------------------------------------- #
# Channels
# --------------------------------------------------------------------------- #


def _email(sender="docs@techsol.example", auth="mx.acme.example; dkim=pass; spf=pass; dmarc=pass",
           subject=f"Docs for {SHP}"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, "intake@acme.example", subject
    m["Authentication-Results"] = auth
    m.set_content("see attached")
    m.add_attachment(INVOICE_PDF, maintype="application", subtype="pdf", filename="inv.pdf")
    return m.as_bytes()


def test_email_channel(tenants):
    t = tenants.get(TENANT)
    [it] = parse_email(_email(), t, "mx.acme.example")
    assert it.shipment_id == SHP and it.content == INVOICE_PDF and it.metadata["sender"] == "docs@techsol.example"


@pytest.mark.parametrize("kw", [
    {"sender": "ceo@evil.example"},
    {"auth": "mx.acme.example; dkim=fail; spf=pass; dmarc=fail"},
    {"auth": "mx.attacker.example; dkim=pass; spf=pass; dmarc=pass"},  # forged header from another MTA
    {"subject": "documents"},
])
def test_email_channel_rejections(tenants, kw):
    with pytest.raises(ChannelRejected):
        parse_email(_email(**kw), tenants.get(TENANT), "mx.acme.example")


def test_signed_port_webhook(tenants):
    t = tenants.get(TENANT)
    body = json.dumps({"shipment_id": SHP, "doc_type": "bill_of_lading",
                       "content_b64": base64.b64encode(INVOICE_PDF).decode()}).encode()
    ts, nonce = "1700000000", "n-1"
    sig = hmac.new(t.webhook_secrets["port-montreal"], f"{ts}.{nonce}.".encode() + body, hashlib.sha256).hexdigest()
    replay = ReplayCache()
    kw = dict(tenant=t, partner_id="port-montreal", timestamp=ts, nonce=nonce, body=body, replay=replay, now=1700000010)
    verify_webhook(signature=sig, **kw)
    assert from_port_api(body, t, "port-montreal").doc_type_hint is DT.BILL_OF_LADING
    with pytest.raises(ChannelRejected, match="replayed"):
        verify_webhook(signature=sig, **kw)
    with pytest.raises(ChannelRejected, match="signature"):
        verify_webhook(signature="0" * 64, **{**kw, "nonce": "n-2"})
    with pytest.raises(ChannelRejected, match="tolerance"):
        verify_webhook(signature=sig, **{**kw, "nonce": "n-3", "now": 1700009999})


def test_object_storage_prefix_enforced(tenants, raw_blobs):
    t = tenants.get(TENANT)
    raw_blobs.put(f"inbound/{TENANT}/{SHP}/inv.pdf", INVOICE_PDF)
    assert from_object_event({"key": f"inbound/{TENANT}/{SHP}/inv.pdf"}, t, raw_blobs).content == INVOICE_PDF
    with pytest.raises(ChannelRejected):
        from_object_event({"key": f"inbound/globex_freight/{SHP}/inv.pdf"}, t, raw_blobs)
