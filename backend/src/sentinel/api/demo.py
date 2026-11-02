"""Self-contained demo: ``SENTINEL_ENV=dev uvicorn sentinel.api.main:app``.

In-memory ledger, local KMS, offline scripted LLM (or real Claude when
SENTINEL_DEMO_USE_CLAUDE=1 and credentials are configured), and six seeded
shipments that exercise every review path. Never use in production.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel

from sentinel.agents.claude import ClaudeJsonLlm
from sentinel.api.app import create_app, mount_frontend
from sentinel.api.auth import issue_dev_token
from sentinel.api.settings import Settings
from sentinel.crypto.envelope import LocalKms
from sentinel.devtools import samples
from sentinel.devtools.reference_data import DEMO_ALT_CSV, DEMO_SDN_CSV, DEMO_TARIFF_CSV
from sentinel.devtools.scripted import demo_llm
from sentinel.dispatch.outbox import RecordingCustomsGateway, RecordingEmailSender
from sentinel.domain.documents import DocumentType as DT
from sentinel.extraction.ocr import PdfTextLayerEngine
from sentinel.ingestion.channels import IntakeItem
from sentinel.ingestion.scanner import EicarOnlyScanner
from sentinel.ledger.chain import InMemoryLedgerStore
from sentinel.ledger.signing import Ed25519Signer, KeyRing
from sentinel.platform import Platform, build_platform
from sentinel.regulatory.sanctions import StaticSanctionsProvider, parse_ofac
from sentinel.regulatory.tariff import StaticTariffSchedule
from sentinel.storage.blobs import InMemoryBlobStore
from sentinel.tenancy import Counterparty, TenantConfig, TenantDirectory

TENANT = "acme_trading"
USERS = {
    "alex.lee": ("Alex Lee", ["reviewer"]),
    "emma.davis": ("Emma Davis", ["compliance_officer"]),
    "jane.doe": ("Jane Doe", ["compliance_officer"]),
    "sam.patel": ("Sam Patel", ["customs_filer"]),
    "kim.auditor": ("Kim Park", ["auditor"]),
}


def _scenarios():
    now = datetime.now(timezone.utc)
    coffee = samples.coffee_shipment()

    typo = replace(coffee, invoice_no="INV-2026-0042", lines=[replace(ln) for ln in coffee.lines])
    typo_pl_bad = replace(typo, lines=[replace(typo.lines[0]), replace(typo.lines[1], gross="4,690.00")])

    clean = replace(coffee, ref="PO-778901", invoice_no="INV-2026-0057", bl_no="MEDU7781200", seal="ML-901122",
                    lines=[replace(ln, container="TGHU1234567") for ln in coffee.lines])

    mango = replace(coffee, ref="PO-779310", invoice_no="INV-2026-0061", bl_no="MAEU5512093", seal="MS-551209",
                    seller="Frutas del Pacifico S.A.C.", seller_country="PE", pol="PECLL",
                    lines=[samples.Line("Fresh mangoes, Kent variety", "0804.50", 1200, "18.50", "4,800.00",
                                        "5,280.00", "MSKU7319021", "PE")])

    sanctioned = replace(coffee, ref="PO-779455", invoice_no="INV-2026-0073", bl_no="CMDU4410028", seal="CM-441002",
                         buyer="Kestrel Bulk Lines", lines=[replace(ln, container="CMAU2178547") for ln in coffee.lines])

    blurry = replace(coffee, ref="PO-779502", invoice_no="INV-2026-0080", bl_no="HLCU9910331", seal="HL-991033",
                     lines=[replace(ln, container="HLXU8034523") for ln in coffee.lines])

    return now, [
        # id, reference, free-time offset (days), documents [(DT, (pdf, resp))], follow-ups
        ("SHP-2026-000123", typo.ref, -2, [(DT.COMMERCIAL_INVOICE, samples.invoice(typo)),
                                          (DT.BILL_OF_LADING, samples.bill_of_lading(typo)),
                                          (DT.CERTIFICATE_OF_ORIGIN, samples.certificate_of_origin(typo)),
                                          (DT.PACKING_LIST, samples.packing_list(typo_pl_bad))]),
        ("SHP-2026-000124", clean.ref, 6, [(DT.COMMERCIAL_INVOICE, samples.invoice(clean)),
                                          (DT.BILL_OF_LADING, samples.bill_of_lading(clean)),
                                          (DT.CERTIFICATE_OF_ORIGIN, samples.certificate_of_origin(clean)),
                                          (DT.PACKING_LIST, samples.packing_list(clean))]),
        ("SHP-2026-000125", mango.ref, 2, [(DT.COMMERCIAL_INVOICE, samples.invoice(mango)),
                                          (DT.BILL_OF_LADING, samples.bill_of_lading(mango)),
                                          (DT.PACKING_LIST, samples.packing_list(mango))]),
        ("SHP-2026-000126", sanctioned.ref, 1, [(DT.COMMERCIAL_INVOICE, samples.invoice(sanctioned)),
                                               (DT.BILL_OF_LADING, samples.bill_of_lading(sanctioned)),
                                               (DT.PACKING_LIST, samples.packing_list(sanctioned))]),
        ("SHP-2026-000127", blurry.ref, 9, [(DT.COMMERCIAL_INVOICE, _blurry_invoice(blurry)),
                                           (DT.BILL_OF_LADING, samples.bill_of_lading(blurry)),
                                           (DT.CERTIFICATE_OF_ORIGIN, samples.certificate_of_origin(blurry)),
                                           (DT.PACKING_LIST, samples.packing_list(blurry))]),
    ], samples.packing_list(typo)


def _blurry_invoice(s):
    pdf, resp = samples.invoice(s)
    # The model "read" a total that is not on the page -> grounding caps the confidence.
    resp["invoice_total"] = {"value": {"amount": "95200.00", "currency": "USD"}, "evidence": "TOTAL DUE USD 95,200.00"}
    return pdf, resp


def build_demo_platform() -> tuple[Platform, dict]:
    tenants = TenantDirectory([TenantConfig(
        tenant_id=TENANT, kms_key_ref="kms://acme-trading", data_region="ca-central-1",
        counterparties=(
            Counterparty("Fazenda Boa Vista Exportadora Ltda", "supplier", "export@fazendaboavista.example",
                         frozenset({"fazendaboavista.example"})),
            Counterparty("Oceanic Lines S.A.", "shipping_line", "documentation@oceaniclines.example",
                         frozenset({"oceaniclines.example"})),
        ),
        inbound_email_domains=frozenset({"fazendaboavista.example", "oceaniclines.example"}),
    )])
    kms = LocalKms()
    kms.create_key("kms://acme-trading")
    signer = Ed25519Signer("demo-ledger-key-1")
    keyring = KeyRing()
    keyring.add(signer.key_id, signer.public_key())
    now, scenarios, corrected_pl = _scenarios()
    extractions: dict[str, list[dict]] = {}
    for _, _, _, docs in scenarios:
        for dt, (_, resp) in docs:
            extractions.setdefault(dt.value, []).append(resp)
    extractions["packing_list"].append(corrected_pl[1])
    use_claude = os.environ.get("SENTINEL_DEMO_USE_CLAUDE") == "1"
    email, customs = RecordingEmailSender(), RecordingCustomsGateway()
    platform = build_platform(
        tenants=tenants, store=InMemoryLedgerStore(), signer=signer, keyring=keyring,
        raw_blobs=InMemoryBlobStore(), kms=kms,
        llm_factory=(lambda audit: ClaudeJsonLlm(audit=audit)) if use_claude
        else (lambda audit: demo_llm(extractions, audit)),
        scanner=EicarOnlyScanner(),
        sanctions=StaticSanctionsProvider(parse_ofac(DEMO_SDN_CSV, DEMO_ALT_CSV, "demo-fictitious-2026-11")),
        tariff=StaticTariffSchedule.from_csv(DEMO_TARIFF_CSV), email=email, customs=customs,
        ocr=PdfTextLayerEngine(), company_name="Acme Trading Inc.",
    )
    rt = platform.runtime(TENANT)
    for shipment_id, ref, days, docs in scenarios:
        platform.service.open_shipment(rt.principals["ingest"], TENANT, shipment_id, ref,
                                       (now + timedelta(days=days)).replace(microsecond=0))
        for dt, (pdf, _) in docs:
            rt.gateway.ingest(IntakeItem(TENANT, shipment_id, f"{dt.value}.pdf", pdf, "email",
                                         metadata={"sender": "seed"}))
    rt.orchestrator.tick(TENANT)
    return platform, {"email": email, "customs": customs, "corrected_packing_list": corrected_pl[0]}


class TokenRequest(BaseModel):
    user: str


def create_demo_app():
    os.environ.setdefault("SENTINEL_DEV_JWT_SECRET", secrets.token_urlsafe(48))
    settings = Settings(env="dev", dev_jwt_secret=os.environ["SENTINEL_DEV_JWT_SECRET"],
                        cors_origins=["http://localhost:5173"], rate_limit_per_minute=600)
    platform, extras = build_demo_platform()
    app = create_app(platform, settings)
    app.state.demo = extras

    @app.get("/api/v1/dev/users")
    def dev_users():
        return [{"id": k, "name": v[0], "roles": v[1]} for k, v in USERS.items()]

    @app.post("/api/v1/dev/token")
    def dev_token(body: TokenRequest):
        if body.user not in USERS:
            raise HTTPException(404, "unknown demo user")
        name, roles = USERS[body.user]
        return {"token": issue_dev_token(settings, body.user, TENANT, roles, name), "name": name, "roles": roles}

    @app.get("/api/v1/dev/outbox")
    def dev_outbox():
        return {"emails": extras["email"].sent,
                "customs": [{**s, "payload": s["payload"].decode()} for s in extras["customs"].submissions]}

    @app.get("/api/v1/dev/sample/corrected-packing-list")
    def corrected():
        from fastapi.responses import Response
        return Response(extras["corrected_packing_list"], media_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="packing-list-corrected.pdf"'})

    mount_frontend(app, os.environ.get("SENTINEL_FRONTEND_DIST",
                                       str(Path(__file__).resolve().parents[4] / "frontend" / "dist")))
    return app
