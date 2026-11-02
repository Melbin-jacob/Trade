"""Realistic sample shipment documents for tests and the offline demo.

Each builder returns ``(pdf_bytes, llm_response)`` generated from the same data,
so the scripted LLM's evidence quotes really appear in the PDF text - exactly
the contract a real Claude extraction must satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.devtools.pdf import make_pdf


def F(value, evidence):
    return {"value": value, "evidence": evidence}


def NA():
    return {"value": None, "evidence": ""}


def _money(amount: str, cur="USD"):
    return {"amount": amount.replace(",", ""), "currency": cur}


def _kg(amount: str):
    return {"amount": amount.replace(",", ""), "unit": "KG"}


@dataclass
class Line:
    desc: str
    hs: str
    qty: int
    unit_price: str
    net: str
    gross: str
    container: str
    origin: str = "BR"

    @property
    def total(self) -> str:
        from decimal import Decimal
        return f"{Decimal(self.unit_price.replace(',', '')) * self.qty:,.2f}"


@dataclass
class Shipment:
    ref: str
    invoice_no: str
    seller: str
    seller_country: str
    buyer: str
    buyer_country: str
    lines: list[Line]
    bl_no: str = "MEDU1234567"
    vessel: str = "MSC AURORA"
    voyage: str = "245N"
    pol: str = "BRSSZ"
    pod: str = "CAMTR"
    seal: str = "ML-778812"
    bl_gross_override: str | None = None
    extra: dict = field(default_factory=dict)


def coffee_shipment() -> Shipment:
    return Shipment(
        ref="PO-778812", invoice_no="INV-2026-0042",
        seller="Fazenda Boa Vista Exportadora Ltda", seller_country="BR",
        buyer="Acme Trading Inc.", buyer_country="CA",
        lines=[
            Line("Green coffee beans, Arabica, not roasted", "0901.11", 320, "210.00", "19,200.00", "19,520.00", "CSQU3054383"),
            Line("Roasted coffee beans, not decaffeinated", "0901.21", 80, "350.00", "4,800.00", "4,960.00", "CSQU3054383"),
        ],
    )


def _sum(values: list[str]) -> str:
    from decimal import Decimal
    return f"{sum(Decimal(v.replace(',', '')) for v in values):,.2f}"


def invoice(s: Shipment):
    total = _sum([ln.total for ln in s.lines])
    text = ["COMMERCIAL INVOICE", f"Invoice No: {s.invoice_no}", "Date: 2026-10-12",
            f"Seller: {s.seller}, Country: {s.seller_country}", f"Buyer: {s.buyer}, Country: {s.buyer_country}",
            "Incoterm: FOB Santos", "Line | Description | HS Code | Qty | Unit Price | Amount"]
    lines = []
    for i, ln in enumerate(s.lines, start=1):
        row = f"{i} | {ln.desc} | HS {ln.hs} | {ln.qty} BAG | USD {ln.unit_price} | USD {ln.total} | Origin {ln.origin}"
        text.append(row)
        lines.append({
            "line_no": i, "description": F(ln.desc, ln.desc), "hs_code": F(ln.hs.replace(".", ""), f"HS {ln.hs}"),
            "quantity": F(str(ln.qty), f"{ln.qty} BAG"), "unit_of_measure": F("BAG", f"{ln.qty} BAG"),
            "unit_price": F(_money(ln.unit_price), f"USD {ln.unit_price}"),
            "line_total": F(_money(ln.total), f"USD {ln.total}"),
            "country_of_origin": F(ln.origin, f"Origin {ln.origin}"),
        })
    text.append(f"TOTAL VALUE: USD {total}")
    resp = {
        "document_number": F(s.invoice_no, f"Invoice No: {s.invoice_no}"),
        "issue_date": F("2026-10-12", "Date: 2026-10-12"),
        "seller": {"name": F(s.seller, s.seller), "address": NA(), "country": F(s.seller_country, f"Country: {s.seller_country}")},
        "buyer": {"name": F(s.buyer, s.buyer), "address": NA(), "country": F(s.buyer_country, f"Country: {s.buyer_country}")},
        "incoterm": F("FOB", "Incoterm: FOB Santos"),
        "lines": lines,
        "invoice_total": F(_money(total), f"TOTAL VALUE: USD {total}"),
    }
    return make_pdf(text), resp


def packing_list(s: Shipment):
    text = ["PACKING LIST", f"Packing List No: PL-{s.invoice_no[-4:]}", "Date: 2026-10-12",
            "Line | Description | Qty | No. of Packages | Net Weight | Gross Weight | Container"]
    lines = []
    for i, ln in enumerate(s.lines, start=1):
        text.append(f"{i} | {ln.desc} | {ln.qty} | {ln.qty} BAGS | Net {ln.net} KG | Gross {ln.gross} KG | {ln.container}")
        lines.append({
            "line_no": i, "description": F(ln.desc, ln.desc), "quantity": F(str(ln.qty), f"{ln.desc} | {ln.qty}"),
            "package_count": F(ln.qty, f"{ln.qty} BAGS"), "package_type": F("BAG", f"{ln.qty} BAGS"),
            "net_weight": F(_kg(ln.net), f"Net {ln.net} KG"), "gross_weight": F(_kg(ln.gross), f"Gross {ln.gross} KG"),
            "container_number": F(ln.container, ln.container),
        })
    pkgs = sum(ln.qty for ln in s.lines)
    gross = _sum([ln.gross for ln in s.lines])
    text += [f"TOTAL PACKAGES: {pkgs} BAGS", f"TOTAL GROSS WEIGHT: {gross} KG"]
    resp = {
        "document_number": F(f"PL-{s.invoice_no[-4:]}", f"Packing List No: PL-{s.invoice_no[-4:]}"),
        "issue_date": F("2026-10-12", "Date: 2026-10-12"),
        "lines": lines,
        "total_packages": F(pkgs, f"TOTAL PACKAGES: {pkgs} BAGS"),
        "total_gross_weight": F(_kg(gross), f"TOTAL GROSS WEIGHT: {gross} KG"),
    }
    return make_pdf(text), resp


def bill_of_lading(s: Shipment, container: str | None = None):
    container = container or s.lines[0].container
    pkgs = sum(ln.qty for ln in s.lines)
    gross = s.bl_gross_override or _sum([ln.gross for ln in s.lines])
    text = ["BILL OF LADING", f"B/L No: {s.bl_no}", "Carrier: Oceanic Lines S.A.",
            f"Shipper: {s.seller}", f"Consignee: {s.buyer}", f"Notify Party: {s.buyer}",
            f"Vessel: {s.vessel} Voyage: {s.voyage}", f"Port of Loading: {s.pol}", f"Port of Discharge: {s.pod}",
            f"Container: {container} Seal: {s.seal} Packages: {pkgs} Gross Weight: {gross} KG",
            f"Description of Goods: {pkgs} BAGS COFFEE"]
    resp = {
        "document_number": F(s.bl_no, f"B/L No: {s.bl_no}"), "issue_date": NA(),
        "carrier": {"name": F("Oceanic Lines S.A.", "Carrier: Oceanic Lines S.A."), "address": NA(), "country": NA()},
        "shipper": {"name": F(s.seller, f"Shipper: {s.seller}"), "address": NA(), "country": NA()},
        "consignee": {"name": F(s.buyer, f"Consignee: {s.buyer}"), "address": NA(), "country": NA()},
        "notify_party": {"name": F(s.buyer, f"Notify Party: {s.buyer}"), "address": NA(), "country": NA()},
        "vessel_name": F(s.vessel, f"Vessel: {s.vessel}"), "voyage_number": F(s.voyage, f"Voyage: {s.voyage}"),
        "port_of_loading": F(s.pol, f"Port of Loading: {s.pol}"),
        "port_of_discharge": F(s.pod, f"Port of Discharge: {s.pod}"),
        "containers": [{
            "container_number": F(container, f"Container: {container}"), "seal_number": F(s.seal, f"Seal: {s.seal}"),
            "package_count": F(pkgs, f"Packages: {pkgs}"), "gross_weight": F(_kg(gross), f"Gross Weight: {gross} KG"),
        }],
        "cargo_description": F(f"{pkgs} BAGS COFFEE", f"Description of Goods: {pkgs} BAGS COFFEE"),
    }
    return make_pdf(text), resp


def certificate_of_origin(s: Shipment):
    hs = sorted({ln.hs for ln in s.lines})
    text = ["CERTIFICATE OF ORIGIN", "Certificate No: CO-55120", f"Exporter: {s.seller}", f"Consignee: {s.buyer}",
            f"Country of Origin: {s.seller_country}", "Issued by: Camara de Comercio de Santos",
            "Goods: Coffee", "HS Codes: " + ", ".join(hs), "We hereby certify that the goods originate in the country shown."]
    resp = {
        "document_number": F("CO-55120", "Certificate No: CO-55120"), "issue_date": NA(),
        "exporter": {"name": F(s.seller, f"Exporter: {s.seller}"), "address": NA(), "country": NA()},
        "consignee": {"name": F(s.buyer, f"Consignee: {s.buyer}"), "address": NA(), "country": NA()},
        "origin_country": F(s.seller_country, f"Country of Origin: {s.seller_country}"),
        "issuing_authority": F("Camara de Comercio de Santos", "Issued by: Camara de Comercio de Santos"),
        "goods_description": F("Coffee", "Goods: Coffee"),
        "hs_codes": [F(h.replace(".", ""), h) for h in hs],
    }
    return make_pdf(text), resp
