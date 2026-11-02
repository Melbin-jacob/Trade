"""Canonical schemas for the trade documents the Sentinel reconciles.

These are the JSON schemas the LLM extraction stage is constrained to (via
``model_json_schema()``). The LLM fills them; it never decides whether they agree.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

from sentinel.domain.fields import ExtractedField, Money, Weight, iter_review_flags
from sentinel.domain.identifiers import ContainerNumber, CountryCode, HSCode

F = ExtractedField  # brevity


class DocumentType(StrEnum):
    COMMERCIAL_INVOICE = "commercial_invoice"
    BILL_OF_LADING = "bill_of_lading"
    PACKING_LIST = "packing_list"
    CERTIFICATE_OF_ORIGIN = "certificate_of_origin"
    PHYTOSANITARY_CERTIFICATE = "phytosanitary_certificate"


class Party(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: F[str]
    address: F[str] | None = None
    country: F[CountryCode] | None = None


class _DocBase(BaseModel):
    model_config = ConfigDict(frozen=True)

    document_number: F[str]
    issue_date: F[date] | None = None

    def review_flags(self) -> list[str]:
        return [path for path, _ in iter_review_flags(self)]


# --------------------------------------------------------------------------- #
# Commercial invoice
# --------------------------------------------------------------------------- #


class InvoiceLine(BaseModel):
    model_config = ConfigDict(frozen=True)

    line_no: int = Field(ge=1)
    description: F[str]
    hs_code: F[HSCode] | None = None
    quantity: F[Decimal]
    unit_of_measure: F[str]
    unit_price: F[Money]
    line_total: F[Money]
    country_of_origin: F[CountryCode] | None = None


class CommercialInvoice(_DocBase):
    doc_type: Literal[DocumentType.COMMERCIAL_INVOICE] = DocumentType.COMMERCIAL_INVOICE
    seller: Party
    buyer: Party
    incoterm: F[str] | None = None
    lines: list[InvoiceLine]
    invoice_total: F[Money]


# --------------------------------------------------------------------------- #
# Packing list
# --------------------------------------------------------------------------- #


class PackingLine(BaseModel):
    model_config = ConfigDict(frozen=True)

    line_no: int = Field(ge=1)
    description: F[str]
    quantity: F[Decimal]
    package_count: F[int]
    package_type: F[str] | None = None
    net_weight: F[Weight]
    gross_weight: F[Weight]
    container_number: F[ContainerNumber] | None = None


class PackingList(_DocBase):
    doc_type: Literal[DocumentType.PACKING_LIST] = DocumentType.PACKING_LIST
    lines: list[PackingLine]
    total_packages: F[int]
    total_gross_weight: F[Weight]


# --------------------------------------------------------------------------- #
# Bill of lading
# --------------------------------------------------------------------------- #


class BLContainer(BaseModel):
    model_config = ConfigDict(frozen=True)

    container_number: F[ContainerNumber]
    seal_number: F[str] | None = None
    package_count: F[int]
    gross_weight: F[Weight]


class BillOfLading(_DocBase):
    doc_type: Literal[DocumentType.BILL_OF_LADING] = DocumentType.BILL_OF_LADING
    carrier: Party
    shipper: Party
    consignee: Party
    notify_party: Party | None = None
    vessel_name: F[str] | None = None
    voyage_number: F[str] | None = None
    port_of_loading: F[str]  # UN/LOCODE
    port_of_discharge: F[str]
    containers: list[BLContainer]
    cargo_description: F[str]


# --------------------------------------------------------------------------- #
# Certificates
# --------------------------------------------------------------------------- #


class CertificateOfOrigin(_DocBase):
    doc_type: Literal[DocumentType.CERTIFICATE_OF_ORIGIN] = DocumentType.CERTIFICATE_OF_ORIGIN
    exporter: Party
    consignee: Party
    origin_country: F[CountryCode]
    issuing_authority: F[str]
    goods_description: F[str]
    hs_codes: list[F[HSCode]] = []


class PhytosanitaryCertificate(_DocBase):
    doc_type: Literal[DocumentType.PHYTOSANITARY_CERTIFICATE] = DocumentType.PHYTOSANITARY_CERTIFICATE
    exporter: Party
    consignee: Party
    place_of_origin: F[str]
    botanical_name: F[str]
    treatment: F[str] | None = None
    issuing_nppo: F[str]  # National Plant Protection Organization


TradeDocument = Annotated[
    Union[CommercialInvoice, PackingList, BillOfLading, CertificateOfOrigin, PhytosanitaryCertificate],
    Field(discriminator="doc_type"),
]
