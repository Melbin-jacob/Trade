from __future__ import annotations
import os

os.environ.setdefault("SENTINEL_AUTOLOAD", "0")  # never build the production app on import in tests

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from itertools import count

import pytest

from sentinel.domain.documents import (
    BillOfLading,
    BLContainer,
    CommercialInvoice,
    InvoiceLine,
    PackingLine,
    PackingList,
    Party,
)
from sentinel.domain.fields import ExtractedField, Extractor, Money, Weight, WeightUnit
from sentinel.kernel.service import ShipmentService
from sentinel.ledger.chain import InMemoryLedgerStore, Ledger
from sentinel.ledger.signing import Ed25519Signer, KeyRing
from sentinel.security.principals import Principal, PrincipalKind, Role

TENANT = "acme_trading"


def f(value, confidence="99.50"):
    return ExtractedField(value=value, confidence=Decimal(confidence), extractor=Extractor.ENSEMBLE)


@pytest.fixture
def clock():
    t0 = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)
    ticks = count()
    return lambda: t0 + timedelta(seconds=next(ticks))


@pytest.fixture
def signer():
    return Ed25519Signer("ledger-key-2026-11")


@pytest.fixture
def keyring(signer):
    ring = KeyRing()
    ring.add(signer.key_id, signer.public_key())
    return ring


@pytest.fixture
def store():
    return InMemoryLedgerStore()


@pytest.fixture
def ledger(store, signer, clock):
    return Ledger(store, signer, clock)


@pytest.fixture
def service(ledger):
    return ShipmentService(ledger)


def principal(pid, kind, *roles, tenant=TENANT):
    return Principal(id=pid, kind=kind, tenant_id=tenant, roles=frozenset(roles))


@pytest.fixture
def actors():
    H, A, S = PrincipalKind.HUMAN, PrincipalKind.AGENT, PrincipalKind.SERVICE
    return {
        "ingest": principal("svc-ingest", S, Role.INGESTION_SERVICE),
        "extract": principal("svc-extract", S, Role.EXTRACTION_SERVICE),
        "rules": principal("svc-rules", S, Role.RULE_ENGINE),
        "screen": principal("svc-screen", S, Role.SCREENING_SERVICE),
        "analyzer": principal("agent-analyzer", A, Role.ANALYZER_AGENT),
        "drafter": principal("agent-drafter", A, Role.REMEDIATION_AGENT),
        "reviewer": principal("alex.lee", H, Role.REVIEWER),
        "officer1": principal("emma.davis", H, Role.COMPLIANCE_OFFICER),
        "officer2": principal("jane.doe", H, Role.COMPLIANCE_OFFICER),
        "filer": principal("filer.one", H, Role.CUSTOMS_FILER),
        "other_tenant": principal("mallory", H, Role.COMPLIANCE_OFFICER, tenant="globex_freight"),
    }


# --------------------------------------------------------------------------- #
# Sample extracted documents
# --------------------------------------------------------------------------- #

PARTY = Party(name=f("Tech Solutions Ltd"))
CONTAINER = "CSQU3054383"  # valid ISO 6346


def invoice(confidence="99.50"):
    usd = lambda a: Money(amount=Decimal(a), currency="USD")
    return CommercialInvoice(
        document_number=f("INV-2026-0042"),
        seller=PARTY,
        buyer=PARTY,
        lines=[
            InvoiceLine(
                line_no=1,
                description=f("Roasted coffee beans, not decaffeinated"),
                hs_code=f("090121"),
                quantity=f(Decimal("400")),
                unit_of_measure=f("BAG"),
                unit_price=f(usd("125.00")),
                line_total=f(usd("50000.00"), confidence),
            )
        ],
        invoice_total=f(usd("50000.00")),
    )


def packing_list():
    kg = lambda a: Weight(amount=Decimal(a), unit=WeightUnit.KG)
    return PackingList(
        document_number=f("PL-0042"),
        lines=[
            PackingLine(
                line_no=1,
                description=f("Roasted coffee beans"),
                quantity=f(Decimal("400")),
                package_count=f(400),
                net_weight=f(kg("24000")),
                gross_weight=f(kg("24480")),
                container_number=f(CONTAINER),
            )
        ],
        total_packages=f(400),
        total_gross_weight=f(kg("24480")),
    )


def bill_of_lading():
    return BillOfLading(
        document_number=f("MEDU1234567"),
        carrier=PARTY,
        shipper=PARTY,
        consignee=PARTY,
        port_of_loading=f("BRSSZ"),
        port_of_discharge=f("CAMTR"),
        containers=[
            BLContainer(
                container_number=f(CONTAINER),
                package_count=f(400),
                gross_weight=f(Weight(amount=Decimal("24480"), unit=WeightUnit.KG)),
            )
        ],
        cargo_description=f("400 bags roasted coffee"),
    )


# --------------------------------------------------------------------------- #
# Platform fixtures (tenancy, encryption, audit)
# --------------------------------------------------------------------------- #

from sentinel.crypto.envelope import LocalKms  # noqa: E402
from sentinel.ledger.audit import AuditLog  # noqa: E402
from sentinel.storage.blobs import EncryptedBlobStore, InMemoryBlobStore  # noqa: E402
from sentinel.tenancy import Counterparty, TenantConfig, TenantDirectory  # noqa: E402

SUPPLIER = Counterparty("Tech Solutions Ltd", "supplier", "docs@techsol.example", frozenset({"techsol.example"}))
CARRIER = Counterparty("Oceanic Lines", "shipping_line", "bl-desk@oceanic.example", frozenset({"oceanic.example"}))


@pytest.fixture
def tenants():
    return TenantDirectory([
        TenantConfig(
            tenant_id=TENANT, kms_key_ref="kms://acme", data_region="ca-central-1",
            counterparties=(SUPPLIER, CARRIER),
            webhook_secrets={"port-montreal": b"s3cret-shared-key-0123456789abcdef"},
            inbound_email_domains=frozenset({"techsol.example", "oceanic.example"}),
        ),
        TenantConfig(tenant_id="globex_freight", kms_key_ref="kms://globex", data_region="eu-west-1"),
    ])


@pytest.fixture
def kms():
    k = LocalKms()
    k.create_key("kms://acme")
    k.create_key("kms://globex")
    return k


@pytest.fixture
def raw_blobs():
    return InMemoryBlobStore()


@pytest.fixture
def blobs(raw_blobs, kms, tenants):
    return EncryptedBlobStore(raw_blobs, kms, tenants)


@pytest.fixture
def audit(ledger):
    return AuditLog(ledger)
