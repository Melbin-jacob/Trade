"""Composition root: wires every component with its own least-privilege principal.

``build_platform`` is used by the API, the worker process, the demo and tests.
Adapters (Postgres vs in-memory ledger, Claude vs scripted LLM, SMTP vs
recording sender) are chosen here and nowhere else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from sentinel.agents.claude import JsonLlm
from sentinel.agents.remediation import RemediationDrafter
from sentinel.crypto.envelope import KeyManagementService
from sentinel.dispatch.outbox import CustomsGateway, Dispatcher, EmailSender
from sentinel.extraction.ocr import HybridOcr, OcrEngine
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.ingestion.gateway import IngestionGateway
from sentinel.ingestion.scanner import MalwareScanner
from sentinel.kernel.service import ShipmentService
from sentinel.ledger.audit import AuditLog
from sentinel.ledger.chain import Ledger, LedgerStore
from sentinel.ledger.signing import KeyRing, Signer
from sentinel.orchestration.orchestrator import Orchestrator
from sentinel.regulatory.rulepacks import import_rules_pack, tariff_pack
from sentinel.regulatory.screening import SanctionsProvider, ScreeningService
from sentinel.regulatory.tariff import TariffProvider
from sentinel.rules.engine import RuleEngine
from sentinel.rules.runner import ValidationRunner
from sentinel.rules.semantic import HybridMatcher
from sentinel.security.principals import Principal, PrincipalKind, Role
from sentinel.storage.blobs import BlobStore, EncryptedBlobStore
from sentinel.tenancy import TenantDirectory


def worker_principals(tenant_id: str) -> dict[str, Principal]:
    S, A = PrincipalKind.SERVICE, PrincipalKind.AGENT

    def p(pid, kind, role):
        return Principal(id=pid, kind=kind, tenant_id=tenant_id, roles=frozenset({role}))

    return {
        "ingest": p("svc-ingestion", S, Role.INGESTION_SERVICE),
        "extract": p("svc-extraction", S, Role.EXTRACTION_SERVICE),
        "rules": p("svc-rule-engine", S, Role.RULE_ENGINE),
        "screen": p("svc-screening", S, Role.SCREENING_SERVICE),
        "analyzer": p("agent-analyzer", A, Role.ANALYZER_AGENT),
        "drafter": p("agent-remediation-drafter", A, Role.REMEDIATION_AGENT),
        "dispatch": p("svc-dispatcher", S, Role.DISPATCHER),
    }


@dataclass
class TenantRuntime:
    principals: dict[str, Principal]
    gateway: IngestionGateway
    orchestrator: Orchestrator


@dataclass
class Platform:
    tenants: TenantDirectory
    store: LedgerStore
    ledger: Ledger
    keyring: KeyRing
    service: ShipmentService
    audit: AuditLog
    blobs: EncryptedBlobStore
    email: EmailSender
    customs: CustomsGateway
    _factory: Callable[[str], TenantRuntime]
    _runtimes: dict[str, TenantRuntime] = field(default_factory=dict)

    def runtime(self, tenant_id: str) -> TenantRuntime:
        if tenant_id not in self._runtimes:
            self.tenants.get(tenant_id)  # raises for unknown tenants
            self._runtimes[tenant_id] = self._factory(tenant_id)
        return self._runtimes[tenant_id]


def build_platform(*, tenants: TenantDirectory, store: LedgerStore, signer: Signer, keyring: KeyRing,
                   raw_blobs: BlobStore, kms: KeyManagementService,
                   llm_factory: Callable[[AuditLog], JsonLlm],
                   scanner: MalwareScanner, sanctions: SanctionsProvider, tariff: TariffProvider,
                   email: EmailSender, customs: CustomsGateway, ocr: OcrEngine | None = None,
                   company_name: str = "Acme Trading Inc.") -> Platform:
    ledger = Ledger(store, signer)
    service = ShipmentService(ledger)
    audit = AuditLog(ledger)
    llm = llm_factory(audit)  # every LLM call is written to the same signed ledger
    blobs = EncryptedBlobStore(raw_blobs, kms, tenants)
    engine = RuleEngine()
    ocr = ocr or HybridOcr()

    def factory(tenant_id: str) -> TenantRuntime:
        pr = worker_principals(tenant_id)
        gateway = IngestionGateway(principal=pr["ingest"], service=service, blobs=blobs, scanner=scanner, audit=audit)
        extraction = ExtractionPipeline(principal=pr["extract"], service=service, blobs=blobs, ocr=ocr, llm=llm)
        validation = ValidationRunner(
            principal=pr["rules"], service=service, blobs=blobs, engine=engine,
            matcher_factory=lambda t: HybridMatcher(llm, t, pr["analyzer"].audit_ref()),
            rules_factory=lambda t: [import_rules_pack(), tariff_pack(tariff, audit, t, pr["rules"].audit_ref())],
        )
        screening = ScreeningService(principal=pr["screen"], service=service, blobs=blobs, provider=sanctions, audit=audit)
        drafter = RemediationDrafter(principal=pr["drafter"], service=service, tenants=tenants, llm=llm,
                                     company_name=company_name)
        dispatcher = Dispatcher(principal=pr["dispatch"], store=store, audit=audit, tenants=tenants, blobs=blobs,
                                email=email, customs=customs)
        orchestrator = Orchestrator(store=store, audit=audit, extraction=extraction, validation=validation,
                                    screening=screening, drafter=drafter, dispatcher=dispatcher)
        return TenantRuntime(pr, gateway, orchestrator)

    return Platform(tenants, store, ledger, keyring, service, audit, blobs, email, customs, factory)
