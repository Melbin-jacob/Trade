"""Regulatory rule packs plugged into the rule engine: import requirements and tariff checks."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.documents import BillOfLading, CommercialInvoice, DocumentType as DT
from sentinel.kernel.service import Severity
from sentinel.ledger.audit import AuditLog
from sentinel.regulatory.tariff import TariffProvider
from sentinel.rules.engine import Context, Rule, TraceNode, _v


@dataclass(frozen=True)
class ImportRule:
    rule_id: str
    destinations: frozenset[str]
    hs_prefixes: tuple[str, ...]
    requires: tuple[DT, ...] = ()
    prohibited: bool = False
    note: str = ""


#: Illustrative pack - real packs are maintained by the compliance team per lane.
DEFAULT_IMPORT_RULES: tuple[ImportRule, ...] = (
    ImportRule("PHYTO_REQUIRED", frozenset({"CA", "US", "GB", "AU"}),
               ("06", "07", "08", "10", "12", "1404"), (DT.PHYTOSANITARY_CERTIFICATE,),
               note="Live plants, fresh produce, cereals and seeds need a phytosanitary certificate"),
    ImportRule("COO_REQUIRED_FOOD", frozenset({"CA", "US"}), ("09", "16", "17", "18", "20", "21"),
               (DT.CERTIFICATE_OF_ORIGIN,), note="Origin declaration required for food products"),
    ImportRule("ROUGH_DIAMONDS_KPCS", frozenset({"CA", "US", "GB"}), ("710210", "710221", "710231"), prohibited=True,
               note="Rough diamonds require Kimberley Process certification - manual handling only"),
)


def destination_country(ctx: Context) -> str | None:
    bl: BillOfLading | None = ctx.doc(DT.BILL_OF_LADING)
    pod = _v(bl.port_of_discharge) if bl else None
    return pod[:2].upper() if pod and len(pod) >= 2 else None


def _hs_codes(ctx: Context) -> list[tuple[int, str]]:
    inv: CommercialInvoice | None = ctx.doc(DT.COMMERCIAL_INVOICE)
    return [] if inv is None else [(i, _v(ln.hs_code)) for i, ln in enumerate(inv.lines) if _v(ln.hs_code)]


def import_rules_pack(rules: tuple[ImportRule, ...] = DEFAULT_IMPORT_RULES) -> Rule:
    def import_requirements(ctx: Context) -> list[TraceNode]:
        dest = destination_country(ctx)
        if dest is None:
            return [TraceNode("IMPORT_RULES", "destination import requirements", "skip", detail="destination unknown")]
        nodes = []
        for r in rules:
            if dest not in r.destinations:
                continue
            hits = [(i, hs) for i, hs in _hs_codes(ctx) if hs.startswith(r.hs_prefixes)]
            if not hits:
                continue
            ev = [ctx.ev(DT.COMMERCIAL_INVOICE, f"lines[{i}].hs_code", hs) for i, hs in hits]
            codes = ", ".join(hs for _, hs in hits)
            if r.prohibited:
                nodes.append(ctx.check(r.rule_id, f"{dest}: {r.note}", False, location=dest, kind="regulatory",
                                       severity=Severity.CRITICAL, message=f"{r.note} (HS {codes}, destination {dest})",
                                       evidence=ev, inputs={"destination": dest, "hs_codes": codes}))
            for doc in r.requires:
                nodes.append(ctx.check(
                    r.rule_id, f"{dest}: {doc.value} present for HS {codes}", doc in ctx.docs, location=f"{dest}:{doc.value}",
                    kind="missing_document", severity=Severity.CRITICAL,
                    message=f"{r.note}: {doc.value.replace('_', ' ')} missing for HS {codes} into {dest}",
                    evidence=ev, inputs={"destination": dest, "hs_codes": codes},
                ))
        return nodes

    return import_requirements


def tariff_pack(provider: TariffProvider, audit: AuditLog, tenant_id: str, actor: dict[str, str]) -> Rule:
    def tariff_classification(ctx: Context) -> list[TraceNode]:
        dest = destination_country(ctx)
        if dest is None:
            return []
        nodes = []
        for i, hs in _hs_codes(ctx):
            try:
                line = provider.lookup(hs, dest)
                outcome = "found" if line else "not_found"
            except Exception as exc:  # includes CircuitOpen - fail closed with a waivable issue
                audit.external_call(tenant_id=tenant_id, actor=actor, system="tariff", operation="lookup",
                                    request={"hs": hs, "country": dest}, outcome=f"error:{type(exc).__name__}",
                                    correlation_id=f"{tenant_id}-{hs}-{dest}-{id(ctx)}")
                nodes.append(ctx.check(
                    "TARIFF_UNAVAILABLE", f"HS {hs} verified against {dest} tariff", False, location=f"{dest}:{hs}",
                    kind="regulatory", message=f"Tariff service unavailable - HS {hs} could not be verified for {dest}",
                    inputs={"hs_code": hs, "destination": dest, "error": type(exc).__name__}))
                continue
            audit.external_call(tenant_id=tenant_id, actor=actor, system="tariff", operation="lookup",
                                request={"hs": hs, "country": dest}, response=line.__dict__ if line else None,
                                outcome=outcome, correlation_id=f"{tenant_id}-{hs}-{dest}-{id(ctx)}")
            nodes.append(ctx.check(
                "TARIFF_HS_VALID", f"HS {hs} exists in {dest} tariff", line is not None, location=f"{dest}:{hs}",
                kind="regulatory", severity=Severity.CRITICAL,
                message=f"HS {hs} is not a valid tariff line in the {dest} customs tariff",
                evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, f"lines[{i}].hs_code", hs)],
                inputs={"hs_code": hs, "destination": dest,
                        "tariff_description": line.description if line else "-",
                        "mfn_rate": line.mfn_rate if line else "-"},
            ))
        return nodes

    return tariff_classification
