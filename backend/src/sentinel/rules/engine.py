"""Deterministic cross-document rule engine (the Thick Kernel's validator).

All arithmetic is ``Decimal``; every check emits a trace node (inputs, outcome)
which the dashboard renders as the decision tree behind each flag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable, Iterable

from pydantic import BaseModel

from sentinel.domain.documents import (
    BillOfLading,
    CertificateOfOrigin,
    CommercialInvoice,
    DocumentType as DT,
    PackingList,
)
from sentinel.domain.fields import ExtractedField, Money, Weight
from sentinel.kernel.service import EvidenceRef, Issue, Severity
from sentinel.kernel.shipment import REQUIRED_DOCUMENTS
from sentinel.rules.semantic import DescriptionMatcher, TokenMatcher, party_similarity

RULESET_VERSION = "trade-rules-2026.11.1"


@dataclass(frozen=True)
class RuleConfig:
    gross_weight_tolerance_pct: Decimal = Decimal("0.5")
    gross_weight_critical_pct: Decimal = Decimal("2.0")
    weight_sum_tolerance_kg: Decimal = Decimal("1")
    money_tolerance: Decimal = Decimal("0.01")
    description_match_threshold: float = 0.75
    party_match_threshold: float = 0.6


@dataclass
class DocRef:
    doc_type: DT
    content_sha256: str
    doc: BaseModel


@dataclass
class TraceNode:
    rule_id: str
    check: str
    outcome: str  # pass | fail | skip
    inputs: dict[str, str] = field(default_factory=dict)
    detail: str = ""
    issue_id: str | None = None
    children: list["TraceNode"] = field(default_factory=list)


@dataclass
class ValidationReport:
    ruleset_version: str
    issues: list[Issue]
    trace: list[TraceNode]


def _v(f: ExtractedField | None) -> Any:
    return None if f is None else f.value


def _kg(f: ExtractedField[Weight] | None) -> Decimal | None:
    w = _v(f)
    return None if w is None else w.to_kg()


def _fmt(d: Decimal | None, unit: str = "") -> str:
    return "n/a" if d is None else f"{d:,.2f}{(' ' + unit) if unit else ''}"


def _issue_id(rule_id: str, location: str) -> str:
    return re.sub(r"[^a-z0-9_:.\[\]\-]", "_", f"{rule_id}:{location}".lower())[:200]


class Context:
    def __init__(self, docs: dict[DT, DocRef], config: RuleConfig, matcher: DescriptionMatcher) -> None:
        self.docs, self.config, self.matcher = docs, config, matcher
        self.issues: dict[str, Issue] = {}

    def doc(self, dt: DT):
        ref = self.docs.get(dt)
        return None if ref is None else ref.doc

    def ev(self, dt: DT, path: str, value: Any) -> EvidenceRef:
        return EvidenceRef(doc_type=dt, content_sha256=self.docs[dt].content_sha256, field_path=path,
                           value=None if value is None else str(value))

    def check(self, rule_id: str, check: str, ok: bool | None, *, location: str, kind: str = "discrepancy",
              severity: Severity = Severity.WARNING, message: str = "", evidence: Iterable[EvidenceRef] = (),
              inputs: dict[str, str] | None = None) -> TraceNode:
        if ok is None:
            return TraceNode(rule_id, check, "skip", inputs or {}, "inputs missing or unreadable")
        if ok:
            return TraceNode(rule_id, check, "pass", inputs or {})
        iid = _issue_id(rule_id, location)
        self.issues[iid] = Issue(id=iid, kind=kind, severity=severity, rule_id=rule_id,  # type: ignore[arg-type]
                                 message=message, evidence=list(evidence))
        return TraceNode(rule_id, check, "fail", inputs or {}, message, iid)


Rule = Callable[[Context], list[TraceNode]]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


# --------------------------------------------------------------------------- #
# Document completeness and field formats
# --------------------------------------------------------------------------- #


@rule
def required_documents(ctx: Context) -> list[TraceNode]:
    return [
        ctx.check("DOC_REQUIRED", f"{dt.value} present", dt in ctx.docs, location=dt.value,
                  kind="missing_document", message=f"Required document missing: {dt.value.replace('_', ' ')}")
        for dt in sorted(REQUIRED_DOCUMENTS)
    ]


def _walk(obj: Any, path: str = ""):
    if isinstance(obj, ExtractedField):
        yield path, obj
    elif isinstance(obj, BaseModel):
        for name in type(obj).model_fields:
            yield from _walk(getattr(obj, name), f"{path}.{name}" if path else name)
    elif isinstance(obj, list):
        for i, x in enumerate(obj):
            yield from _walk(x, f"{path}[{i}]")


@rule
def field_formats(ctx: Context) -> list[TraceNode]:
    nodes = []
    for dt, ref in ctx.docs.items():
        for path, f in _walk(ref.doc):
            if f.value is not None or not f.raw_text:
                continue
            what = path.rsplit(".", 1)[-1]
            hint = {"container_number": "fails the ISO 6346 check digit - likely transposed or mistyped digits",
                    "hs_code": "is not a valid HS code"}.get(what, "could not be read as a valid value")
            nodes.append(ctx.check(
                "FIELD_FORMAT", f"{dt.value} {path} well-formed", False, location=f"{dt.value}:{path}",
                kind="format", message=f"{dt.value.replace('_', ' ').title()} {path}: '{f.raw_text}' {hint}",
                evidence=[ctx.ev(dt, path, f.raw_text)], inputs={"raw_text": f.raw_text},
            ))
    return nodes


# --------------------------------------------------------------------------- #
# Invoice arithmetic
# --------------------------------------------------------------------------- #


@rule
def invoice_arithmetic(ctx: Context) -> list[TraceNode]:
    inv: CommercialInvoice | None = ctx.doc(DT.COMMERCIAL_INVOICE)
    if inv is None:
        return []
    tol, nodes, totals, currencies = ctx.config.money_tolerance, [], [], set()
    for i, ln in enumerate(inv.lines):
        qty, price, total = _v(ln.quantity), _v(ln.unit_price), _v(ln.line_total)
        if price and total:
            currencies |= {price.currency, total.currency}
        if total:
            totals.append(total)
        ok = None if None in (qty, price, total) else (
            price.currency == total.currency and abs(qty * price.amount - total.amount) <= tol)
        nodes.append(ctx.check(
            "INV_LINE_ARITHMETIC", f"invoice line {ln.line_no}: qty x unit price = amount", ok,
            location=f"line{ln.line_no}", severity=Severity.CRITICAL,
            message=f"Invoice line {ln.line_no}: {qty} x {price.amount if price else '?'} = "
                    f"{(qty * price.amount) if ok is not None else '?'} but amount shows {total.amount if total else '?'}",
            evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, f"lines[{i}].line_total", total.amount if total else None)],
            inputs={"quantity": str(qty), "unit_price": str(price.amount if price else None),
                    "line_total": str(total.amount if total else None)},
        ))
    grand: Money | None = _v(inv.invoice_total)
    if grand:
        currencies.add(grand.currency)
    nodes.append(ctx.check("INV_CURRENCY", "single invoice currency", len(currencies) <= 1, location="invoice",
                           severity=Severity.CRITICAL, message=f"Invoice mixes currencies: {sorted(currencies)}",
                           inputs={"currencies": ",".join(sorted(currencies))}))
    complete = grand is not None and len(totals) == len(inv.lines) and len(currencies) <= 1
    s = sum((t.amount for t in totals), Decimal(0))
    nodes.append(ctx.check(
        "INV_TOTAL", "sum of line amounts = invoice total",
        None if not complete else abs(s - grand.amount) <= tol, location="invoice_total",
        severity=Severity.CRITICAL,
        message=f"Invoice lines sum to {_fmt(s)} but invoice total is {_fmt(grand.amount if grand else None)}",
        evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, "invoice_total", grand.amount if grand else None)],
        inputs={"sum_of_lines": _fmt(s), "invoice_total": _fmt(grand.amount if grand else None)},
    ))
    return nodes


# --------------------------------------------------------------------------- #
# Packing list internal consistency
# --------------------------------------------------------------------------- #


@rule
def packing_list_totals(ctx: Context) -> list[TraceNode]:
    pl: PackingList | None = ctx.doc(DT.PACKING_LIST)
    if pl is None:
        return []
    nodes = []
    counts = [_v(ln.package_count) for ln in pl.lines]
    total = _v(pl.total_packages)
    nodes.append(ctx.check(
        "PL_PACKAGE_TOTAL", "sum of line packages = total packages",
        None if None in counts or total is None else sum(counts) == total, location="total_packages",
        message=f"Packing list lines add up to {sum(c or 0 for c in counts)} packages but total shows {total}",
        evidence=[ctx.ev(DT.PACKING_LIST, "total_packages", total)],
        inputs={"sum_of_lines": str(sum(c or 0 for c in counts)), "total_packages": str(total)},
    ))
    grosses = [_kg(ln.gross_weight) for ln in pl.lines]
    tg = _kg(pl.total_gross_weight)
    s = sum((g for g in grosses if g is not None), Decimal(0))
    nodes.append(ctx.check(
        "PL_GROSS_TOTAL", "sum of line gross weights = total gross weight",
        None if None in grosses or tg is None else abs(s - tg) <= ctx.config.weight_sum_tolerance_kg,
        location="total_gross_weight",
        message=f"Packing list line gross weights sum to {_fmt(s, 'kg')} but total shows {_fmt(tg, 'kg')}",
        evidence=[ctx.ev(DT.PACKING_LIST, "total_gross_weight", _fmt(tg, "kg"))],
        inputs={"sum_of_lines": _fmt(s, "kg"), "total_gross": _fmt(tg, "kg")},
    ))
    for i, ln in enumerate(pl.lines):
        net, gross = _kg(ln.net_weight), _kg(ln.gross_weight)
        nodes.append(ctx.check(
            "PL_NET_LE_GROSS", f"packing line {ln.line_no}: net <= gross",
            None if net is None or gross is None else net <= gross, location=f"line{ln.line_no}",
            message=f"Packing list line {ln.line_no}: net weight {_fmt(net, 'kg')} exceeds gross {_fmt(gross, 'kg')}",
            evidence=[ctx.ev(DT.PACKING_LIST, f"lines[{i}].net_weight", _fmt(net, "kg")),
                      ctx.ev(DT.PACKING_LIST, f"lines[{i}].gross_weight", _fmt(gross, "kg"))],
            inputs={"net": _fmt(net, "kg"), "gross": _fmt(gross, "kg")},
        ))
    return nodes


# --------------------------------------------------------------------------- #
# Bill of lading vs packing list
# --------------------------------------------------------------------------- #


def _transposition(a: str, b: str) -> bool:
    if len(a) != len(b) or sorted(a) != sorted(b):
        return False
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diff) == 2 and diff[1] == diff[0] + 1


@rule
def bl_vs_packing_list(ctx: Context) -> list[TraceNode]:
    bl: BillOfLading | None = ctx.doc(DT.BILL_OF_LADING)
    pl: PackingList | None = ctx.doc(DT.PACKING_LIST)
    if bl is None or pl is None:
        return []
    nodes = []
    bl_c = {_v(c.container_number) for c in bl.containers} - {None}
    pl_c = {_v(ln.container_number) for ln in pl.lines} - {None}
    if bl_c and pl_c:
        only_bl, only_pl = sorted(bl_c - pl_c), sorted(pl_c - bl_c)
        hint = " (looks like transposed digits)" if any(_transposition(x, y) for x in only_bl for y in only_pl) else ""
        nodes.append(ctx.check(
            "BL_PL_CONTAINERS", "container numbers agree", not only_bl and not only_pl, location="containers",
            severity=Severity.CRITICAL,
            message=f"Container numbers differ{hint}: B/L {only_bl or '-'} vs packing list {only_pl or '-'}",
            evidence=[ctx.ev(DT.BILL_OF_LADING, "containers", ", ".join(sorted(bl_c))),
                      ctx.ev(DT.PACKING_LIST, "lines[*].container_number", ", ".join(sorted(pl_c)))],
            inputs={"bill_of_lading": ", ".join(sorted(bl_c)), "packing_list": ", ".join(sorted(pl_c))},
        ))
    else:
        nodes.append(TraceNode("BL_PL_CONTAINERS", "container numbers agree", "skip", detail="no readable container numbers"))

    bl_g = [_kg(c.gross_weight) for c in bl.containers]
    pl_g = _kg(pl.total_gross_weight)
    if None in bl_g or pl_g is None or not bl_g:
        nodes.append(TraceNode("BL_PL_GROSS", "gross weight agrees within tolerance", "skip", detail="weights unreadable"))
    else:
        bl_total = sum(bl_g, Decimal(0))
        diff = abs(bl_total - pl_g)
        pct = Decimal(0) if pl_g == 0 else (diff / pl_g * 100).quantize(Decimal("0.01"))
        sev = Severity.CRITICAL if pct > ctx.config.gross_weight_critical_pct else Severity.WARNING
        nodes.append(ctx.check(
            "BL_PL_GROSS", f"B/L gross vs packing list gross within {ctx.config.gross_weight_tolerance_pct}%",
            pct <= ctx.config.gross_weight_tolerance_pct, location="gross_weight", severity=sev,
            message=f"Gross weight mismatch: B/L {_fmt(bl_total, 'kg')} vs packing list {_fmt(pl_g, 'kg')} "
                    f"(difference {_fmt(diff, 'kg')}, {pct}%)",
            evidence=[ctx.ev(DT.BILL_OF_LADING, "containers[*].gross_weight", _fmt(bl_total, "kg")),
                      ctx.ev(DT.PACKING_LIST, "total_gross_weight", _fmt(pl_g, "kg"))],
            inputs={"bill_of_lading": _fmt(bl_total, "kg"), "packing_list": _fmt(pl_g, "kg"),
                    "difference_pct": str(pct), "tolerance_pct": str(ctx.config.gross_weight_tolerance_pct)},
        ))
    bl_p = [_v(c.package_count) for c in bl.containers]
    pl_p = _v(pl.total_packages)
    nodes.append(ctx.check(
        "BL_PL_PACKAGES", "package counts agree", None if None in bl_p or pl_p is None else sum(bl_p) == pl_p,
        location="packages", severity=Severity.CRITICAL,
        message=f"Package count mismatch: B/L {sum(p or 0 for p in bl_p)} vs packing list {pl_p}",
        evidence=[ctx.ev(DT.BILL_OF_LADING, "containers[*].package_count", sum(p or 0 for p in bl_p)),
                  ctx.ev(DT.PACKING_LIST, "total_packages", pl_p)],
        inputs={"bill_of_lading": str(sum(p or 0 for p in bl_p)), "packing_list": str(pl_p)},
    ))
    return nodes


# --------------------------------------------------------------------------- #
# Invoice vs packing list (semantic line matching + quantities)
# --------------------------------------------------------------------------- #


@rule
def invoice_vs_packing_list(ctx: Context) -> list[TraceNode]:
    inv: CommercialInvoice | None = ctx.doc(DT.COMMERCIAL_INVOICE)
    pl: PackingList | None = ctx.doc(DT.PACKING_LIST)
    if inv is None or pl is None:
        return []
    nodes, used = [], set()
    for i, il in enumerate(inv.lines):
        desc = _v(il.description) or ""
        best, best_j, best_r = None, None, None
        for j, pln in enumerate(pl.lines):
            if j in used:
                continue
            r = ctx.matcher.match(desc, _v(pln.description) or "")
            if best is None or r.score > best:
                best, best_j, best_r = r.score, j, r
        matched = best is not None and best >= ctx.config.description_match_threshold
        node = ctx.check(
            "INV_PL_LINE_MATCH", f"invoice line {il.line_no} has a packing-list line", matched,
            location=f"line{il.line_no}",
            message=f"Invoice line {il.line_no} '{desc}' has no matching packing-list line",
            evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, f"lines[{i}].description", desc)],
            inputs={"invoice_description": desc,
                    "best_packing_description": _v(pl.lines[best_j].description) if best_j is not None else "-",
                    "score": f"{best or 0:.2f}", "method": best_r.method if best_r else "-",
                    "rationale": best_r.rationale if best_r else "-"},
        )
        if matched:
            used.add(best_j)
            pln = pl.lines[best_j]
            q_inv, q_pl = _v(il.quantity), _v(pln.quantity)
            node.children.append(ctx.check(
                "INV_PL_QUANTITY", f"invoice line {il.line_no} quantity = packing line {pln.line_no}",
                None if q_inv is None or q_pl is None else q_inv == q_pl, location=f"line{il.line_no}",
                severity=Severity.CRITICAL,
                message=f"Quantity mismatch: invoice line {il.line_no} shows {q_inv}, packing list line {pln.line_no} shows {q_pl}",
                evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, f"lines[{i}].quantity", q_inv),
                          ctx.ev(DT.PACKING_LIST, f"lines[{best_j}].quantity", q_pl)],
                inputs={"invoice": str(q_inv), "packing_list": str(q_pl)},
            ))
        nodes.append(node)
    return nodes


# --------------------------------------------------------------------------- #
# Origin and parties
# --------------------------------------------------------------------------- #


@rule
def origin_consistency(ctx: Context) -> list[TraceNode]:
    inv: CommercialInvoice | None = ctx.doc(DT.COMMERCIAL_INVOICE)
    coo: CertificateOfOrigin | None = ctx.doc(DT.CERTIFICATE_OF_ORIGIN)
    if inv is None or coo is None:
        return []
    nodes = []
    origin = _v(coo.origin_country)
    for i, ln in enumerate(inv.lines):
        o = _v(ln.country_of_origin)
        nodes.append(ctx.check(
            "INV_COO_ORIGIN", f"invoice line {ln.line_no} origin matches certificate",
            None if o is None or origin is None else o == origin, location=f"line{ln.line_no}",
            severity=Severity.CRITICAL,
            message=f"Invoice line {ln.line_no} origin {o} contradicts certificate of origin ({origin})",
            evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, f"lines[{i}].country_of_origin", o),
                      ctx.ev(DT.CERTIFICATE_OF_ORIGIN, "origin_country", origin)],
            inputs={"invoice": str(o), "certificate": str(origin)},
        ))
    coo_hs = {h.value[:6] for h in coo.hs_codes if h.value}
    for i, ln in enumerate(inv.lines):
        hs = _v(ln.hs_code)
        nodes.append(ctx.check(
            "INV_COO_HS", f"invoice line {ln.line_no} HS heading covered by certificate",
            None if hs is None or not coo_hs else hs[:6] in coo_hs, location=f"line{ln.line_no}",
            message=f"Invoice line {ln.line_no} HS {hs} is not listed on the certificate of origin ({', '.join(sorted(coo_hs))})",
            evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, f"lines[{i}].hs_code", hs),
                      ctx.ev(DT.CERTIFICATE_OF_ORIGIN, "hs_codes", ", ".join(sorted(coo_hs)))],
            inputs={"invoice_hs": str(hs), "certificate_hs": ", ".join(sorted(coo_hs))},
        ))
    return nodes


@rule
def parties(ctx: Context) -> list[TraceNode]:
    inv: CommercialInvoice | None = ctx.doc(DT.COMMERCIAL_INVOICE)
    bl: BillOfLading | None = ctx.doc(DT.BILL_OF_LADING)
    if inv is None or bl is None:
        return []
    nodes = []
    for inv_party, bl_party, label in ((inv.seller, bl.shipper, "seller/shipper"), (inv.buyer, bl.consignee, "buyer/consignee")):
        a, b = _v(inv_party.name), _v(bl_party.name)
        sim = None if a is None or b is None else party_similarity(a, b)
        nodes.append(ctx.check(
            "PARTY_MATCH", f"invoice vs B/L {label}", None if sim is None else sim >= ctx.config.party_match_threshold,
            location=label.replace("/", "_"),
            message=f"Invoice {label.split('/')[0]} '{a}' does not match B/L {label.split('/')[1]} '{b}'",
            evidence=[ctx.ev(DT.COMMERCIAL_INVOICE, f"{label.split('/')[0]}.name", a),
                      ctx.ev(DT.BILL_OF_LADING, f"{label.split('/')[1]}.name", b)],
            inputs={"invoice": str(a), "bill_of_lading": str(b), "similarity": f"{sim or 0:.2f}"},
        ))
    return nodes


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class RuleEngine:
    def __init__(self, config: RuleConfig | None = None, extra_rules: Iterable[Rule] = ()) -> None:
        self.config = config or RuleConfig()
        self.rules = [*RULES, *extra_rules]

    def evaluate(self, docs: dict[DT, DocRef], matcher: DescriptionMatcher | None = None,
                 extra_rules: Iterable[Rule] = ()) -> ValidationReport:
        ctx = Context(docs, self.config, matcher or TokenMatcher())
        trace = []
        for r in [*self.rules, *extra_rules]:
            children = r(ctx)
            if children:
                outcome = "fail" if any(_failed(c) for c in children) else (
                    "pass" if any(_passed(c) for c in children) else "skip")
                trace.append(TraceNode(children[0].rule_id if len(children) == 1 else r.__name__,
                                       r.__doc__ or r.__name__.replace("_", " "), outcome, children=children))
        return ValidationReport(RULESET_VERSION, list(ctx.issues.values()), trace)


def _failed(n: TraceNode) -> bool:
    return n.outcome == "fail" or any(_failed(c) for c in n.children)


def _passed(n: TraceNode) -> bool:
    return n.outcome == "pass" or any(_passed(c) for c in n.children)
