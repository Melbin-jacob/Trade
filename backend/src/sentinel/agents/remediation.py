"""Remediation drafter agent.

Turns open discrepancies into a precise correction request for the party that
can fix them. The agent only *proposes*: the kernel records the proposal, a
human approves the exact text, and the dispatcher sends it.

Guardrails:
  * recipients come from the tenant's counterparty directory, never from the
    LLM or document text (a forged document cannot redirect the email)
  * the LLM sees issue data fenced as untrusted, has no tools, and must return
    a strict schema; output is checked for links, payment-detail requests and
    issue coverage, otherwise a deterministic template is used instead
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.agents.claude import UNTRUSTED_DATA_RULES, JsonLlm, LlmError
from sentinel.core.canonical import canonical_json
from sentinel.domain.documents import DocumentType as DT
from sentinel.kernel.service import RemediationAction, ShipmentService
from sentinel.kernel.shipment import ShipmentAggregate
from sentinel.security.principals import Principal
from sentinel.tenancy import TenantDirectory

DRAFTABLE_KINDS = {"discrepancy", "format", "missing_document"}
_ROLE_FOR_DOC = {DT.BILL_OF_LADING.value: "shipping_line"}
_FORBIDDEN = re.compile(
    r"(https?://|www\.|\biban\b|\bswift\b|\bbic\b|account number|routing number|wire transfer|bank details|password)",
    re.IGNORECASE,
)

SCHEMA = {
    "type": "object",
    "properties": {
        "subject": {"type": "string"},
        "body": {"type": "string"},
        "covered_issue_ids": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["subject", "body", "covered_issue_ids"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = f"""You draft correction requests that a trade-compliance team sends to an overseas supplier or \
shipping line when shipment documents disagree. A human compliance officer reviews every draft before it is sent.

Write a short, courteous, specific business email:
- Name each problem precisely: the document, the line or field, the conflicting values, and which document \
holds the value we believe is correct when the issue data says so.
- Ask for corrected, reissued documents (or the missing document). Do not ask for anything else.
- Plain text only: no links, no attachments, no payment, banking or credential topics, no threats or deadlines \
beyond asking for a prompt reply because the cargo is at port and demurrage applies.
- Sign off as "Trade Compliance Team, {{company}}".
- List in covered_issue_ids every issue id you addressed; address all of them.

{UNTRUSTED_DATA_RULES}"""


@dataclass(frozen=True)
class Draft:
    to: list[str]
    subject: str
    body: str
    issue_ids: list[str]
    generated_by: str  # llm | template

    def serialise(self) -> str:
        return canonical_json({"to": self.to, "subject": self.subject, "body": self.body,
                               "issue_ids": self.issue_ids, "generated_by": self.generated_by}).decode()


def responsible_role(issue: dict) -> str:
    docs = {e["doc_type"] for e in issue.get("evidence", [])}
    if docs and docs <= set(_ROLE_FOR_DOC):
        return _ROLE_FOR_DOC[next(iter(docs))]
    return "supplier"


class RemediationDrafter:
    def __init__(self, *, principal: Principal, service: ShipmentService, tenants: TenantDirectory,
                 llm: JsonLlm | None, company_name: str = "Acme Trading Inc.") -> None:
        self._principal, self._service, self._tenants = principal, service, tenants
        self._llm, self._company = llm, company_name

    def select(self, agg: ShipmentAggregate) -> tuple[str, list[dict]] | None:
        groups: dict[str, list[dict]] = {}
        for issue in agg.open_issues.values():
            if issue.get("kind") in DRAFTABLE_KINDS:
                groups.setdefault(responsible_role(issue), []).append(issue)
        if not groups:
            return None
        role = max(groups, key=lambda r: (sum(i.get("severity") == "critical" for i in groups[r]), len(groups[r])))
        return role, sorted(groups[role], key=lambda i: i["id"])

    def _template(self, agg: ShipmentAggregate, to: str, issues: list[dict]) -> Draft:
        lines = [f"{n}. {i['message']}" for n, i in enumerate(issues, start=1)]
        body = (
            "Hello,\n\nDuring our pre-clearance review of shipment "
            f"{agg.reference or agg.shipment_id} we found the following problems in the documents:\n\n"
            + "\n".join(lines)
            + "\n\nCould you please send corrected, reissued documents as soon as possible? The cargo is at port "
            "and demurrage charges apply until customs clearance.\n\nThank you,\n"
            f"Trade Compliance Team, {self._company}"
        )
        return Draft([to], f"Document corrections needed - {agg.reference or agg.shipment_id}", body,
                     [i["id"] for i in issues], "template")

    def _valid(self, d: dict, issue_ids: set[str]) -> bool:
        return (
            isinstance(d.get("subject"), str) and 0 < len(d["subject"]) <= 200
            and isinstance(d.get("body"), str) and 50 <= len(d["body"]) <= 4000
            and not _FORBIDDEN.search(d["subject"] + d["body"])
            and set(d.get("covered_issue_ids", [])) == issue_ids
        )

    def draft(self, agg: ShipmentAggregate) -> Draft | None:
        sel = self.select(agg)
        if sel is None:
            return None
        role, issues = sel
        cp = self._tenants.get(agg.tenant_id).counterparty_for_role(role)
        if cp is None:
            return None  # nobody on file for that role: a human handles it
        if self._llm is not None:
            facts = "\n".join(
                f"- id={i['id']} severity={i['severity']} problem={i['message']} evidence="
                + "; ".join(f"{e['doc_type']}:{e['field_path']}={e.get('value')}" for e in i.get("evidence", []))
                for i in issues
            )
            try:
                d = self._llm.complete_json(
                    purpose="draft_remediation", system=SYSTEM_PROMPT.replace("{company}", self._company),
                    user=(f"Recipient: {cp.name} ({role.replace('_', ' ')})\nOur shipment reference: "
                          f"{agg.reference}\n<untrusted>\n{facts}\n</untrusted>"),
                    schema=SCHEMA, tenant_id=agg.tenant_id, actor=self._principal.audit_ref(),
                )
                if self._valid(d, {i["id"] for i in issues}):
                    return Draft([cp.email], d["subject"].strip(), d["body"].strip(), [i["id"] for i in issues], "llm")
            except LlmError:
                pass
        return self._template(agg, cp.email, issues)

    def propose(self, agg: ShipmentAggregate) -> ShipmentAggregate | None:
        d = self.draft(agg)
        if d is None:
            return None
        return self._service.propose_remediation(
            self._principal, agg.tenant_id, agg.shipment_id, d.issue_ids, RemediationAction.EMAIL_DRAFT,
            d.serialise(), d.to,
        )
