"""Offline stand-ins for Claude used by tests and the demo (no API key needed)."""

from __future__ import annotations

import re
from typing import Any

from sentinel.agents.claude import ScriptedLlm
from sentinel.ledger.audit import AuditLog


def _evidences(obj: Any) -> list[str]:
    if isinstance(obj, dict):
        if set(obj) == {"value", "evidence"}:
            return [obj["evidence"]] if obj["evidence"] else []
        return [e for v in obj.values() for e in _evidences(v)]
    if isinstance(obj, list):
        return [e for v in obj for e in _evidences(v)]
    return []


def extraction_responder(responses: list[dict]):
    """Pick the canned extraction whose evidence quotes best match the document text."""

    def respond(user: str) -> dict:
        def score(r):
            ev = _evidences(r)
            doc_no = r.get("document_number", {}).get("evidence", "")
            return (2 if doc_no and doc_no in user else 0) + sum(e in user for e in ev) / max(1, len(ev))

        return max(responses, key=score)

    return respond


def draft_responder(user: str) -> dict:
    ids = re.findall(r"id=(\S+)", user)
    problems = re.findall(r"problem=(.+?) evidence=", user)
    ref = re.search(r"shipment reference: (\S+)", user)
    body = ("Hello,\n\nWhile preparing customs clearance for our order "
            f"{ref.group(1) if ref else ''} we found these document problems:\n\n"
            + "\n".join(f"- {p}" for p in problems)
            + "\n\nPlease reissue the corrected documents at your earliest convenience - the container is at "
              "port and demurrage is accruing.\n\nKind regards,\nTrade Compliance Team, Acme Trading Inc.")
    return {"subject": f"Correction request - {ref.group(1) if ref else 'shipment'}", "body": body,
            "covered_issue_ids": ids}


def demo_llm(extractions: dict[str, list[dict]], audit: AuditLog | None = None) -> ScriptedLlm:
    """Pass as ``llm_factory=lambda audit: demo_llm(..., audit)``."""
    responses: dict[str, Any] = {f"extract:{k}": extraction_responder(v) for k, v in extractions.items()}
    responses["draft_remediation"] = draft_responder
    responses["semantic_match"] = {"label": "same_goods", "rationale": "Same commodity described differently."}
    return ScriptedLlm(responses, audit)
