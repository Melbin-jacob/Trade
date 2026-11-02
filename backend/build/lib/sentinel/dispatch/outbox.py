"""Outbox dispatcher: executes external actions that are already approved in the ledger.

It never decides anything. For each approval it re-verifies the approval
against the proposal, enforces the recipient allowlist and DLP rules, claims
the action idempotently in the ledger, executes it, and records the result.
"""

from __future__ import annotations

import json
import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

from sentinel.kernel.service import sha256_hex
from sentinel.ledger.audit import AuditLog
from sentinel.ledger.chain import ConcurrencyConflict, LedgerEntry, LedgerStore
from sentinel.security.principals import Principal
from sentinel.storage.blobs import EncryptedBlobStore
from sentinel.tenancy import TenantDirectory


class EmailSender(Protocol):
    def send(self, *, to: list[str], subject: str, body: str, headers: dict[str, str]) -> str: ...


class CustomsGateway(Protocol):
    def submit(self, *, system: str, payload: bytes, shipment_id: str) -> str: ...


class SmtpEmailSender:
    """SMTP submission with STARTTLS pinned to TLS 1.3 and certificate verification."""

    def __init__(self, host: str, port: int, username: str, password: str, from_addr: str) -> None:
        self._host, self._port, self._user, self._pw, self._from = host, port, username, password, from_addr

    def send(self, *, to: list[str], subject: str, body: str, headers: dict[str, str]) -> str:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self._from, ", ".join(to), subject
        for k, v in headers.items():
            msg[k] = v
        msg.set_content(body)
        with smtplib.SMTP(self._host, self._port, timeout=30) as s:
            s.starttls(context=ctx)
            s.login(self._user, self._pw)
            s.send_message(msg)
        return str(msg["Message-ID"] or "")


class RecordingEmailSender:
    """Test/demo sender that keeps messages in memory."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, *, to: list[str], subject: str, body: str, headers: dict[str, str]) -> str:
        self.sent.append({"to": to, "subject": subject, "body": body, "headers": headers})
        return f"<demo-{len(self.sent)}@sentinel.local>"


class RecordingCustomsGateway:
    def __init__(self) -> None:
        self.submissions: list[dict] = []

    def submit(self, *, system: str, payload: bytes, shipment_id: str) -> str:
        self.submissions.append({"system": system, "payload": payload, "shipment_id": shipment_id})
        return f"{system}-ACK-{len(self.submissions):06d}"


def _luhn(digits: str) -> bool:
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")


def dlp_findings(text: str) -> list[str]:
    found = []
    for m in _CARD.finditer(text):
        if _luhn(re.sub(r"\D", "", m.group())):
            found.append("payment card number")
    if _IBAN.search(text):
        found.append("IBAN")
    if re.search(r"(?i)(password|secret|api[_ -]?key)\s*[:=]", text):
        found.append("credential")
    return found


def filing_key(shipment_id: str, payload_sha256: str) -> str:
    return f"filings/{shipment_id.lower()}/{payload_sha256}.json"


@dataclass
class DispatchResult:
    entry_sequence: int
    action: str
    outcome: str  # sent | blocked | failed | skipped
    detail: str = ""


class Dispatcher:
    def __init__(self, *, principal: Principal, store: LedgerStore, audit: AuditLog, tenants: TenantDirectory,
                 blobs: EncryptedBlobStore, email: EmailSender, customs: CustomsGateway) -> None:
        self._p, self._store, self._audit, self._tenants = principal, store, audit, tenants
        self._blobs, self._email, self._customs = blobs, email, customs
        self._checkpoint: dict[str, int] = {}

    def _record(self, e: LedgerEntry, event: str, payload: dict, expected_version: int | None = None) -> None:
        self._audit.record(tenant_id=e.tenant_id, actor=self._p.audit_ref(), aggregate_type="dispatch",
                           aggregate_id=f"dispatch:{e.entry_id}", event_type=event,
                           payload={"source_sequence": e.sequence, "shipment_id": e.aggregate_id, **payload},
                           expected_version=expected_version)

    def _claim(self, e: LedgerEntry, action: str) -> bool:
        try:
            self._record(e, "dispatch.claimed", {"action": action}, expected_version=0)
            return True
        except ConcurrencyConflict:
            return False  # already handled (or being handled) by another worker

    def run_once(self, tenant_id: str) -> list[DispatchResult]:
        results = []
        start = self._checkpoint.get(tenant_id, 0) + 1
        for e in self._store.read_chain(tenant_id, start):
            self._checkpoint[tenant_id] = e.sequence
            if e.aggregate_type != "shipment":
                continue
            if e.event_type == "remediation.approved":
                results.append(self._send_remediation(e))
            elif e.event_type == "filing.submitted":
                results.append(self._submit_filing(e))
        return results

    def _send_remediation(self, e: LedgerEntry) -> DispatchResult:
        if not self._claim(e, "email"):
            return DispatchResult(e.sequence, "email", "skipped", "already dispatched")
        proposal = next((x.payload for x in self._store.read_aggregate(e.tenant_id, e.aggregate_id)
                         if x.event_type == "remediation.proposed"
                         and x.payload["proposal_id"] == e.payload["proposal_id"]), None)
        problems = []
        if proposal is None:
            problems.append("proposal not found")
        elif sha256_hex(proposal["draft"].encode()) != e.payload["draft_sha256"]:
            problems.append("draft does not match approved hash")
        if problems:
            self._record(e, "dispatch.blocked", {"reasons": problems})
            return DispatchResult(e.sequence, "email", "blocked", "; ".join(problems))
        draft = json.loads(proposal["draft"])
        tenant = self._tenants.get(e.tenant_id)
        bad = [r for r in draft["to"] if not tenant.allowed_recipient(r)]
        if bad or sorted(draft["to"]) != sorted(proposal["recipients"]):
            problems.append(f"recipient not on counterparty allowlist: {bad or draft['to']}")
        problems += [f"DLP: {f}" for f in dlp_findings(draft["subject"] + "\n" + draft["body"])]
        if problems:
            self._record(e, "dispatch.blocked", {"reasons": problems})
            return DispatchResult(e.sequence, "email", "blocked", "; ".join(problems))
        try:
            message_id = self._email.send(to=draft["to"], subject=draft["subject"], body=draft["body"],
                                          headers={"X-Sentinel-Shipment": e.aggregate_id,
                                                   "X-Sentinel-Approval": str(e.entry_id)})
        except Exception as exc:
            self._record(e, "dispatch.failed", {"error": type(exc).__name__})
            return DispatchResult(e.sequence, "email", "failed", type(exc).__name__)
        self._record(e, "dispatch.sent", {"channel": "email", "to": draft["to"], "message_id": message_id,
                                          "draft_sha256": e.payload["draft_sha256"]})
        return DispatchResult(e.sequence, "email", "sent", message_id)

    def _submit_filing(self, e: LedgerEntry) -> DispatchResult:
        if not self._claim(e, "customs_filing"):
            return DispatchResult(e.sequence, "customs_filing", "skipped", "already dispatched")
        sha = e.payload["filing_payload_sha256"]
        try:
            payload = self._blobs.get(e.tenant_id, filing_key(e.aggregate_id, sha))
        except FileNotFoundError:
            self._record(e, "dispatch.blocked", {"reasons": ["filing payload not found"]})
            return DispatchResult(e.sequence, "customs_filing", "blocked", "payload missing")
        if sha256_hex(payload) != sha:
            self._record(e, "dispatch.blocked", {"reasons": ["filing payload hash mismatch"]})
            return DispatchResult(e.sequence, "customs_filing", "blocked", "hash mismatch")
        try:
            ack = self._customs.submit(system=e.payload["customs_system"], payload=payload, shipment_id=e.aggregate_id)
        except Exception as exc:
            self._record(e, "dispatch.failed", {"error": type(exc).__name__})
            return DispatchResult(e.sequence, "customs_filing", "failed", type(exc).__name__)
        self._record(e, "dispatch.sent", {"channel": "customs", "system": e.payload["customs_system"], "ack": ack})
        return DispatchResult(e.sequence, "customs_filing", "sent", ack)
