"""Inbound channels: email, cloud object storage events, signed partner/port APIs.

Each channel authenticates its source and turns it into ``IntakeItem``s. Nothing
from a channel is trusted beyond "this party sent these bytes".
"""

from __future__ import annotations

import base64
import binascii
import email
import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr

from sentinel.domain.documents import DocumentType
from sentinel.storage.blobs import BlobStore
from sentinel.tenancy import TenantConfig

SHIPMENT_REF_RE = re.compile(r"\b(SHP-\d{4}-\d{6})\b")


class ChannelRejected(PermissionError):
    pass


@dataclass(frozen=True)
class IntakeItem:
    tenant_id: str
    shipment_id: str
    filename: str
    content: bytes
    channel: str  # email | object_storage | port_api | manual_upload
    doc_type_hint: DocumentType | None = None
    metadata: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Email
# --------------------------------------------------------------------------- #


def _auth_passed(msg: email.message.EmailMessage, trusted_authserv_id: str) -> bool:
    """Only trust Authentication-Results stamped by OUR receiving MTA."""
    for header in msg.get_all("Authentication-Results", []):
        authserv, _, results = str(header).partition(";")
        if authserv.strip().lower() != trusted_authserv_id.lower():
            continue
        r = results.lower()
        if "dmarc=pass" in r or ("dkim=pass" in r and "spf=pass" in r):
            return True
    return False


def parse_email(raw: bytes, tenant: TenantConfig, trusted_authserv_id: str) -> list[IntakeItem]:
    msg = email.message_from_bytes(raw, policy=policy.default)
    sender = parseaddr(str(msg.get("From", "")))[1].lower()
    domain = sender.rsplit("@", 1)[-1]
    if domain not in tenant.inbound_email_domains:
        raise ChannelRejected(f"sender domain {domain!r} is not an approved counterparty")
    if not _auth_passed(msg, trusted_authserv_id):
        raise ChannelRejected("message failed DMARC/DKIM/SPF authentication")
    m = SHIPMENT_REF_RE.search(str(msg.get("Subject", "")))
    if not m:
        raise ChannelRejected("no shipment reference (SHP-YYYY-NNNNNN) in subject")
    items = []
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        items.append(
            IntakeItem(
                tenant_id=tenant.tenant_id,
                shipment_id=m.group(1),
                filename=part.get_filename() or "attachment",
                content=payload,
                channel="email",
                metadata={"sender": sender, "message_id": str(msg.get("Message-ID", ""))},
            )
        )
    if not items:
        raise ChannelRejected("email has no attachments")
    return items


# --------------------------------------------------------------------------- #
# Object storage (e.g. S3 ObjectCreated -> queue -> here)
# --------------------------------------------------------------------------- #


def from_object_event(event: dict, tenant: TenantConfig, source: BlobStore) -> IntakeItem:
    """Expected key layout: ``inbound/<tenant_id>/<shipment_id>/<filename>``."""
    parts = str(event["key"]).split("/")
    if len(parts) != 4 or parts[0] != "inbound" or parts[1] != tenant.tenant_id:
        raise ChannelRejected("object key outside this tenant's inbound prefix")
    if not SHIPMENT_REF_RE.fullmatch(parts[2]):
        raise ChannelRejected("invalid shipment id in object key")
    return IntakeItem(
        tenant_id=tenant.tenant_id,
        shipment_id=parts[2],
        filename=parts[3],
        content=source.get(event["key"]),
        channel="object_storage",
        metadata={"bucket": str(event.get("bucket", "")), "key": event["key"]},
    )


# --------------------------------------------------------------------------- #
# Signed partner / port-community-system webhooks
# --------------------------------------------------------------------------- #


class ReplayCache:
    def __init__(self, ttl_seconds: int = 600) -> None:
        self._seen: dict[str, float] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str, now: float) -> bool:
        with self._lock:
            self._seen = {k: t for k, t in self._seen.items() if now - t < self._ttl}
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


def verify_webhook(
    *, tenant: TenantConfig, partner_id: str, timestamp: str, nonce: str, signature: str,
    body: bytes, replay: ReplayCache, now: float | None = None, tolerance: int = 300,
) -> None:
    secret = tenant.webhook_secrets.get(partner_id)
    if secret is None:
        raise ChannelRejected("unknown partner")
    now = time.time() if now is None else now
    try:
        ts = int(timestamp)
    except ValueError:
        raise ChannelRejected("bad timestamp") from None
    if abs(now - ts) > tolerance:
        raise ChannelRejected("timestamp outside tolerance")
    expected = hmac.new(secret, f"{timestamp}.{nonce}.".encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ChannelRejected("bad signature")
    if not replay.check_and_add(f"{partner_id}:{nonce}", now):
        raise ChannelRejected("replayed request")


def from_port_api(body: bytes, tenant: TenantConfig, partner_id: str) -> IntakeItem:
    """Call only after ``verify_webhook`` succeeded."""
    try:
        data = json.loads(body)
        content = base64.b64decode(data["content_b64"], validate=True)
        shipment_id = data["shipment_id"]
    except (ValueError, KeyError, binascii.Error) as exc:
        raise ChannelRejected(f"malformed payload: {exc}") from None
    if not SHIPMENT_REF_RE.fullmatch(shipment_id):
        raise ChannelRejected("invalid shipment id")
    hint = data.get("doc_type")
    return IntakeItem(
        tenant_id=tenant.tenant_id,
        shipment_id=shipment_id,
        filename=str(data.get("filename", "document"))[:200],
        content=content,
        channel="port_api",
        doc_type_hint=DocumentType(hint) if hint else None,
        metadata={"partner_id": partner_id},
    )
