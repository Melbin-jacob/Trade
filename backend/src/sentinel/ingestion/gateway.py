"""Ingestion gateway: inspect -> scan -> classify -> encrypt & store -> register.

Every decision (accept / quarantine / duplicate) is written to the audit ledger.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable

from sentinel.domain.documents import DocumentType
from sentinel.ingestion.channels import IntakeItem
from sentinel.ingestion.classifier import MIN_CONFIDENCE, classify
from sentinel.ingestion.inspection import EXTENSIONS, inspect
from sentinel.ingestion.scanner import MalwareScanner, ScannerUnavailable
from sentinel.kernel.service import GuardViolation, ShipmentService
from sentinel.kernel.shipment import InvalidTransition
from sentinel.ledger.audit import AuditLog
from sentinel.security.principals import AuthorizationError, Principal
from sentinel.storage.blobs import EncryptedBlobStore


class Outcome(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class IngestionResult:
    outcome: Outcome
    content_sha256: str
    reason: str | None = None
    doc_type: DocumentType | None = None
    storage_key: str | None = None


def pdf_text_layer(data: bytes, media_type: str) -> str:
    """Default text source for classification: the PDF text layer (first 2 pages)."""
    if media_type != "application/pdf":
        return ""
    import io

    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data))
        return "\n".join((p.extract_text() or "") for p in reader.pages[:2])
    except Exception:  # malformed PDFs are classified as unknown -> quarantine
        return ""


class IngestionGateway:
    def __init__(
        self,
        *,
        principal: Principal,
        service: ShipmentService,
        blobs: EncryptedBlobStore,
        scanner: MalwareScanner,
        audit: AuditLog,
        text_reader: Callable[[bytes, str], str] = pdf_text_layer,
    ) -> None:
        self._principal = principal
        self._service = service
        self._blobs = blobs
        self._scanner = scanner
        self._audit = audit
        self._text = text_reader

    def _record(self, item: IntakeItem, sha: str, event: str, payload: dict) -> None:
        self._audit.record(
            tenant_id=item.tenant_id,
            actor=self._principal.audit_ref(),
            aggregate_type="intake",
            aggregate_id=f"intake:{sha}",
            event_type=event,
            payload={"shipment_id": item.shipment_id, "channel": item.channel,
                     "filename": item.filename, "metadata": dict(item.metadata), **payload},
        )

    def _quarantine(self, item: IntakeItem, sha: str, reason: str) -> IngestionResult:
        key = f"quarantine/{sha}"
        self._blobs.put(item.tenant_id, key, item.content)
        self._record(item, sha, "intake.quarantined", {"reason": reason, "storage_key": key})
        return IngestionResult(Outcome.QUARANTINED, sha, reason, storage_key=key)

    def ingest(self, item: IntakeItem) -> IngestionResult:
        sha = hashlib.sha256(item.content).hexdigest()

        report = inspect(item.content)
        if not report.ok:
            return self._quarantine(item, sha, "; ".join(report.problems))

        try:
            scan = self._scanner.scan(item.content)
        except ScannerUnavailable as exc:
            return self._quarantine(item, sha, f"malware scanner unavailable: {exc}")
        if not scan.clean:
            return self._quarantine(item, sha, f"malware detected: {scan.signature}")

        doc_type = item.doc_type_hint
        if doc_type is None:
            c = classify(self._text(item.content, report.media_type or ""))
            if c.doc_type is None or c.confidence < MIN_CONFIDENCE:
                return self._quarantine(item, sha, f"document type unclear (confidence {c.confidence})")
            doc_type = c.doc_type

        key = f"documents/{item.shipment_id.lower()}/{sha}.{EXTENSIONS[report.media_type]}"
        ref = self._blobs.put(item.tenant_id, key, item.content)
        try:
            self._service.register_document(
                self._principal, item.tenant_id, item.shipment_id, doc_type,
                item.content, item.channel, ref.uri,  # type: ignore[arg-type]
            )
        except GuardViolation as exc:
            self._record(item, sha, "intake.duplicate", {"reason": str(exc)})
            return IngestionResult(Outcome.DUPLICATE, sha, str(exc), doc_type, key)
        except (InvalidTransition, AuthorizationError) as exc:
            # Unknown shipment, or shipment already filed/closed: a human decides.
            return self._quarantine(item, sha, f"cannot attach to shipment: {exc}")
        self._record(item, sha, "intake.accepted", {"doc_type": doc_type, "storage_key": key,
                                                    "media_type": report.media_type})
        return IngestionResult(Outcome.ACCEPTED, sha, None, doc_type, key)
