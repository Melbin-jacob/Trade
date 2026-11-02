"""Static inspection of untrusted files: type sniffing and active-content checks.

The declared filename / Content-Type are never trusted; the type is decided by
magic bytes and only a short allowlist is accepted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024
MIN_BYTES = 64

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"II*\x00", "image/tiff"),
    (b"MM\x00*", "image/tiff"),
)

EXTENSIONS = {"application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpg", "image/tiff": "tiff"}

# PDF features that can execute code, launch programs or smuggle payloads.
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFiles?|RichMedia|XFA|AcroForm\s*<<[^>]*?/XFA)\b")


@dataclass(frozen=True)
class InspectionResult:
    media_type: str | None
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.media_type is not None and not self.problems


def sniff_media_type(data: bytes) -> str | None:
    head = data[:16]
    for magic, media_type in _SIGNATURES:
        if head.startswith(magic):
            return media_type
    return None


def inspect(data: bytes) -> InspectionResult:
    problems: list[str] = []
    if len(data) > MAX_BYTES:
        problems.append(f"file exceeds {MAX_BYTES} bytes")
    if len(data) < MIN_BYTES:
        problems.append("file too small to be a trade document")
    media_type = sniff_media_type(data)
    if media_type is None:
        problems.append("unsupported or unrecognised file type")
    elif media_type == "application/pdf":
        found = sorted({m.group(1).decode() for m in _PDF_ACTIVE.finditer(data)})
        if found:
            problems.append("PDF contains active content: " + ", ".join(found))
        if b"/Encrypt" in data:
            problems.append("PDF is encrypted")
    return InspectionResult(media_type, tuple(problems))
