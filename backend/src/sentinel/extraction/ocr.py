"""OCR / text-layer engines (deterministic layer of the hybrid pipeline).

Engines return words (or line chunks) with a per-token confidence (0-100) and
position. The LLM never sees pixels it could "imagine" values from: it reads
this text, and every value it returns must be found back in it.
"""

from __future__ import annotations

import csv
import io
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from sentinel.domain.fields import BoundingBox


@dataclass(frozen=True)
class OcrToken:
    text: str
    confidence: Decimal  # 0-100
    box: BoundingBox | None = None


@dataclass(frozen=True)
class OcrResult:
    engine: str
    tokens: tuple[OcrToken, ...]

    @property
    def text(self) -> str:
        return "\n".join(t.text for t in self.tokens)

    @property
    def char_count(self) -> int:
        return sum(len(t.text.strip()) for t in self.tokens)


class OcrEngine(Protocol):
    name: str

    def read(self, data: bytes, media_type: str) -> OcrResult: ...


class OcrUnavailable(RuntimeError):
    pass


class PdfTextLayerEngine:
    """Born-digital PDFs: the text layer is exact, so confidence is near-certain."""

    name = "pdf_text_layer"
    TEXT_LAYER_CONFIDENCE = Decimal("99.90")

    def read(self, data: bytes, media_type: str) -> OcrResult:
        if media_type != "application/pdf":
            return OcrResult(self.name, ())
        from pypdf import PdfReader

        tokens: list[OcrToken] = []
        reader = PdfReader(io.BytesIO(data))
        for page_no, page in enumerate(reader.pages, start=1):
            chunks: list[tuple[str, float, float]] = []

            def visit(text, cm, tm, font_dict, font_size, _chunks=chunks):
                if text.strip():
                    _chunks.append((text.strip(), float(tm[4]), float(tm[5])))

            page.extract_text(visitor_text=visit)
            for text, x, y in chunks:
                box = BoundingBox(page=page_no, x0=Decimal(str(round(x, 2))), y0=Decimal(str(round(y, 2))),
                                  x1=Decimal(str(round(x + 6 * len(text), 2))), y1=Decimal(str(round(y + 12, 2))))
                tokens.append(OcrToken(text, self.TEXT_LAYER_CONFIDENCE, box))
        return OcrResult(self.name, tuple(tokens))


def parse_tesseract_tsv(tsv: str, page_offset: int = 0) -> list[OcrToken]:
    tokens = []
    for row in csv.DictReader(io.StringIO(tsv), delimiter="\t", quoting=csv.QUOTE_NONE):
        text = (row.get("text") or "").strip()
        conf = row.get("conf") or "-1"
        if not text or float(conf) < 0:
            continue
        left, top, w, h = (Decimal(row[k]) for k in ("left", "top", "width", "height"))
        box = BoundingBox(page=int(row["page_num"]) + page_offset, x0=left, y0=top, x1=left + w, y1=top + h)
        tokens.append(OcrToken(text, Decimal(conf).quantize(Decimal("0.01")), box))
    return tokens


class TesseractEngine:
    """Scanned documents. Needs the ``tesseract`` binary (and ``pdftoppm`` for PDFs)."""

    name = "tesseract"

    def __init__(self, lang: str = "eng", dpi: int = 300, timeout: int = 120) -> None:
        self._lang, self._dpi, self._timeout = lang, dpi, timeout

    def _tsv(self, image: Path) -> str:
        if not shutil.which("tesseract"):
            raise OcrUnavailable("tesseract binary not installed")
        out = subprocess.run(
            ["tesseract", str(image), "stdout", "-l", self._lang, "--dpi", str(self._dpi), "tsv"],
            capture_output=True, timeout=self._timeout, check=True,
        )
        return out.stdout.decode("utf-8", errors="replace")

    def read(self, data: bytes, media_type: str) -> OcrResult:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "input"
            src.write_bytes(data)
            images = [src]
            if media_type == "application/pdf":
                if not shutil.which("pdftoppm"):
                    raise OcrUnavailable("pdftoppm not installed")
                subprocess.run(["pdftoppm", "-r", str(self._dpi), "-png", str(src), str(Path(tmp) / "p")],
                               capture_output=True, timeout=self._timeout, check=True)
                images = sorted(Path(tmp).glob("p-*.png"))
            tokens: list[OcrToken] = []
            for i, img in enumerate(images):
                tokens += parse_tesseract_tsv(self._tsv(img), page_offset=i)
        return OcrResult(self.name, tuple(tokens))


class HybridOcr:
    """Use the exact text layer when a PDF has one; otherwise fall back to OCR."""

    name = "hybrid"

    def __init__(self, text_layer: OcrEngine | None = None, ocr: OcrEngine | None = None,
                 min_chars: int = 40) -> None:
        self._text_layer = text_layer or PdfTextLayerEngine()
        self._ocr = ocr or TesseractEngine()
        self._min_chars = min_chars

    def read(self, data: bytes, media_type: str) -> OcrResult:
        result = self._text_layer.read(data, media_type)
        if result.char_count >= self._min_chars:
            return result
        return self._ocr.read(data, media_type)
