"""Deterministic confidence scoring ("grounding") for LLM-extracted values.

A value earns a high score only if ALL of these hold:
  1. the LLM's verbatim evidence quote is actually present in the OCR text
     (otherwise it may be hallucinated)             -> else capped at 40
  2. the value itself is visible inside that quote  -> else capped at 70
  3. the value passes its type/format validator     -> else value=None, score 0
  4. independent deterministic extractors agree     -> disagreement capped at 60
The score is the lowest OCR confidence of the tokens the quote spans, then
passed through a calibration curve fitted on labelled data (identity by default).
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from pydantic import BaseModel

from sentinel.domain.fields import Extractor
from sentinel.domain.identifiers import iso6346_check_digit
from sentinel.extraction.ocr import OcrResult

CAP_UNGROUNDED = Decimal("40")
CAP_VALUE_NOT_IN_EVIDENCE = Decimal("70")
CAP_CROSS_CHECK_DISAGREES = Decimal("60")

_CONTAINER_RE = re.compile(r"\b([A-Z]{3}[UJZR])\s?-?(\d{6})\s?-?(\d)\b")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.casefold()).strip()


def _digits(s: str) -> str:
    return re.sub(r"[^0-9]", "", s)


@dataclass
class Calibration:
    """Piecewise-linear map raw score -> calibrated probability-of-correct (0-100)."""

    points: list[tuple[Decimal, Decimal]] = field(
        default_factory=lambda: [(Decimal(0), Decimal(0)), (Decimal(100), Decimal(100))]
    )

    def __call__(self, raw: Decimal) -> Decimal:
        xs = [p[0] for p in self.points]
        i = max(1, min(len(xs) - 1, bisect_right(xs, raw)))
        (x0, y0), (x1, y1) = self.points[i - 1], self.points[i]
        y = y0 if x1 == x0 else y0 + (raw - x0) * (y1 - y0) / (x1 - x0)
        return max(Decimal(0), min(Decimal(100), y)).quantize(Decimal("0.01"))


def _value_tokens(value: Any) -> list[str]:
    """What must be visible in the evidence for this value to count as grounded."""
    if isinstance(value, BaseModel):  # Money / Weight
        return _value_tokens(getattr(value, "amount", None))
    if isinstance(value, Decimal):
        whole, _, frac = format(value.normalize(), "f").partition(".")
        return [_digits(whole) + frac.rstrip("0")]
    if isinstance(value, int):
        return [str(value)]
    if value is None:
        return []
    return [t for t in re.split(r"[^0-9a-z]+", _norm(str(value))) if t]


def _in_evidence(value: Any, evidence: str) -> bool:
    tokens = _value_tokens(value)
    if not tokens:
        return False
    if isinstance(value, (Decimal, int)) or isinstance(value, BaseModel):
        ev = _digits(evidence)
        return all(t.rstrip("0") in ev or t in ev for t in tokens)
    ev = _norm(evidence)
    hits = sum(1 for t in tokens if t in ev)
    if hits / len(tokens) >= 0.8:
        return True
    # Codes printed with separators: HS "0901.11" -> 090111, container "CSQU 305438-3".
    collapse = lambda x: re.sub(r"[^0-9a-z]", "", _norm(str(x)))  # noqa: E731
    return bool(collapse(value)) and collapse(value) in collapse(evidence)


class Scorer:
    def __init__(self, ocr: OcrResult, calibration: Calibration | None = None) -> None:
        self._ocr = ocr
        self._calibration = calibration or Calibration()
        self._norm_tokens = [_norm(t.text) for t in ocr.tokens]
        self._containers = {
            f"{m.group(1)}{m.group(2)}{m.group(3)}"
            for m in _CONTAINER_RE.finditer(ocr.text.upper())
            if iso6346_check_digit(m.group(1) + m.group(2)) == int(m.group(3))
        }

    def _locate(self, evidence: str):
        """Return the OCR tokens whose concatenation contains the evidence."""
        target = _norm(evidence)
        if not target:
            return None
        for i in range(len(self._norm_tokens)):
            acc = ""
            for j in range(i, min(i + 40, len(self._norm_tokens))):
                acc = f"{acc} {self._norm_tokens[j]}".strip()
                if target in acc:
                    return self._ocr.tokens[i : j + 1]
                if len(acc) > len(target) + 200:
                    break
        return None

    def __call__(self, path: str, typed: Any, raw: Any, evidence: str, valid: bool) -> dict[str, Any]:
        raw_text = evidence or (None if raw is None else str(raw))
        if raw is None or not valid:
            return {"value": None, "confidence": Decimal(0), "extractor": Extractor.LLM_SCHEMA, "raw_text": raw_text}
        span = self._locate(evidence)
        if span is None:
            return {"value": typed, "confidence": self._calibration(CAP_UNGROUNDED),
                    "extractor": Extractor.LLM_SCHEMA, "raw_text": raw_text}
        score = min(t.confidence for t in span)
        extractor = Extractor.ENSEMBLE
        if not _in_evidence(typed, evidence):
            score, extractor = min(score, CAP_VALUE_NOT_IN_EVIDENCE), Extractor.LLM_SCHEMA
        if path.endswith("container_number") and typed not in self._containers:
            score, extractor = min(score, CAP_CROSS_CHECK_DISAGREES), Extractor.LLM_SCHEMA
        return {"value": typed, "confidence": self._calibration(score), "extractor": extractor,
                "source": span[0].box, "raw_text": raw_text}
