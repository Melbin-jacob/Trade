"""Extracted-field envelope with provenance and confidence.

Every value that comes out of the extraction pipeline is wrapped in an
``ExtractedField`` so downstream code can never "forget" where a value came from
or how confident the pipeline was.
"""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Any, Generic, Iterator, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from sentinel.domain.identifiers import CurrencyCode

T = TypeVar("T")

#: Fields scoring below this are automatically flagged for human review.
CONFIDENCE_REVIEW_THRESHOLD = Decimal("98")


class Extractor(StrEnum):
    OCR = "ocr"
    LAYOUT_MODEL = "layout_model"
    LLM_SCHEMA = "llm_schema"
    ENSEMBLE = "ensemble"  # agreement of two or more independent extractors
    HUMAN = "human"  # value keyed/corrected by an operator


class BoundingBox(BaseModel):
    model_config = ConfigDict(frozen=True)

    page: int = Field(ge=1)
    x0: Decimal
    y0: Decimal
    x1: Decimal
    y1: Decimal


class ExtractedField(BaseModel, Generic[T]):
    """A single extracted value with calibrated confidence (0-100)."""

    model_config = ConfigDict(frozen=True)

    value: T | None
    confidence: Decimal = Field(ge=0, le=100, decimal_places=2)
    extractor: Extractor
    source: BoundingBox | None = None
    raw_text: str | None = None  # what was literally on the page, before normalisation

    @property
    def needs_review(self) -> bool:
        return self.value is None or self.confidence < CONFIDENCE_REVIEW_THRESHOLD


class WeightUnit(StrEnum):
    KG = "KG"
    LB = "LB"
    MT = "MT"  # metric tonne


_TO_KG = {WeightUnit.KG: Decimal("1"), WeightUnit.LB: Decimal("0.45359237"), WeightUnit.MT: Decimal("1000")}


class Weight(BaseModel):
    model_config = ConfigDict(frozen=True)

    amount: Decimal = Field(ge=0)
    unit: WeightUnit

    def to_kg(self) -> Decimal:
        return self.amount * _TO_KG[self.unit]


class Money(BaseModel):
    model_config = ConfigDict(frozen=True)

    amount: Decimal
    currency: CurrencyCode


def iter_review_flags(obj: Any, path: str = "") -> Iterator[tuple[str, ExtractedField[Any]]]:
    """Yield ``(json_path, field)`` for every ExtractedField that needs review."""
    if isinstance(obj, ExtractedField):
        if obj.needs_review:
            yield path or "$", obj
        return
    if isinstance(obj, BaseModel):
        for name in type(obj).model_fields:
            yield from iter_review_flags(getattr(obj, name), f"{path}.{name}" if path else name)
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            yield from iter_review_flags(item, f"{path}[{i}]")
