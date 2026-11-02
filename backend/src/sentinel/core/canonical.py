"""Canonical JSON encoding used for hashing and signing.

Every byte that feeds a hash in the audit ledger goes through this module, so the
encoding must be byte-for-byte reproducible on any machine, in any language, for
the lifetime of the records (customs retention is typically 5-7 years).

Rules:
  * object keys must be strings and are sorted; no insignificant whitespace
  * floats are REJECTED - binary floating point is ambiguous for money and
    weights. Use ``decimal.Decimal`` (encoded as a string).
  * datetimes must be timezone-aware and are normalised to UTC ISO-8601
  * UUIDs, Enums and Pydantic models are reduced to primitive values
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class CanonicalEncodingError(TypeError):
    """Raised when a value cannot be encoded deterministically."""


def _normalise(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalEncodingError(
            "floats are not allowed in canonical payloads; use Decimal"
        )
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalEncodingError("non-finite Decimal is not allowed")
        return str(value)
    if isinstance(value, Enum):
        return _normalise(value.value)
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CanonicalEncodingError("naive datetimes are not allowed")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, BaseModel):
        return _normalise(value.model_dump(mode="python"))
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalEncodingError(f"object keys must be str, got {type(k)!r}")
            out[k] = _normalise(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalise(v) for v in value]
    if isinstance(value, (set, frozenset)):
        raise CanonicalEncodingError("sets have no canonical order; use a sorted list")
    raise CanonicalEncodingError(f"unsupported type {type(value)!r}")


def canonical_json(value: Any) -> bytes:
    """Return the canonical UTF-8 JSON encoding of ``value``."""
    return json.dumps(
        _normalise(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
