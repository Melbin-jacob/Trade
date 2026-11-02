"""Strongly-validated trade identifiers.

These are deterministic checks (Thick Kernel): no LLM is ever asked whether a
container number is valid.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator, StringConstraints

# --------------------------------------------------------------------------- #
# ISO 6346 container numbers, e.g. "MSCU1234565"
# --------------------------------------------------------------------------- #

_ISO6346_RE = re.compile(r"^[A-Z]{3}[UJZR][0-9]{7}$")


def _iso6346_letter_values() -> dict[str, int]:
    # Letters map to 10..38, skipping multiples of 11 (11, 22, 33).
    values: dict[str, int] = {}
    n = 10
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if n % 11 == 0:
            n += 1
        values[ch] = n
        n += 1
    return values


_LETTER_VALUES = _iso6346_letter_values()


def iso6346_check_digit(first_ten: str) -> int:
    """Compute the ISO 6346 check digit for the owner code + serial (10 chars)."""
    if len(first_ten) != 10:
        raise ValueError("expected 10 characters (owner code, category, serial)")
    total = 0
    for i, ch in enumerate(first_ten):
        v = _LETTER_VALUES[ch] if ch.isalpha() else int(ch)
        total += v * (2**i)
    return (total % 11) % 10


def validate_container_number(value: str) -> str:
    normalised = re.sub(r"[\s\-]", "", value).upper()
    if not _ISO6346_RE.match(normalised):
        raise ValueError(f"{value!r} is not a well-formed ISO 6346 container number")
    if iso6346_check_digit(normalised[:10]) != int(normalised[10]):
        # A failed check digit is the classic signature of a transposed digit.
        raise ValueError(f"{value!r} fails the ISO 6346 check digit")
    return normalised


ContainerNumber = Annotated[str, AfterValidator(validate_container_number)]

# --------------------------------------------------------------------------- #
# Harmonized System codes: 6-digit international root, up to 10 national digits
# --------------------------------------------------------------------------- #


def validate_hs_code(value: str) -> str:
    digits = re.sub(r"[\s.]", "", value)
    if not re.fullmatch(r"[0-9]{6,10}", digits) or len(digits) % 2:
        raise ValueError(f"{value!r} is not a valid HS code (6, 8 or 10 digits)")
    if digits[:2] == "00" or int(digits[:2]) > 97:
        raise ValueError(f"{value!r} has an invalid HS chapter")
    return digits


HSCode = Annotated[str, AfterValidator(validate_hs_code)]

# --------------------------------------------------------------------------- #
# Misc codes
# --------------------------------------------------------------------------- #

CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]  # ISO 4217
CountryCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]  # ISO 3166-1 alpha-2
TenantId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{2,40}$")]
