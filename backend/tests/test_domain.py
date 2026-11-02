from decimal import Decimal

import pytest
from pydantic import TypeAdapter, ValidationError

from sentinel.core.canonical import CanonicalEncodingError, canonical_json
from sentinel.domain.fields import Weight, WeightUnit
from sentinel.domain.identifiers import ContainerNumber, HSCode
from tests.conftest import invoice

container = TypeAdapter(ContainerNumber)
hs = TypeAdapter(HSCode)


def test_valid_container_number_normalised():
    assert container.validate_python("csqu 305438-3") == "CSQU3054383"


@pytest.mark.parametrize("bad", ["CSQU3054384", "CSQU3045383", "CSQ3054383", "CSQX3054383"])
def test_container_check_digit_catches_typos_and_transpositions(bad):
    with pytest.raises(ValidationError):
        container.validate_python(bad)


def test_hs_codes():
    assert hs.validate_python("0901.21") == "090121"
    for bad in ["0901", "0901211", "000121", "990121"]:
        with pytest.raises(ValidationError):
            hs.validate_python(bad)


def test_weight_conversion_is_exact_decimal():
    assert Weight(amount=Decimal("1"), unit=WeightUnit.LB).to_kg() == Decimal("0.45359237")
    assert Weight(amount=Decimal("24.48"), unit=WeightUnit.MT).to_kg() == Decimal("24480.00")


def test_low_confidence_fields_are_flagged_with_paths():
    assert invoice().review_flags() == []
    assert invoice(confidence="97.99").review_flags() == ["lines[0].line_total"]


def test_canonical_json_is_order_independent_and_rejects_floats():
    assert canonical_json({"b": 1, "a": Decimal("2.50")}) == b'{"a":"2.50","b":1}'
    with pytest.raises(CanonicalEncodingError):
        canonical_json({"weight": 24.48})
