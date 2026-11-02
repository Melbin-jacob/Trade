"""Derive the LLM-facing JSON schema from the domain models, and map back.

The domain models wrap every value in ``ExtractedField[T]``. The LLM instead
fills ``{"value": <T>, "evidence": "<verbatim quote>"}`` for each field. The
LLM never supplies a confidence score - that is computed deterministically by
``grounding.Scorer`` from the OCR layer.
"""

from __future__ import annotations

import types
from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Annotated, Any, Callable, Literal, Union, get_args, get_origin

from pydantic import BaseModel, TypeAdapter, ValidationError

from sentinel.domain.fields import ExtractedField, Extractor

NUMBER_HINT = "Decimal number exactly as printed, normalised: digits and a '.' only (e.g. '24480.50')."


def _unwrap_optional(ann: Any) -> tuple[Any, bool]:
    if get_origin(ann) in (Union, types.UnionType):
        args = [a for a in get_args(ann) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
    return ann, False


def _base(ann: Any) -> Any:
    return get_args(ann)[0] if get_origin(ann) is Annotated else ann


def _field_inner(ann: Any) -> Any | None:
    if isinstance(ann, type) and issubclass(ann, ExtractedField):
        args = ann.__pydantic_generic_metadata__["args"]
        return args[0] if args else None
    return None


def _nullable(schema: dict) -> dict:
    return {"anyOf": [schema, {"type": "null"}]}


def _obj(props: dict[str, dict]) -> dict:
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


def _value_schema(ann: Any) -> dict:
    ann = _base(ann)
    if ann is str:
        return {"type": "string"}
    if ann is int:
        return {"type": "integer"}
    if ann is Decimal:
        return {"type": "string", "description": NUMBER_HINT}
    if ann is date:
        return {"type": "string", "description": "ISO-8601 date YYYY-MM-DD"}
    if isinstance(ann, type) and issubclass(ann, Enum):
        return {"type": "string", "enum": [m.value for m in ann]}
    if isinstance(ann, type) and issubclass(ann, BaseModel):
        return model_schema(ann)
    raise TypeError(f"unsupported value type {ann!r}")


def _schema_for(ann: Any) -> dict | None:
    inner_ann, optional = _unwrap_optional(ann)
    if get_origin(inner_ann) is Literal:
        return None  # discriminators are set by us, not the LLM
    if (inner := _field_inner(inner_ann)) is not None:
        return _obj({
            "value": _nullable(_value_schema(inner)),
            "evidence": {"type": "string",
                         "description": "Verbatim text copied from the document that shows this value; '' if absent."},
        })
    if get_origin(inner_ann) is list:
        item = _schema_for(get_args(inner_ann)[0])
        return {"type": "array", "items": item}
    s = _value_schema(inner_ann)
    return _nullable(s) if optional else s


def model_schema(cls: type[BaseModel]) -> dict:
    props = {}
    for name, f in cls.model_fields.items():
        s = _schema_for(f.annotation)
        if s is not None:
            props[name] = s
    return _obj(props)


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #

#: (path, typed_value_or_None, raw_value, evidence, valid) -> ExtractedField kwargs
Scorer = Callable[[str, Any, Any, str, bool], dict[str, Any]]


def _assemble_value(ann: Any, raw: Any, path: str, score: Scorer) -> Any:
    inner_ann, optional = _unwrap_optional(ann)
    if (inner := _field_inner(inner_ann)) is not None:
        raw = raw or {}
        value, evidence = raw.get("value"), str(raw.get("evidence") or "")
        if value is None and optional:
            return None
        typed, valid = None, False
        if value is not None:
            try:
                typed = TypeAdapter(inner).validate_python(value)
                valid = True
            except ValidationError:
                typed = None
        kwargs = score(path, typed, value, evidence, valid)
        return inner_ann(**kwargs)
    if get_origin(inner_ann) is list:
        item_ann = get_args(inner_ann)[0]
        return [_assemble_value(item_ann, r, f"{path}[{i}]", score) for i, r in enumerate(raw or [])]
    base = _base(inner_ann)
    if isinstance(base, type) and issubclass(base, BaseModel):
        return None if raw is None and optional else assemble(base, raw or {}, score, path)
    return raw


def assemble(cls: type[BaseModel], data: dict, score: Scorer, prefix: str = "") -> BaseModel:
    kwargs = {}
    for name, f in cls.model_fields.items():
        if _schema_for(f.annotation) is None:
            continue
        path = f"{prefix}.{name}" if prefix else name
        kwargs[name] = _assemble_value(f.annotation, data.get(name), path, score)
    return cls(**kwargs)


__all__ = ["model_schema", "assemble", "Scorer", "Extractor"]
