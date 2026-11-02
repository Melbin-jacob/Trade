"""Semantic matching of goods descriptions (the "thin agent" part of validation).

The LLM only *labels* whether two descriptions denote the same goods; the
accept/reject threshold and every consequence are decided in code. Cheap
deterministic matching runs first, so the LLM is consulted only for real
ambiguity ("Green coffee beans, Arabica" vs "Coffea arabica, unroasted").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from sentinel.agents.claude import UNTRUSTED_DATA_RULES, JsonLlm, LlmError

_STOP = {"of", "the", "and", "a", "an", "in", "for", "with", "not", "no", "bag", "bags", "pcs", "ctn", "cartons"}
_SYNONYMS = {"unroasted": "green", "raw": "green", "coffea": "coffee", "arabica": "arabica"}
_LEGAL = {"ltd", "ltda", "llc", "inc", "co", "corp", "corporation", "gmbh", "sa", "s.a", "bv", "plc", "limited",
          "company", "srl", "spa", "pte", "pty", "ag", "oy", "ab", "as", "nv", "kg", "sarl"}


def tokens(text: str, drop: set[str] = _STOP) -> set[str]:
    out = set()
    for t in re.split(r"[^0-9a-z]+", text.casefold()):
        if not t or t in drop:
            continue
        t = _SYNONYMS.get(t, t)
        out.add(t[:-1] if len(t) > 4 and t.endswith("s") else t)
    return out


def party_similarity(a: str, b: str) -> float:
    ta, tb = tokens(a, _LEGAL), tokens(b, _LEGAL)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


@dataclass(frozen=True)
class MatchResult:
    score: float  # 0..1
    method: str  # token | llm
    rationale: str


class DescriptionMatcher(Protocol):
    def match(self, a: str, b: str) -> MatchResult: ...


class TokenMatcher:
    def match(self, a: str, b: str) -> MatchResult:
        ta, tb = tokens(a), tokens(b)
        if not ta or not tb:
            return MatchResult(0.0, "token", "empty description")
        containment = len(ta & tb) / min(len(ta), len(tb))
        jaccard = len(ta & tb) / len(ta | tb)
        score = round(max(jaccard, 0.9 * containment), 3)
        return MatchResult(score, "token", f"shared terms: {', '.join(sorted(ta & tb)) or 'none'}")


LABEL_SCORES = {"same_goods": 0.95, "related_goods": 0.55, "different_goods": 0.05}

_SCHEMA = {
    "type": "object",
    "properties": {
        "label": {"type": "string", "enum": list(LABEL_SCORES)},
        "rationale": {"type": "string"},
    },
    "required": ["label", "rationale"],
    "additionalProperties": False,
}

_SYSTEM = f"""You compare two goods descriptions taken from different trade documents for the same \
shipment (for example an invoice line and a packing-list line) and decide whether they describe the same goods.
Use trade terminology: botanical names, HS nomenclature, abbreviations, and supplier shorthand all count. \
Answer "same_goods" when a customs officer would accept them as the same item, "related_goods" when they are \
the same category but plausibly a different item (different grade, processing or variety), otherwise \
"different_goods". Give a one-sentence rationale.
{UNTRUSTED_DATA_RULES}"""


class HybridMatcher:
    def __init__(self, llm: JsonLlm | None, tenant_id: str, actor: dict[str, str],
                 fast_accept: float = 0.8) -> None:
        self._token = TokenMatcher()
        self._llm, self._tenant, self._actor, self._fast = llm, tenant_id, actor, fast_accept
        self._cache: dict[tuple[str, str], MatchResult] = {}

    def match(self, a: str, b: str) -> MatchResult:
        quick = self._token.match(a, b)
        if quick.score >= self._fast or self._llm is None:
            return quick
        key = (a, b)
        if key not in self._cache:
            try:
                r = self._llm.complete_json(
                    purpose="semantic_match", system=_SYSTEM,
                    user=f"<untrusted>\nA: {a}\nB: {b}\n</untrusted>", schema=_SCHEMA,
                    tenant_id=self._tenant, actor=self._actor,
                )
                self._cache[key] = MatchResult(LABEL_SCORES[r["label"]], "llm", str(r["rationale"])[:300])
            except (LlmError, KeyError):
                return quick  # degrade to deterministic matching, never block validation
        return self._cache[key]
