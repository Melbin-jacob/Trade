"""Deterministic document-type classifier (keyword evidence scoring).

Classification decides which schema the extractor is constrained to, so a
wrong guess is expensive. Below ``MIN_CONFIDENCE`` the file is quarantined for
a human to label instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.domain.documents import DocumentType as DT

MIN_CONFIDENCE = 90

_TITLE, _CUE = 6, 1
_RULES: dict[DT, tuple[tuple[str, int], ...]] = {
    DT.COMMERCIAL_INVOICE: (("commercial invoice", _TITLE), ("invoice no", _CUE), ("unit price", _CUE),
                            ("amount due", _CUE), ("incoterm", _CUE), ("total value", _CUE)),
    DT.BILL_OF_LADING: (("bill of lading", _TITLE), ("b/l no", _CUE), ("port of loading", _CUE),
                        ("port of discharge", _CUE), ("notify party", _CUE), ("vessel", _CUE)),
    DT.PACKING_LIST: (("packing list", _TITLE), ("gross weight", _CUE), ("net weight", _CUE),
                      ("no. of packages", _CUE), ("carton", _CUE), ("measurement", _CUE)),
    DT.CERTIFICATE_OF_ORIGIN: (("certificate of origin", _TITLE), ("country of origin", _CUE),
                               ("chamber of commerce", _CUE), ("hereby certif", _CUE)),
    DT.PHYTOSANITARY_CERTIFICATE: (("phytosanitary certificate", _TITLE), ("plant protection", _CUE),
                                   ("botanical name", _CUE), ("disinfestation", _CUE), ("ippc", _CUE)),
}


@dataclass(frozen=True)
class Classification:
    doc_type: DT | None
    confidence: int  # 0-100
    scores: dict[str, int]


def classify(text: str) -> Classification:
    norm = re.sub(r"\s+", " ", text.lower())
    scores = {dt: sum(w for phrase, w in rules if phrase in norm) for dt, rules in _RULES.items()}
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    (best, top), (_, second) = ranked[0], ranked[1]
    if top == 0:
        return Classification(None, 0, {k.value: v for k, v in scores.items()})
    # Needs a title hit plus a clear margin over the runner-up.
    has_title = any(phrase in norm for phrase, w in _RULES[best] if w == _TITLE)
    margin = (top - second) / top
    confidence = round(100 * margin) if has_title else min(60, round(100 * margin))
    return Classification(best, confidence, {k.value: v for k, v in scores.items()})
