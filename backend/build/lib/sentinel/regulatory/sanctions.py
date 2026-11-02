"""Sanctions-list screening (OFAC SDN format; other lists map onto the same entry type).

Matching is deterministic: normalised names, token-order-insensitive
Jaro-Winkler plus token containment. Thresholds are deliberately conservative -
a false positive costs a human review, a false negative costs a violation.
"""

from __future__ import annotations

import csv
import io
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

OFAC_SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
OFAC_ALT_URL = "https://www.treasury.gov/ofac/downloads/alt.csv"

#: Comprehensively sanctioned jurisdictions (illustrative; maintained by compliance).
EMBARGOED_COUNTRIES = frozenset({"CU", "IR", "KP", "SY"})

_NOISE = {"ltd", "ltda", "llc", "inc", "co", "corp", "company", "limited", "gmbh", "sa", "s", "a", "fze", "fzco",
          "plc", "bv", "nv", "ag", "the", "of", "and", "trading", "group", "holding", "holdings", "international"}


def normalise(name: str) -> str:
    n = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().casefold()
    return " ".join(t for t in re.split(r"[^0-9a-z]+", n) if t and t not in _NOISE)


def jaro_winkler(a: str, b: str) -> float:
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if not la or not lb:
        return 0.0
    window = max(la, lb) // 2 - 1
    ma, mb = [False] * la, [False] * lb
    matches = 0
    for i, ch in enumerate(a):
        for j in range(max(0, i - window), min(lb, i + window + 1)):
            if not mb[j] and b[j] == ch:
                ma[i] = mb[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    sa = [a[i] for i in range(la) if ma[i]]
    sb = [b[j] for j in range(lb) if mb[j]]
    transpositions = sum(x != y for x, y in zip(sa, sb)) / 2
    jaro = (matches / la + matches / lb + (matches - transpositions) / matches) / 3
    prefix = 0
    for x, y in zip(a[:4], b[:4]):
        if x != y:
            break
        prefix += 1
    return jaro + prefix * 0.1 * (1 - jaro)


def similarity(a: str, b: str) -> float:
    na, nb = normalise(a), normalise(b)
    if not na or not nb:
        return 0.0
    sorted_a, sorted_b = " ".join(sorted(na.split())), " ".join(sorted(nb.split()))
    ta, tb = set(na.split()), set(nb.split())
    containment = len(ta & tb) / min(len(ta), len(tb))
    return max(jaro_winkler(na, nb), jaro_winkler(sorted_a, sorted_b), 0.97 * containment if min(len(ta), len(tb)) >= 2 else 0)


@dataclass(frozen=True)
class SanctionsEntry:
    uid: str
    name: str
    list_name: str
    program: str
    entry_type: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class SanctionsMatch:
    entry: SanctionsEntry
    matched_name: str
    queried_name: str
    score: float


@dataclass
class SanctionsIndex:
    version: str
    entries: list[SanctionsEntry] = field(default_factory=list)

    def search(self, name: str, threshold: float = 0.88) -> list[SanctionsMatch]:
        out = []
        for e in self.entries:
            best = max(((similarity(name, n), n) for n in (e.name, *e.aliases)), key=lambda x: x[0])
            if best[0] >= threshold:
                out.append(SanctionsMatch(e, best[1], name, round(best[0], 4)))
        return sorted(out, key=lambda m: m.score, reverse=True)


def _clean(v: str) -> str:
    v = v.strip()
    return "" if v in ("-0-", "-0- ") else v


def parse_ofac(sdn_csv: str, alt_csv: str | None, version: str) -> SanctionsIndex:
    aliases: dict[str, list[str]] = {}
    if alt_csv:
        for row in csv.reader(io.StringIO(alt_csv)):
            if len(row) >= 4 and _clean(row[3]):
                aliases.setdefault(row[0].strip(), []).append(_clean(row[3]))
    entries = []
    for row in csv.reader(io.StringIO(sdn_csv)):
        if len(row) < 4 or not _clean(row[1]):
            continue
        uid = row[0].strip()
        entries.append(SanctionsEntry(uid=f"OFAC-{uid}", name=_clean(row[1]), list_name="OFAC SDN",
                                      program=_clean(row[3]), entry_type=_clean(row[2]) or "entity",
                                      aliases=tuple(aliases.get(uid, []))))
    return SanctionsIndex(version, entries)


class OfacFileProvider:
    """Reads lists downloaded by the scheduled refresh job (see ``download_ofac``)."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory

    def current(self) -> SanctionsIndex:
        sdn = (self._dir / "sdn.csv").read_text(encoding="latin-1")
        alt_path = self._dir / "alt.csv"
        alt = alt_path.read_text(encoding="latin-1") if alt_path.exists() else None
        version = (self._dir / "VERSION").read_text().strip() if (self._dir / "VERSION").exists() else "unknown"
        return parse_ofac(sdn, alt, version)


def download_ofac(directory: Path, timeout: float = 60.0) -> str:
    """Fetch the current SDN + alias lists over TLS and stamp a version."""
    import hashlib
    from datetime import datetime, timezone

    import httpx

    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for url, name in ((OFAC_SDN_URL, "sdn.csv"), (OFAC_ALT_URL, "alt.csv")):
            r = client.get(url)
            r.raise_for_status()
            (directory / name).write_bytes(r.content)
            digest.update(r.content)
    version = f"ofac-{datetime.now(timezone.utc):%Y%m%dT%H%M}-{digest.hexdigest()[:12]}"
    (directory / "VERSION").write_text(version)
    return version


class StaticSanctionsProvider:
    def __init__(self, index: SanctionsIndex) -> None:
        self._index = index

    def current(self) -> SanctionsIndex:
        return self._index
