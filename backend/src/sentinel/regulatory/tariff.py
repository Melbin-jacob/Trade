"""Tariff / HS-code verification against the destination's customs schedule."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Protocol

from sentinel.regulatory.resilience import CircuitBreaker


@dataclass(frozen=True)
class TariffLine:
    country: str
    hs_code: str
    description: str
    mfn_rate: str


class TariffProvider(Protocol):
    def lookup(self, hs_code: str, country: str) -> TariffLine | None: ...


class StaticTariffSchedule:
    """CSV columns: country,hs_code,description,mfn_rate. Matches the longest prefix (down to the 4-digit heading)."""

    def __init__(self, rows: list[TariffLine]) -> None:
        self._rows = {(r.country, r.hs_code): r for r in rows}

    @classmethod
    def from_csv(cls, text: str) -> "StaticTariffSchedule":
        return cls([TariffLine(r["country"], r["hs_code"], r["description"], r["mfn_rate"])
                    for r in csv.DictReader(io.StringIO(text))])

    def lookup(self, hs_code: str, country: str) -> TariffLine | None:
        for n in range(len(hs_code), 3, -2):  # subheading -> 4-digit heading
            if (hit := self._rows.get((country, hs_code[:n]))) is not None:
                return hit
        return None


class HttpTariffProvider:
    """Generic JSON tariff API (e.g. a national customs tariff service or a vendor).

    Expects ``GET {base_url}/tariff/{country}/{hs_code}`` -> 200 with
    ``{"hs_code", "description", "mfn_rate"}`` or 404.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0,
                 breaker: CircuitBreaker | None = None) -> None:
        import httpx

        if not base_url.startswith("https://"):
            raise ValueError("tariff API must use HTTPS")
        self._client = httpx.Client(base_url=base_url, timeout=timeout,
                                    headers={"Authorization": f"Bearer {api_key}"})
        self._breaker = breaker or CircuitBreaker("tariff-api")

    def lookup(self, hs_code: str, country: str) -> TariffLine | None:
        def call():
            r = self._client.get(f"/tariff/{country}/{hs_code}")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            d = r.json()
            return TariffLine(country, str(d["hs_code"]), str(d["description"]), str(d["mfn_rate"]))

        return self._breaker.call(call)
