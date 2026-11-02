"""Customs gateway adapters."""

from __future__ import annotations

import os
from pathlib import Path


class FileDropCustomsGateway:
    """Writes approved declarations to an outbox folder picked up by the licensed
    customs broker / EDI software (a common integration for CBSA CARM, US ACE, EU ICS2).
    Files are written atomically and never overwritten."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)

    def submit(self, *, system: str, payload: bytes, shipment_id: str) -> str:
        import hashlib

        name = f"{system}_{shipment_id}_{hashlib.sha256(payload).hexdigest()[:16]}.json"
        target = self._dir / name
        if target.exists():
            return name
        tmp = self._dir / f".{name}.tmp"
        with open(tmp, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(target)
        return name
