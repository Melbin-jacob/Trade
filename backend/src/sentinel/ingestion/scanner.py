"""Malware scanning port. Fails closed: a scanner error means quarantine."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ScanResult:
    clean: bool
    signature: str | None = None


class ScannerUnavailable(RuntimeError):
    pass


class MalwareScanner(Protocol):
    def scan(self, data: bytes) -> ScanResult: ...


class ClamdScanner:
    """ClamAV daemon over its INSTREAM protocol (unix socket or TCP)."""

    def __init__(self, unix_socket: str | None = "/var/run/clamav/clamd.ctl",
                 host: str | None = None, port: int = 3310, timeout: float = 30.0) -> None:
        self._unix, self._host, self._port, self._timeout = unix_socket, host, port, timeout

    def _connect(self) -> socket.socket:
        if self._host:
            return socket.create_connection((self._host, self._port), timeout=self._timeout)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self._timeout)
        s.connect(self._unix)
        return s

    def scan(self, data: bytes) -> ScanResult:
        try:
            with self._connect() as s:
                s.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), 64 * 1024):
                    chunk = data[i : i + 64 * 1024]
                    s.sendall(struct.pack("!L", len(chunk)) + chunk)
                s.sendall(struct.pack("!L", 0))
                reply = s.recv(4096).rstrip(b"\0").decode(errors="replace")
        except OSError as exc:
            raise ScannerUnavailable(str(exc)) from exc
        if reply.endswith("OK"):
            return ScanResult(True)
        if reply.endswith("FOUND"):
            return ScanResult(False, reply.split(":", 1)[-1].removesuffix("FOUND").strip())
        raise ScannerUnavailable(f"unexpected clamd reply: {reply!r}")


class EicarOnlyScanner:
    """Test double: flags the EICAR test string, everything else is clean."""

    EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    def scan(self, data: bytes) -> ScanResult:
        return ScanResult(False, "Eicar-Test-Signature") if self.EICAR in data else ScanResult(True)
