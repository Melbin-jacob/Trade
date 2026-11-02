"""Append-only, hash-chained, signed event ledger.

Each tenant has its own chain. Entry *n* commits to entry *n-1* via
``prev_hash``, so any edit, deletion, insertion or reordering of history breaks
every subsequent hash. Each ``entry_hash`` is additionally signed with a
KMS/HSM-held key so an attacker with database write access cannot simply
recompute the chain.

The ledger is the system of record: shipment state is *derived* by replaying it
(see ``sentinel.kernel.shipment``), so the audit trail can never disagree with
the state the operators saw.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Protocol, Sequence
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from sentinel.core.canonical import canonical_json
from sentinel.ledger.signing import Signer, Verifier

GENESIS_HASH = "0" * 64
HASH_DOMAIN = b"trade-lane-sentinel/ledger/v1\x00"


class LedgerEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str
    sequence: int  # 1-based, gap-free per tenant
    entry_id: UUID
    recorded_at: datetime
    aggregate_type: str
    aggregate_id: str
    aggregate_version: int  # 1-based, gap-free per aggregate
    event_type: str
    actor: dict[str, str]
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str
    key_id: str
    signature: str  # hex

    def hashed_body(self) -> dict[str, Any]:
        return self.model_dump(exclude={"entry_hash", "key_id", "signature"})


def compute_entry_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(HASH_DOMAIN + canonical_json(body)).hexdigest()


# --------------------------------------------------------------------------- #
# Storage port
# --------------------------------------------------------------------------- #


class ConcurrencyConflict(RuntimeError):
    """The aggregate changed since it was read. Caller must reload and re-decide."""


class ChainHeadMoved(RuntimeError):
    """Another writer appended to the tenant chain. Safe to rebuild and retry."""


class LedgerStore(Protocol):
    def head(self, tenant_id: str) -> tuple[int, str]: ...

    def aggregate_version(self, tenant_id: str, aggregate_id: str) -> int: ...

    def append(self, tenant_id: str, expected_head_hash: str, entries: Sequence[LedgerEntry]) -> None:
        """Atomically append iff the chain head is still ``expected_head_hash``."""

    def read_aggregate(self, tenant_id: str, aggregate_id: str) -> list[LedgerEntry]: ...

    def read_chain(self, tenant_id: str, from_sequence: int = 1) -> list[LedgerEntry]: ...


class InMemoryLedgerStore:
    """Reference implementation. The Postgres adapter enforces the same rules
    with a head-row lock, UNIQUE(prev_hash) and UPDATE/DELETE-blocking triggers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._chains: dict[str, list[LedgerEntry]] = {}

    def head(self, tenant_id: str) -> tuple[int, str]:
        chain = self._chains.get(tenant_id, [])
        return (chain[-1].sequence, chain[-1].entry_hash) if chain else (0, GENESIS_HASH)

    def aggregate_version(self, tenant_id: str, aggregate_id: str) -> int:
        return max(
            (e.aggregate_version for e in self._chains.get(tenant_id, []) if e.aggregate_id == aggregate_id),
            default=0,
        )

    def append(self, tenant_id: str, expected_head_hash: str, entries: Sequence[LedgerEntry]) -> None:
        with self._lock:
            if self.head(tenant_id)[1] != expected_head_hash:
                raise ChainHeadMoved(tenant_id)
            for e in entries:
                if e.tenant_id != tenant_id:
                    raise ValueError("cross-tenant append rejected")
                current = self.aggregate_version(tenant_id, e.aggregate_id)
                pending = sum(
                    1 for p in entries[: entries.index(e)] if p.aggregate_id == e.aggregate_id
                )
                if e.aggregate_version != current + pending + 1:
                    raise ConcurrencyConflict(f"{e.aggregate_id} is at v{current}")
            # Store copies so callers cannot mutate history through references.
            self._chains.setdefault(tenant_id, []).extend(e.model_copy() for e in entries)

    def read_aggregate(self, tenant_id: str, aggregate_id: str) -> list[LedgerEntry]:
        return [e for e in self._chains.get(tenant_id, []) if e.aggregate_id == aggregate_id]

    def read_chain(self, tenant_id: str, from_sequence: int = 1) -> list[LedgerEntry]:
        return [e for e in self._chains.get(tenant_id, []) if e.sequence >= from_sequence]


# --------------------------------------------------------------------------- #
# Ledger service
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EventDraft:
    event_type: str
    payload: dict[str, Any]


class Ledger:
    def __init__(
        self,
        store: LedgerStore,
        signer: Signer,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        max_retries: int = 5,
    ) -> None:
        self._store = store
        self._signer = signer
        self._clock = clock
        self._max_retries = max_retries

    @property
    def store(self) -> LedgerStore:
        return self._store

    def append(
        self,
        *,
        tenant_id: str,
        aggregate_type: str,
        aggregate_id: str,
        expected_version: int,
        actor: dict[str, str],
        events: Iterable[EventDraft],
    ) -> list[LedgerEntry]:
        drafts = list(events)
        if not drafts:
            return []
        for _ in range(self._max_retries):
            if self._store.aggregate_version(tenant_id, aggregate_id) != expected_version:
                raise ConcurrencyConflict(f"{aggregate_id} is not at v{expected_version}")
            seq, prev = self._store.head(tenant_id)
            expected_head = prev
            built: list[LedgerEntry] = []
            for i, d in enumerate(drafts, start=1):
                body = {
                    "tenant_id": tenant_id,
                    "sequence": seq + i,
                    "entry_id": uuid4(),
                    "recorded_at": self._clock(),
                    "aggregate_type": aggregate_type,
                    "aggregate_id": aggregate_id,
                    "aggregate_version": expected_version + i,
                    "event_type": d.event_type,
                    "actor": dict(actor),
                    # Normalise to JSON primitives so the payload hashes identically
                    # after a round-trip through JSONB / an export file.
                    "payload": json.loads(canonical_json(d.payload)),
                    "prev_hash": prev,
                }
                entry_hash = compute_entry_hash(body)
                entry = LedgerEntry(
                    **body,
                    entry_hash=entry_hash,
                    key_id=self._signer.key_id,
                    signature=self._signer.sign(bytes.fromhex(entry_hash)).hex(),
                )
                built.append(entry)
                prev = entry_hash
            try:
                self._store.append(tenant_id, expected_head, built)
            except ChainHeadMoved:
                continue
            return built
        raise ChainHeadMoved(f"gave up after {self._max_retries} retries")


# --------------------------------------------------------------------------- #
# Verification (used by auditors and by a scheduled integrity job)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    entries_checked: int
    failed_sequence: int | None = None
    reason: str | None = None


def verify_chain(entries: Sequence[LedgerEntry], verifier: Verifier) -> VerificationResult:
    prev_hash = GENESIS_HASH
    expected_seq = 1
    for e in entries:
        def fail(reason: str) -> VerificationResult:
            return VerificationResult(False, e.sequence - 1, e.sequence, reason)

        if e.sequence != expected_seq:
            return fail(f"sequence gap: expected {expected_seq}")
        if e.prev_hash != prev_hash:
            return fail("prev_hash does not link to previous entry")
        if compute_entry_hash(e.hashed_body()) != e.entry_hash:
            return fail("entry contents do not match entry_hash")
        if not verifier.verify(e.key_id, bytes.fromhex(e.entry_hash), bytes.fromhex(e.signature)):
            return fail("signature invalid or unknown key")
        prev_hash = e.entry_hash
        expected_seq += 1
    return VerificationResult(True, len(entries))
