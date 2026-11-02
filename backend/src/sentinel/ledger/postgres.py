"""Postgres adapter for the ledger store (see db/migrations/0001_tenant_ledger.sql).

Every operation runs in its own transaction, under the tenant's least-privilege
role and with ``app.tenant_id`` set for row-level security. The database itself
enforces append-only semantics and chain linkage; this adapter just maps its
errors onto the ledger's exception types.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Callable, Iterator, Sequence

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from sentinel.ledger.chain import (
    GENESIS_HASH,
    ChainHeadMoved,
    ConcurrencyConflict,
    LedgerEntry,
)

_TENANT_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
_COLUMNS = (
    "sequence", "entry_id", "recorded_at", "aggregate_type", "aggregate_id", "aggregate_version",
    "event_type", "actor", "payload", "prev_hash", "entry_hash", "key_id", "signature",
)


class PostgresLedgerStore:
    def __init__(self, connect: Callable[[], psycopg.Connection]) -> None:
        self._connect = connect

    @contextmanager
    def _tx(self, tenant_id: str) -> Iterator[psycopg.Cursor]:
        if not _TENANT_RE.match(tenant_id):
            raise ValueError("invalid tenant id")
        with self._connect() as conn, conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(f"tenant_{tenant_id}")))
            cur.execute(sql.SQL("SET LOCAL search_path TO {}").format(sql.Identifier(f"t_{tenant_id}")))
            cur.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
            yield cur

    def head(self, tenant_id: str) -> tuple[int, str]:
        with self._tx(tenant_id) as cur:
            row = cur.execute("SELECT sequence, entry_hash FROM chain_head").fetchone()
        return (row["sequence"], row["entry_hash"]) if row else (0, GENESIS_HASH)

    def aggregate_version(self, tenant_id: str, aggregate_id: str) -> int:
        with self._tx(tenant_id) as cur:
            row = cur.execute(
                "SELECT coalesce(max(aggregate_version), 0) AS v FROM ledger_entries WHERE aggregate_id = %s",
                (aggregate_id,),
            ).fetchone()
        return row["v"]

    def append(self, tenant_id: str, expected_head_hash: str, entries: Sequence[LedgerEntry]) -> None:
        if entries and entries[0].prev_hash != expected_head_hash:
            raise ValueError("first entry must link to expected head")
        insert = sql.SQL("INSERT INTO ledger_entries ({}) VALUES ({})").format(
            sql.SQL(", ").join(map(sql.Identifier, _COLUMNS)),
            sql.SQL(", ").join(sql.Placeholder() * len(_COLUMNS)),
        )
        try:
            with self._tx(tenant_id) as cur:
                for e in entries:
                    if e.tenant_id != tenant_id:
                        raise ValueError("cross-tenant append rejected")
                    row = e.model_dump()
                    row["actor"], row["payload"] = Jsonb(row["actor"]), Jsonb(row["payload"])
                    cur.execute(insert, [row[c] for c in _COLUMNS])
        except psycopg.errors.SerializationFailure as exc:
            raise ChainHeadMoved(str(exc)) from exc
        except psycopg.errors.UniqueViolation as exc:
            raise ConcurrencyConflict(str(exc)) from exc
        except psycopg.Error as exc:
            if exc.sqlstate == "SNT02":
                raise ConcurrencyConflict(str(exc)) from exc
            raise

    def _read(self, tenant_id: str, where: str, params: tuple) -> list[LedgerEntry]:
        with self._tx(tenant_id) as cur:
            rows = cur.execute(
                f"SELECT * FROM ledger_entries WHERE {where} ORDER BY sequence", params
            ).fetchall()
        return [LedgerEntry(**row) for row in rows]

    def read_aggregate(self, tenant_id: str, aggregate_id: str) -> list[LedgerEntry]:
        return self._read(tenant_id, "aggregate_id = %s", (aggregate_id,))

    def read_chain(self, tenant_id: str, from_sequence: int = 1) -> list[LedgerEntry]:
        return self._read(tenant_id, "sequence >= %s", (from_sequence,))
