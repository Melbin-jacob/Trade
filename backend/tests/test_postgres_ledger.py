"""Integration tests against a real Postgres. Skipped unless SENTINEL_TEST_DSN is set.

    SENTINEL_TEST_DSN="postgresql://postgres@localhost/postgres" pytest tests/test_postgres_ledger.py
"""

import os
import uuid
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")
DSN = os.environ.get("SENTINEL_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SENTINEL_TEST_DSN not set")

from sentinel.ledger.chain import ConcurrencyConflict, EventDraft, Ledger, verify_chain  # noqa: E402
from sentinel.ledger.postgres import PostgresLedgerStore  # noqa: E402
from tests.test_shipment_lifecycle import SHP, ingest_all  # noqa: E402

MIGRATION = Path(__file__).resolve().parents[2] / "db" / "migrations" / "0001_tenant_ledger.sql"


@pytest.fixture(scope="module")
def tenants():
    a, b = f"acme_{uuid.uuid4().hex[:8]}", f"globex_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(MIGRATION.read_text())
        for t in (a, b):
            conn.execute("SELECT sentinel_admin.provision_tenant(%s, %s, %s)", (t, f"kms://{t}", "ca-central-1"))
    return a, b


@pytest.fixture
def pg_store():
    return PostgresLedgerStore(lambda: psycopg.connect(DSN))


def test_full_lifecycle_round_trips_and_verifies(tenants, pg_store, signer, keyring, clock, actors):
    from sentinel.kernel.service import ShipmentService

    tenant = tenants[0]
    svc = ShipmentService(Ledger(pg_store, signer, clock))
    # Re-scope the fixture principals to this tenant.
    a = {k: p.model_copy(update={"tenant_id": tenant}) for k, p in actors.items()}
    agg = ingest_all(svc, a, tenant=tenant)
    assert agg.version == 7
    # Hashes recomputed from rows read back out of JSONB/timestamptz still verify.
    assert verify_chain(pg_store.read_chain(tenant), keyring).ok


def test_database_rejects_update_delete_truncate(tenants, pg_store):
    tenant = tenants[0]
    for stmt in ("UPDATE ledger_entries SET event_type = 'x'", "DELETE FROM ledger_entries", "TRUNCATE ledger_entries"):
        with pytest.raises(psycopg.Error, match="append-only|permission denied"):
            with pg_store._tx(tenant) as cur:
                cur.execute(stmt)
    # Even the superuser/owner cannot bypass the triggers.
    with psycopg.connect(DSN) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f"DELETE FROM t_{tenant}.ledger_entries")


def test_stale_head_and_version_conflicts(tenants, pg_store, signer, clock):
    tenant = tenants[0]
    ledger = Ledger(pg_store, signer, clock)
    kwargs = dict(tenant_id=tenant, aggregate_type="shipment", aggregate_id="SHP-X",
                  actor={"id": "svc", "kind": "service"}, events=[EventDraft("t", {})])
    ledger.append(expected_version=0, **kwargs)
    with pytest.raises(ConcurrencyConflict):
        ledger.append(expected_version=0, **kwargs)


def test_tenant_role_cannot_read_other_tenant(tenants, pg_store):
    a, b = tenants
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with pg_store._tx(a) as cur:
            cur.execute(f"SELECT * FROM t_{b}.ledger_entries")


def test_rls_hides_rows_when_tenant_setting_missing(tenants):
    a, _ = tenants
    with psycopg.connect(DSN) as conn, conn.transaction():
        conn.execute(f'SET LOCAL ROLE "tenant_{a}"')
        n = conn.execute(f"SELECT count(*) FROM t_{a}.ledger_entries").fetchone()[0]
    assert n == 0
