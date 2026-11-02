import pytest

from sentinel.ledger.chain import (
    ConcurrencyConflict,
    EventDraft,
    InMemoryLedgerStore,
    Ledger,
    verify_chain,
)
from sentinel.ledger.signing import Ed25519Signer, KeyRing
from tests.conftest import TENANT


def _append(ledger, agg="SHP-1", version=0, n=1):
    return ledger.append(
        tenant_id=TENANT,
        aggregate_type="shipment",
        aggregate_id=agg,
        expected_version=version,
        actor={"id": "svc", "kind": "service"},
        events=[EventDraft("test.event", {"i": i}) for i in range(n)],
    )


def test_chain_links_and_verifies(ledger, store, keyring):
    _append(ledger, n=3)
    _append(ledger, agg="SHP-2")
    chain = store.read_chain(TENANT)
    assert [e.sequence for e in chain] == [1, 2, 3, 4]
    assert all(b.prev_hash == a.entry_hash for a, b in zip(chain, chain[1:]))
    assert verify_chain(chain, keyring).ok


def test_tampered_payload_is_detected(ledger, store, keyring):
    _append(ledger, n=3)
    chain = store.read_chain(TENANT)
    chain[1] = chain[1].model_copy(update={"payload": {"i": 999}})
    result = verify_chain(chain, keyring)
    assert not result.ok and result.failed_sequence == 2


def test_deleted_entry_is_detected(ledger, store, keyring):
    _append(ledger, n=3)
    chain = store.read_chain(TENANT)
    del chain[1]
    assert not verify_chain(chain, keyring).ok


def test_recomputed_chain_without_signing_key_is_detected(ledger, store, keyring):
    """An attacker with DB write access can recompute hashes but cannot sign."""
    _append(ledger, n=2)
    forged_store = InMemoryLedgerStore()
    forger = Ledger(forged_store, Ed25519Signer("ledger-key-2026-11"))  # same key id, different key
    forger.append(
        tenant_id=TENANT, aggregate_type="shipment", aggregate_id="SHP-1", expected_version=0,
        actor={"id": "x", "kind": "human"}, events=[EventDraft("test.event", {"i": 0})],
    )
    assert not verify_chain(forged_store.read_chain(TENANT), keyring).ok


def test_optimistic_concurrency(ledger):
    _append(ledger)
    with pytest.raises(ConcurrencyConflict):
        _append(ledger, version=0)


def test_tenants_have_independent_chains(ledger, store):
    _append(ledger)
    ledger.append(
        tenant_id="globex_freight", aggregate_type="shipment", aggregate_id="SHP-1",
        expected_version=0, actor={"id": "svc", "kind": "service"}, events=[EventDraft("x", {})],
    )
    assert len(store.read_chain(TENANT)) == 1
    assert len(store.read_chain("globex_freight")) == 1
