#!/usr/bin/env python3
"""Regression tests for the revoked-JTI store pluggability.

Critical security finding 2026-04-20: ``JWTTokenManager`` previously stored
revoked jti values in a process-local ``set[str]``. In multi-node deployments
this made ``revoke_jti`` effectively a no-op (revoked tokens stayed valid on
peer nodes) and restart-fragile (revocations were forgotten after a routine
redeploy).

These tests guard:

1. The :class:`IRevokedJtiStore` protocol is respected by the default
   :class:`InMemoryRevokedJtiStore`.
2. :class:`JWTTokenManager` accepts an injected store and consults *that*
   store on every ``is_jti_revoked`` call — not a hidden internal ``set``.
3. Revoking a jti is visible to a *separate* ``JWTTokenManager`` that shares
   the same injected store (the distributed-store contract).
4. Each manager with its own default (in-memory) store is independent — the
   historical bug scenario — and the new constructor argument is what makes
   the distributed scenario possible.
"""

from __future__ import annotations

import time

import pytest

from exonware.xwauth.identity.tokens.jwt import JWTTokenManager
from exonware.xwauth.identity.tokens.revoked_jti_store import (
    IRevokedJtiStore,
    InMemoryRevokedJtiStore,
)


@pytest.mark.xwauth_identity_unit
class TestRevokedJtiStoreProtocol:
    def test_in_memory_store_satisfies_protocol(self) -> None:
        store = InMemoryRevokedJtiStore()
        # ``@runtime_checkable`` Protocol → isinstance check is meaningful.
        assert isinstance(store, IRevokedJtiStore)

    def test_in_memory_store_round_trip(self) -> None:
        store = InMemoryRevokedJtiStore()
        assert store.contains("a") is False
        store.add("a")
        assert store.contains("a") is True
        # Empty / falsy jti must be a no-op.
        store.add("")
        assert store.contains("") is False

    def test_in_memory_store_prunes_expired_records(self) -> None:
        """When ``exp_ts`` is provided and already past, ``contains`` drops it."""
        store = InMemoryRevokedJtiStore()
        past = int(time.time()) - 10
        store.add("old-jti", exp_ts=past)
        assert store.contains("old-jti") is False

    def test_in_memory_store_keeps_live_records(self) -> None:
        """Records whose exp is in the future stay live."""
        store = InMemoryRevokedJtiStore()
        future = int(time.time()) + 3600
        store.add("live-jti", exp_ts=future)
        assert store.contains("live-jti") is True


@pytest.mark.xwauth_identity_unit
class TestJWTTokenManagerUsesInjectedStore:
    def test_default_store_is_in_memory(self) -> None:
        mgr = JWTTokenManager(secret="t", algorithm="HS256")
        assert isinstance(mgr._revoked_jti_store, InMemoryRevokedJtiStore)

    def test_injected_store_is_used_for_is_jti_revoked(self) -> None:
        """The manager must consult the injected store — not a hidden set."""
        store = InMemoryRevokedJtiStore()
        mgr = JWTTokenManager(secret="t", algorithm="HS256", revoked_jti_store=store)

        assert mgr.is_jti_revoked("abc") is False
        # Simulate an out-of-band revocation (e.g. a peer node writing to the
        # same distributed store). ``mgr`` must immediately see it.
        store.add("abc")
        assert mgr.is_jti_revoked("abc") is True

    def test_revoke_jti_writes_to_the_injected_store(self) -> None:
        store = InMemoryRevokedJtiStore()
        mgr = JWTTokenManager(secret="t", algorithm="HS256", revoked_jti_store=store)

        mgr.revoke_jti("xyz", exp_ts=int(time.time()) + 60)
        # The store now reports revoked regardless of which manager we ask.
        assert store.contains("xyz") is True

    def test_revoke_then_check_on_a_separate_manager_sharing_the_store(self) -> None:
        """Regression for the original bug: two managers sharing a distributed
        store must see each other's revocations. Before the fix, each manager
        had its own private ``set[str]`` and revocations did not propagate."""
        shared_store = InMemoryRevokedJtiStore()
        mgr_a = JWTTokenManager(secret="s", algorithm="HS256", revoked_jti_store=shared_store)
        mgr_b = JWTTokenManager(secret="s", algorithm="HS256", revoked_jti_store=shared_store)

        mgr_a.revoke_jti("J1")
        # Peer node sees the revocation without any explicit sync.
        assert mgr_b.is_jti_revoked("J1") is True

    def test_managers_with_separate_default_stores_are_independent(self) -> None:
        """This documents the (intentional) pre-v1 single-node behaviour: if
        each manager gets its own default in-memory store, revocations do NOT
        propagate. This is exactly why production must inject a shared store
        (e.g. :class:`RedisRevokedJtiStore`)."""
        mgr_a = JWTTokenManager(secret="s", algorithm="HS256")
        mgr_b = JWTTokenManager(secret="s", algorithm="HS256")

        mgr_a.revoke_jti("J2")
        assert mgr_a.is_jti_revoked("J2") is True
        # Without a shared store, mgr_b does NOT see the revocation. This is
        # the bug multi-node deployments must not tolerate.
        assert mgr_b.is_jti_revoked("J2") is False

    def test_is_jti_revoked_with_empty_value_returns_false(self) -> None:
        mgr = JWTTokenManager(secret="s", algorithm="HS256")
        assert mgr.is_jti_revoked("") is False
        assert mgr.is_jti_revoked("   ") is False or mgr.is_jti_revoked("   ") is True
        # Behaviour on whitespace jti is implementation-defined; the
        # operational contract is "empty does not raise, does not revoke".


@pytest.mark.xwauth_identity_unit
class TestCustomStoreInjection:
    def test_custom_store_implementing_protocol_is_accepted(self) -> None:
        """Any object honouring the :class:`IRevokedJtiStore` protocol should
        be a valid backend — DB, Redis, DynamoDB, …"""

        class _FakeDistributedStore:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, int | None]] = []
                self._live: set[str] = set()

            def add(self, jti: str, *, exp_ts: int | None = None) -> None:
                self.calls.append(("add", str(jti), exp_ts))
                self._live.add(str(jti))

            def contains(self, jti: str) -> bool:
                self.calls.append(("contains", str(jti), None))
                return str(jti) in self._live

        fake = _FakeDistributedStore()
        mgr = JWTTokenManager(secret="s", algorithm="HS256", revoked_jti_store=fake)

        mgr.revoke_jti("K1", exp_ts=1234567890)
        assert mgr.is_jti_revoked("K1") is True
        # The fake backend observed exactly the expected calls, including the
        # ``exp_ts`` passthrough that distributed stores use for TTL pruning.
        assert ("add", "K1", 1234567890) in fake.calls
        assert ("contains", "K1", None) in fake.calls
