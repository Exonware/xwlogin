#!/usr/bin/env python3
"""
Revoked JWT-ID (jti) store — pluggable backend contract + default in-memory
implementation + Redis implementation.

Problem this module exists to solve
-----------------------------------
Earlier versions of ``JWTTokenManager`` kept revoked jti values in a
process-local ``set[str]``. That has two production-breaking properties:

1. **Not shared across nodes.** Revoking a token on node A does nothing on
   node B — a revoked token still validates on any node that did not receive
   the revoke call. In any multi-worker / multi-pod deployment the revocation
   API is effectively a no-op.
2. **Does not survive restart.** All revocations are lost when the process
   exits. Tokens that were revoked minutes ago become valid again after a
   routine restart or redeploy.

**Fix** (root-cause per GUIDE_53):

- Declare a Protocol, :class:`IRevokedJtiStore`, so ``JWTTokenManager`` no
  longer hardcodes a storage backend.
- Provide :class:`InMemoryRevokedJtiStore` as the default. Same behaviour as
  before, explicitly documented as single-node only.
- Provide :class:`RedisRevokedJtiStore` so production deployments have a
  turnkey distributed option. Uses SETEX with TTL pruned to the token's own
  expiration time — no cleanup worker required.
- ``JWTTokenManager.__init__`` accepts a ``revoked_jti_store`` argument;
  injection point for any custom backend (DB, DynamoDB, etcd, …).

Anyone deploying across more than one process MUST swap the default for a
shared store. Failure to do so is the critical bug this module exists to
prevent.

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from exonware.xwsystem import get_logger

__all__ = [
    "IRevokedJtiStore",
    "InMemoryRevokedJtiStore",
    "RedisRevokedJtiStore",
]

logger = get_logger(__name__)


@runtime_checkable
class IRevokedJtiStore(Protocol):
    """Contract for a revoked-JWT-ID store.

    A ``jti`` value is the ``jti`` claim of the token being revoked. The store
    answers a single question: "has this ``jti`` been revoked and is the
    record still live?" Implementations may TTL-prune records after the
    underlying token would have expired anyway (saves storage without losing
    safety).

    Methods are synchronous because JTI lookup sits on the token-validation
    hot path. Implementations that need async I/O should provide their own
    non-Protocol subclass with coroutine methods and adapt.
    """

    def add(self, jti: str, *, exp_ts: int | None = None) -> None:
        """Record ``jti`` as revoked.

        Args:
            jti: JWT ID to revoke (the ``jti`` claim value).
            exp_ts: Optional original token ``exp`` (Unix timestamp, seconds).
                When provided, the store MAY auto-prune the revocation record
                once the underlying token would have naturally expired —
                keeping the store bounded without risking "un-revoke" while
                the token could still be used.
        """
        ...

    def contains(self, jti: str) -> bool:
        """Return ``True`` if ``jti`` is currently recorded as revoked."""
        ...


class InMemoryRevokedJtiStore:
    """Single-process, in-memory jti store. Default for dev / tests / single-node.

    ⚠️ NOT SAFE for multi-node production.

    - Revocations are NOT visible across processes. Revoking on node A leaves
      node B still accepting the token until it expires.
    - Revocations are LOST on restart. Any revocation older than the last
      process start is forgotten.

    Use :class:`RedisRevokedJtiStore` (or any other implementation of
    :class:`IRevokedJtiStore`) in production.
    """

    def __init__(self) -> None:
        # ``jti -> exp_ts | None``. When ``exp_ts`` is set, ``contains`` may
        # lazily drop records whose exp has passed so the set does not grow
        # without bound in long-running single-node processes.
        self._entries: dict[str, int | None] = {}

    def add(self, jti: str, *, exp_ts: int | None = None) -> None:
        if not jti:
            return
        self._entries[str(jti)] = int(exp_ts) if exp_ts is not None else None

    def contains(self, jti: str) -> bool:
        if not jti:
            return False
        key = str(jti)
        exp_ts = self._entries.get(key)
        if exp_ts is None:
            return key in self._entries
        # Lazy TTL prune: once the underlying token has expired, the
        # revocation record has no operational purpose.
        if int(time.time()) >= exp_ts:
            self._entries.pop(key, None)
            return False
        return True

    def __len__(self) -> int:  # pragma: no cover - introspection helper
        return len(self._entries)


class RedisRevokedJtiStore:
    """Redis-backed revoked-jti store.

    Stores each revoked ``jti`` as ``{prefix}{jti} -> "1"`` with a TTL equal
    to the token's remaining lifetime (``exp_ts - now``). Once Redis expires
    the key, the revocation record is gone — matching the underlying token's
    expiry. No cleanup worker required.

    Multi-node safe: every node reads the same Redis instance, so a revoke
    call on any node is visible immediately everywhere else.

    Restart safe: Redis persists keys across the Python process lifecycle;
    revocations survive routine restarts and deploys.

    Requires the optional ``redis`` package (``pip install redis``). The
    import is deferred to construction so this module is always importable
    even if ``redis`` is not installed — callers get a clear ``ImportError``
    only when they actually try to use the Redis backend.
    """

    _DEFAULT_PREFIX = "xwauth:revoked_jti:"
    _DEFAULT_TTL_SECONDS = 86_400  # 24h fallback when exp_ts is unknown

    def __init__(
        self,
        url: str,
        *,
        key_prefix: str = _DEFAULT_PREFIX,
        default_ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        if not url:
            raise ValueError("RedisRevokedJtiStore requires a non-empty Redis URL")
        try:
            import redis as _redis  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "RedisRevokedJtiStore requires the 'redis' package. "
                "Install via: pip install redis"
            ) from exc
        self._client = _redis.Redis.from_url(url, decode_responses=True)
        self._prefix = str(key_prefix or self._DEFAULT_PREFIX)
        self._default_ttl = int(default_ttl_seconds)
        if self._default_ttl < 1:
            raise ValueError("default_ttl_seconds must be >= 1")

    def _key(self, jti: str) -> str:
        return f"{self._prefix}{jti}"

    def add(self, jti: str, *, exp_ts: int | None = None) -> None:
        if not jti:
            return
        ttl = self._default_ttl
        if exp_ts is not None:
            # At least 1 second — Redis SETEX requires positive TTL.
            ttl = max(1, int(exp_ts) - int(time.time()))
        self._client.setex(self._key(str(jti)), ttl, "1")

    def contains(self, jti: str) -> bool:
        if not jti:
            return False
        # ``EXISTS`` returns 0 or 1; coerce to bool.
        return bool(self._client.exists(self._key(str(jti))))
