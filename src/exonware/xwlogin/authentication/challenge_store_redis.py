# exonware/xwlogin/authentication/challenge_store_redis.py
"""Redis-backed WebAuthn challenge store for multi-process / HA deployments."""

from __future__ import annotations

import secrets
from exonware.xwsystem import get_logger
from exonware.xwsystem.io.errors import SerializationError
from exonware.xwsystem.io.serialization.formats.text import json as xw_json

from .challenge_store import Purpose

logger = get_logger(__name__)


class RedisWebAuthnChallengeStore:
    """
    Challenge store using Redis SETEX + GET + DEL.
    Optional dependency: ``redis`` (pip install redis).
    """

    def __init__(
        self,
        url: str,
        *,
        key_prefix: str = "xwauth:webauthn:ch:",
        default_ttl_seconds: float = 300.0,
    ) -> None:
        try:
            import redis
        except ImportError as e:
            raise ImportError(
                "RedisWebAuthnChallengeStore requires the 'redis' package: pip install redis"
            ) from e
        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = key_prefix
        self._default_ttl = float(default_ttl_seconds)

    def _key(self, handle: str) -> str:
        return f"{self._prefix}{handle}"

    def issue(
        self,
        *,
        challenge_b64url: str,
        purpose: Purpose,
        user_id: str | None,
        ttl_seconds: float | None = None,
    ) -> str:
        handle = secrets.token_urlsafe(24)
        ttl = int(ttl_seconds if ttl_seconds is not None else self._default_ttl)
        if ttl < 1:
            ttl = 1
        payload = xw_json.dumps(
            {"c": challenge_b64url, "p": purpose, "u": user_id},
            separators=(",", ":"),
        )
        self._redis.setex(self._key(handle), ttl, payload)
        return handle

    def lookup(
        self,
        handle: str,
        *,
        purpose: Purpose,
        user_id: str | None,
    ) -> str:
        raw = self._redis.get(self._key(handle))
        if not raw:
            raise ValueError("challenge_not_found")
        try:
            data = xw_json.loads(raw)
        except (xw_json.JSONDecodeError, SerializationError) as e:
            logger.warning("Corrupt webauthn challenge payload for handle prefix")
            raise ValueError("challenge_not_found") from e
        if data.get("p") != purpose:
            raise ValueError("challenge_purpose_mismatch")
        u = data.get("u")
        if user_id is not None and u is not None and u != user_id:
            raise ValueError("challenge_user_mismatch")
        c = data.get("c")
        if not c or not isinstance(c, str):
            raise ValueError("challenge_not_found")
        return c

    def invalidate(self, handle: str) -> None:
        self._redis.delete(self._key(handle))

    def consume(
        self,
        handle: str,
        *,
        purpose: Purpose,
        user_id: str | None,
    ) -> str:
        ch = self.lookup(handle, purpose=purpose, user_id=user_id)
        self.invalidate(handle)
        return ch
