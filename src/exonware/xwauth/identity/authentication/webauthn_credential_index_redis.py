# exonware/xwauth.identity/authentication/webauthn_credential_index_redis.py
"""Redis-backed credential_id → user_id index for discoverable WebAuthn login across workers."""

from __future__ import annotations

from exonware.xwsystem import get_logger

logger = get_logger(__name__)


class RedisWebAuthnCredentialIndex:
    """
    Secondary index shared by all app workers (same pattern as commercial cloud IdPs).

    Keys: ``{prefix}{credential_id_b64}`` → ``user_id`` (plain strings, no TTL).
    Requires: ``pip install redis``.
    """

    def __init__(
        self,
        url: str,
        *,
        key_prefix: str = "xwauth:webauthn:cred:",
    ) -> None:
        try:
            import redis
        except ImportError as e:
            raise ImportError(
                "RedisWebAuthnCredentialIndex requires the 'redis' package: pip install redis"
            ) from e
        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = key_prefix

    def _key(self, credential_id_b64: str) -> str:
        return f"{self._prefix}{credential_id_b64}"

    def set_mapping(self, credential_id_b64: str, user_id: str) -> None:
        self._redis.set(self._key(credential_id_b64), user_id)

    def get_user(self, credential_id_b64: str) -> str | None:
        v = self._redis.get(self._key(credential_id_b64))
        return v if v else None

    def delete_mapping(self, credential_id_b64: str) -> None:
        self._redis.delete(self._key(credential_id_b64))

    def replace_all(self, pairs: list[tuple[str, str]]) -> None:
        """Drop all keys under ``prefix``, then write the given mappings (full rebuild)."""
        keys = list(self._redis.scan_iter(match=f"{self._prefix}*"))
        if keys:
            for i in range(0, len(keys), 500):
                self._redis.delete(*keys[i : i + 500])
        if not pairs:
            return
        pipe = self._redis.pipeline()
        for cid, uid in pairs:
            pipe.set(self._key(cid), uid)
        pipe.execute()
