# exonware/xwlogin/webauthn_connector.py
"""WebAuthn challenge store, Redis credential index factories, and index rebuild (login-provider side).

Connector façade ``XWAuth`` and API hosts delegate here so WebAuthn persistence helpers live with
``exonware.xwlogin.authentication.*`` rather than deep imports from ``xwauth`` or app layers.
"""

from __future__ import annotations

from typing import Any

from exonware.xwsystem import get_logger

from exonware.xwlogin.config_connector import XWAuthConfig

logger = get_logger(__name__)

__all__ = [
    "create_webauthn_challenge_store",
    "create_webauthn_credential_index_redis",
    "rebuild_webauthn_credential_index",
]


def create_webauthn_challenge_store(config: XWAuthConfig) -> Any:
    """WebAuthn challenge store: in-memory (default) or Redis for multi-process HA."""
    from exonware.xwlogin.authentication.challenge_store import WebAuthnChallengeStore

    ttl = float(getattr(config, "webauthn_challenge_ttl_seconds", 300) or 300)
    backend = (getattr(config, "webauthn_challenge_backend", "memory") or "memory").strip().lower()
    if backend == "redis":
        url = getattr(config, "webauthn_redis_url", None)
        if not url:
            logger.warning(
                "webauthn_challenge_backend=redis but webauthn_redis_url is empty; using in-memory store"
            )
            return WebAuthnChallengeStore(default_ttl_seconds=ttl)
        from exonware.xwlogin.authentication.challenge_store_redis import (
            RedisWebAuthnChallengeStore,
        )

        prefix = (
            getattr(config, "webauthn_redis_key_prefix", "xwauth:webauthn:ch:")
            or "xwauth:webauthn:ch:"
        )
        return RedisWebAuthnChallengeStore(str(url), key_prefix=prefix, default_ttl_seconds=ttl)
    return WebAuthnChallengeStore(default_ttl_seconds=ttl)


def create_webauthn_credential_index_redis(config: XWAuthConfig) -> Any:
    """
    Optional Redis index for credential_id → user_id (discoverable login across workers).
    When ``webauthn_credential_index_backend=redis`` and ``webauthn_redis_url`` is set.
    """
    from exonware.xwlogin.authentication.webauthn_credential_index_redis import (
        RedisWebAuthnCredentialIndex,
    )

    backend = (
        getattr(config, "webauthn_credential_index_backend", "memory") or "memory"
    ).strip().lower()
    if backend != "redis":
        return None
    url = getattr(config, "webauthn_redis_url", None)
    if not url:
        logger.warning(
            "webauthn_credential_index_backend=redis but webauthn_redis_url is empty; "
            "credential index is memory-only per process"
        )
        return None
    prefix = (
        getattr(config, "webauthn_redis_credential_key_prefix", "xwauth:webauthn:cred:")
        or "xwauth:webauthn:cred:"
    )
    try:
        return RedisWebAuthnCredentialIndex(str(url), key_prefix=prefix)
    except ImportError:
        logger.warning(
            "webauthn_credential_index_backend=redis requires the 'redis' package; "
            "credential index is memory-only per process"
        )
        return None


async def rebuild_webauthn_credential_index(auth: Any) -> int:
    """Rebuild in-memory (and optional Redis) WebAuthn credential_id → user_id index from storage."""
    from exonware.xwlogin.authentication.webauthn_credential_index import (
        rebuild_webauthn_credential_index as _rebuild,
    )

    return await _rebuild(auth)
