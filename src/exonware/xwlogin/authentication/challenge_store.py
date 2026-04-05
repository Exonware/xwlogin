# exonware/xwlogin/authentication/challenge_store.py
"""
TTL WebAuthn challenge storage with lookup-then-invalidate-after-success semantics.

Matches common IdP behavior (e.g. Keycloak-style): a failed cryptographic verify does not
burn the challenge, so the client can retry within TTL unless policy dictates otherwise.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from exonware.xwsystem import get_logger

logger = get_logger(__name__)

Purpose = Literal["registration", "authentication"]


@dataclass
class StoredWebAuthnChallenge:
    """Server-held challenge metadata for one ceremony."""

    challenge_b64url: str
    purpose: Purpose
    user_id: str | None
    created_monotonic: float
    expires_at_monotonic: float


@runtime_checkable
class IWebAuthnChallengeStore(Protocol):
    """Pluggable challenge store (memory, Redis, etc.)."""

    def issue(
        self,
        *,
        challenge_b64url: str,
        purpose: Purpose,
        user_id: str | None,
        ttl_seconds: float | None = None,
    ) -> str:
        ...

    def lookup(
        self,
        handle: str,
        *,
        purpose: Purpose,
        user_id: str | None,
    ) -> str:
        ...

    def invalidate(self, handle: str) -> None:
        ...


class WebAuthnChallengeStore:
    """
    In-memory challenge store: TTL, validated lookup, explicit invalidate after success.
    """

    def __init__(self, default_ttl_seconds: float = 300.0) -> None:
        self._default_ttl = float(default_ttl_seconds)
        self._entries: dict[str, StoredWebAuthnChallenge] = {}
        self._lock = threading.Lock()

    def issue(
        self,
        *,
        challenge_b64url: str,
        purpose: Purpose,
        user_id: str | None,
        ttl_seconds: float | None = None,
    ) -> str:
        """Store challenge bytes (base64url) and return opaque handle for clients."""
        handle = secrets.token_urlsafe(24)
        now = time.monotonic()
        ttl = float(ttl_seconds if ttl_seconds is not None else self._default_ttl)
        entry = StoredWebAuthnChallenge(
            challenge_b64url=challenge_b64url,
            purpose=purpose,
            user_id=user_id,
            created_monotonic=now,
            expires_at_monotonic=now + ttl,
        )
        with self._lock:
            self._purge_unlocked()
            self._entries[handle] = entry
        return handle

    def lookup(
        self,
        handle: str,
        *,
        purpose: Purpose,
        user_id: str | None,
    ) -> str:
        """
        Return challenge for verification without removing it.
        Raises ValueError on missing, expired, or binding mismatch.
        """
        with self._lock:
            self._purge_unlocked()
            entry = self._entries.get(handle)
            if entry is None:
                raise ValueError("challenge_not_found")
            if time.monotonic() > entry.expires_at_monotonic:
                self._entries.pop(handle, None)
                raise ValueError("challenge_expired")
            if entry.purpose != purpose:
                raise ValueError("challenge_purpose_mismatch")
            if user_id is not None and entry.user_id is not None and entry.user_id != user_id:
                raise ValueError("challenge_user_mismatch")
            return entry.challenge_b64url

    def invalidate(self, handle: str) -> None:
        """Remove a challenge after successful ceremony (or explicit cleanup)."""
        with self._lock:
            self._entries.pop(handle, None)

    def consume(
        self,
        handle: str,
        *,
        purpose: Purpose,
        user_id: str | None,
    ) -> str:
        """
        Single-use read-and-delete (stricter UX). Prefer lookup+invalidate for WebAuthn flows.
        """
        with self._lock:
            self._purge_unlocked()
            entry = self._entries.get(handle)
            if entry is None:
                raise ValueError("challenge_not_found")
            if entry.purpose != purpose:
                raise ValueError("challenge_purpose_mismatch")
            if time.monotonic() > entry.expires_at_monotonic:
                self._entries.pop(handle, None)
                raise ValueError("challenge_expired")
            if user_id is not None and entry.user_id is not None and entry.user_id != user_id:
                raise ValueError("challenge_user_mismatch")
            challenge = entry.challenge_b64url
            self._entries.pop(handle, None)
        return challenge

    def _purge_unlocked(self) -> None:
        now = time.monotonic()
        dead = [h for h, e in self._entries.items() if now > e.expires_at_monotonic]
        for h in dead:
            self._entries.pop(h, None)
        if len(self._entries) > 10_000:
            logger.warning("WebAuthnChallengeStore exceeded 10k entries; clearing stale")
            self._entries = {
                h: e for h, e in self._entries.items() if now <= e.expires_at_monotonic
            }
