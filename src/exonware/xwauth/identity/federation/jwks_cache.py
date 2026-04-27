#!/usr/bin/env python3
"""
In-memory JWKS document cache with TTL (per jwks_uri).

Reduces load on upstream IdPs and mirrors common OSS broker behavior during key rotation windows.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from exonware.xwauth.identity.federation.errors import FederationUpstreamCode, XWFederationError


class JwksDocumentCache:
    """Async-safe TTL cache for JWKS JSON documents keyed by URI."""

    def __init__(
        self,
        ttl_seconds: float = 3600.0,
        *,
        negative_cache_ttl_seconds: float = 20.0,
    ) -> None:
        self._ttl = max(0.0, float(ttl_seconds))
        self._negative_ttl = max(0.0, float(negative_cache_ttl_seconds))
        self._entries: dict[str, tuple[float, dict[str, Any]]] = {}
        self._fail_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def invalidate(self, jwks_uri: str) -> None:
        """Drop cached JWKS (and negative-cache state) for *jwks_uri*."""
        async with self._lock:
            self._entries.pop(jwks_uri, None)
            self._fail_until.pop(jwks_uri, None)

    async def get_or_fetch(
        self,
        jwks_uri: str,
        http_get: Any,
        fetch_jwks_fn: Any,
    ) -> dict[str, Any]:
        """
        Return cached JWKS for *jwks_uri* if fresh; otherwise call
        ``await fetch_jwks_fn(jwks_uri, http_get)`` and store the result.
        """
        now = time.monotonic()
        async with self._lock:
            fu = self._fail_until.get(jwks_uri)
            if fu is not None and now < fu:
                raise XWFederationError(
                    "JWKS temporarily unavailable after a recent fetch failure",
                    upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
                )

        if self._ttl <= 0:
            return await self._fetch_and_store(jwks_uri, http_get, fetch_jwks_fn)

        async with self._lock:
            now = time.monotonic()
            hit = self._entries.get(jwks_uri)
            if hit is not None and (now - hit[0]) < self._ttl:
                return hit[1]

        return await self._fetch_and_store(jwks_uri, http_get, fetch_jwks_fn)

    async def _fetch_and_store(
        self,
        jwks_uri: str,
        http_get: Any,
        fetch_jwks_fn: Any,
    ) -> dict[str, Any]:
        try:
            doc = await fetch_jwks_fn(jwks_uri, http_get)
        except Exception:
            if self._negative_ttl > 0:
                async with self._lock:
                    self._fail_until[jwks_uri] = time.monotonic() + self._negative_ttl
            raise
        async with self._lock:
            self._fail_until.pop(jwks_uri, None)
            if self._ttl > 0:
                self._entries[jwks_uri] = (time.monotonic(), doc)
        return doc

    def clear(self) -> None:
        """Drop all cached entries (tests / rotation drills)."""
        self._entries.clear()
        self._fail_until.clear()
