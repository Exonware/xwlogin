#!/usr/bin/env python3
"""
xwauth storage provider backed by ``exonware-xwjson``.

This is the preferred built-in persistence backend for xwauth when no external
storage system is configured. It satisfies ``IStorageProvider`` so callers can
swap it for xwstorage-, SQL-, or redis-backed providers without touching
handlers or business logic.

Usage::

    from exonware.xwauth.identity.storage.xwjson_provider import XWJSONStorageProvider

    # In-memory only (tests, ephemeral processes):
    storage = XWJSONStorageProvider()

    # Persistent — state is serialized to an xwjson document on every write:
    storage = XWJSONStorageProvider(".data/xwauth.xwjson")
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from exonware.xwsystem import get_logger

from .xwstorage_provider import XWStorageProvider

logger = get_logger(__name__)


class _XWJSONBackend:
    """
    Minimal async read/write backend persisting a single state dict via xwjson.

    The shape matches what ``XWStorageProvider`` expects from its ``_backend``
    attribute: ``await read(key)`` → ``Any | None`` and ``await write(key, value)``.
    Swap this class for any other async adapter (redis, S3, …) without touching
    the xwauth storage provider.
    """

    def __init__(self, file_path: str | Path | None = None) -> None:
        self._file_path: Path | None = Path(file_path) if file_path else None
        self._memory: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        # Imported lazily so the xwauth package doesn't hard-require xwjson at
        # import time; callers that never construct this class never pay the cost.
        from exonware.xwjson import XWJSONSerializer

        # XWJSONSerializer exposes awaitable save_file_async / load_file_async;
        # use it directly so the coroutine gets awaited properly (the XWJSON
        # facade's save/load turned out to be coroutines despite a sync signature).
        self._serializer = XWJSONSerializer(enable_cache=True)

    async def read(self, key: str) -> Any | None:
        if self._file_path is not None and self._file_path.exists():
            try:
                async with self._lock:
                    doc = await self._serializer.load_file_async(self._file_path)
                if isinstance(doc, dict):
                    return doc.get(key)
                return None
            except Exception as e:  # noqa: BLE001 — best-effort persistence
                logger.warning(
                    "xwjson read failed (%s): %s; falling back to in-memory state",
                    self._file_path,
                    e,
                )
        return self._memory.get(key)

    async def write(self, key: str, value: Any) -> None:
        # Always update memory first so in-process state is consistent even when
        # the persist step fails (e.g. read-only disk, permission issues).
        self._memory[key] = value
        if self._file_path is None:
            return
        try:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            async with self._lock:
                doc: dict[str, Any] = {}
                if self._file_path.exists():
                    try:
                        loaded = await self._serializer.load_file_async(self._file_path)
                        if isinstance(loaded, dict):
                            doc = loaded
                    except Exception:
                        # Existing file unreadable — overwrite it cleanly rather than
                        # corrupting or bailing on every subsequent write.
                        doc = {}
                doc[key] = value
                await self._serializer.save_file_async(doc, self._file_path)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "xwjson write failed (%s): %s; state kept in memory",
                self._file_path,
                e,
            )


class XWJSONStorageProvider(XWStorageProvider):
    """
    ``IStorageProvider`` backed by ``exonware-xwjson``.

    Drop-in replacement for ``MockStorageProvider`` with optional durable
    persistence. In-memory mode (``file_path=None``) stores everything in a
    private dict — matches MockStorageProvider semantics. Persistent mode
    serializes the full state dict to a single xwjson document on every write.

    Use ``XWAuthConfig(storage_provider=XWJSONStorageProvider(...))`` or pass
    an instance via the ``storage`` kwarg on ``XWAuth(...)`` to opt in.
    """

    def __init__(self, file_path: str | Path | None = None) -> None:
        super().__init__(_XWJSONBackend(file_path))
        self._file_path = Path(file_path) if file_path else None

    @property
    def file_path(self) -> Path | None:
        """Path to the xwjson document on disk, or ``None`` for in-memory mode."""
        return self._file_path
