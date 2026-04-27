#!/usr/bin/env python3
"""
Extension hooks for xwauth.
"""

from __future__ import annotations
from copy import deepcopy
from typing import Any, Protocol, runtime_checkable
from exonware.xwsystem import get_logger

logger = get_logger(__name__)


@runtime_checkable
class IAuthHook(Protocol):
    async def handle(self, event: str, payload: dict[str, Any]) -> None:
        ...


class AuthHookRegistry:
    """In-process extension registry with strict event dispatch boundary."""

    def __init__(self) -> None:
        self._hooks: list[IAuthHook] = []

    def register(self, hook: IAuthHook) -> None:
        if hook not in self._hooks:
            self._hooks.append(hook)

    async def emit(self, event: str, payload: dict[str, Any]) -> None:
        for hook in list(self._hooks):
            try:
                # Deep-copy payload so hooks cannot mutate shared auth state.
                await hook.handle(event=event, payload=deepcopy(payload))
            except Exception as exc:
                logger.warning(f"Auth hook failed for event '{event}': {exc}")
