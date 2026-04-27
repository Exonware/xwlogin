#!/usr/bin/env python3
"""
#exonware/xwauth-identity/src/exonware/xwauth/identity/clients/entity_session_manager.py
Entity session manager for multi-tenant OAuth client scenarios.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Optional

from exonware.xwsystem import get_logger

logger = get_logger(__name__)

try:
    import requests
except ImportError:  # pragma: no cover - depends on optional dependency availability
    requests = None


class _FallbackCookieJar:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def set(self, key: str, value: str, domain: str | None = None) -> None:
        self._values[key] = value

    def get(self, key: str) -> str | None:
        return self._values.get(key)


class _FallbackSession:
    """Lightweight session shim used when requests is unavailable."""

    def __init__(self) -> None:
        self.cookies = _FallbackCookieJar()


class EntitySessionManager:
    """Session bookkeeping for multiple entities (accounts, agencies, users, etc.)."""

    def __init__(self, entities: dict[str, dict[str, Any]]):
        self._entities = entities

    @property
    def entities(self) -> dict[str, dict[str, Any]]:
        return self._entities

    @property
    def session(self) -> Optional[Any]:
        if self._entities:
            entity_name = list(self._entities.keys())[0]
            if entity_name in self._entities:
                return self._entities[entity_name].get("session")
        return None

    def get_entity_session(self, entity_name: str) -> Optional[Any]:
        if entity_name in self._entities:
            return self._entities[entity_name].get("session")
        return None

    def set_entity(self, entity_name: str, entity_data: dict[str, Any]) -> None:
        self._entities[entity_name] = entity_data

    def get_entity(self, entity_name: str) -> Optional[dict[str, Any]]:
        return self._entities.get(entity_name)

    def create_session(
        self,
        entity_name: str,
        session_factory: Optional[Callable[[], Any]] = None,
    ) -> Optional[Any]:
        if entity_name not in self._entities:
            logger.warning(
                "Entity %r not found, cannot create session (manager has keys: %s)",
                entity_name,
                list(self._entities.keys()),
            )
            return None
        if session_factory is None:
            session = requests.Session() if requests is not None else _FallbackSession()
        else:
            session = session_factory()
        self._entities[entity_name]["session"] = session
        if hasattr(session, "cookies"):
            session.cookies.set("entity_name", entity_name, domain="exonware.com")
        logger.debug("Created session for entity: %s", entity_name)
        return session

    def start_all_sessions(
        self, session_factory: Optional[Callable[[], Any]] = None
    ) -> None:
        for entity_name in self._entities.keys():
            try:
                self.create_session(entity_name, session_factory)
                logger.debug("Started session for entity: %s", entity_name)
            except Exception as e:
                logger.warning(
                    "Failed to start session for entity %r: %s", entity_name, e
                )

    def get_entity_from_session(self, session: Any) -> Optional[str]:
        if hasattr(session, "cookies"):
            val = session.cookies.get("entity_name")
            if val is not None:
                return str(val)
        for entity_name, entity_data in self._entities.items():
            if entity_data.get("session") is session:
                return entity_name
        return None

    def is_entity_authenticated(self, entity_name: str) -> bool:
        if entity_name not in self._entities:
            return False
        entity = self._entities[entity_name]
        return entity.get("logged_in", False) or bool(
            entity.get("headers_authorization") and entity.get("headers_cookie")
        )

    def get_authenticated_entities(self) -> list[str]:
        return [
            entity_name
            for entity_name in self._entities.keys()
            if self.is_entity_authenticated(entity_name)
        ]
