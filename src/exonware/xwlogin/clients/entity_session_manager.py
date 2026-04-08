#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/clients/entity_session_manager.py
Entity Session Manager
Generic session management for multiple entities (agencies, accounts, users, etc.).
Handles both single and multi-entity session scenarios.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 07-Jan-2025
"""

import requests
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class EntitySessionManager:
    """
    Generic session manager for multiple entities.
    Handles:
    - Single session (when only one entity exists)
    - Multi-entity sessions (agencies, accounts, users, etc.)
    - Session creation and management
    - Session authentication state
    Works with any entity type - not hardcoded to "agencies".
    """

    def __init__(self, entities: dict[str, dict[str, Any]]):
        """
        Initialize entity session manager.
        Args:
            entities: Dictionary of entities (e.g., agencies, accounts, users)
        """
        self._entities = entities
    @property

    def entities(self) -> dict[str, dict[str, Any]]:
        """Get entities dictionary."""
        return self._entities
    @property

    def session(self) -> Optional[Any]:
        """
        Get default session from first available entity.
        Generic property that works with any entity type.
        Returns None if no entities exist.
        """
        if self._entities:
            entity_name = list(self._entities.keys())[0]
            if entity_name in self._entities:
                return self._entities[entity_name].get('session')
        return None

    def get_entity_session(self, entity_name: str) -> Optional[Any]:
        """
        Get session for a specific entity.
        Args:
            entity_name: Name of the entity
        Returns:
            Session object or None
        """
        if entity_name in self._entities:
            return self._entities[entity_name].get('session')
        return None

    def set_entity(self, entity_name: str, entity_data: dict[str, Any]) -> None:
        """
        Set entity data.
        Args:
            entity_name: Name of the entity
            entity_data: Entity data dictionary
        """
        self._entities[entity_name] = entity_data

    def get_entity(self, entity_name: str) -> Optional[dict[str, Any]]:
        """
        Get entity data.
        Args:
            entity_name: Name of the entity
        Returns:
            Entity data dictionary or None
        """
        return self._entities.get(entity_name)

    def create_session(
        self,
        entity_name: str,
        session_factory: Optional[callable] = None
    ) -> Optional[Any]:
        """
        Create a session for an entity.
        Args:
            entity_name: Name of the entity
            session_factory: Optional factory function to create session (default: requests.Session)
        Returns:
            Created session object
        """
        if entity_name not in self._entities:
            logger.warning(
                f"Entity '{entity_name}' not found, cannot create session (manager has keys: %s)",
                list(self._entities.keys()),
            )
            return None
        # Use provided factory or default to requests.Session
        if session_factory is None:
            session = requests.Session()
        else:
            session = session_factory()
        # Store session in entity
        self._entities[entity_name]['session'] = session
        # Set entity name in session cookies for identification
        if hasattr(session, 'cookies'):
            session.cookies.set("entity_name", entity_name, domain="exonware.com")
        logger.debug(f"Created session for entity: {entity_name}")
        return session

    def start_all_sessions(self, session_factory: Optional[callable] = None) -> None:
        """
        Start sessions for all entities.
        Args:
            session_factory: Optional factory function to create sessions
        """
        for entity_name in self._entities.keys():
            try:
                self.create_session(entity_name, session_factory)
                logger.debug(f"Started session for entity: {entity_name}")
            except Exception as e:
                logger.warning(f"Failed to start session for entity '{entity_name}': {e}")

    def get_entity_from_session(self, session: Any) -> Optional[str]:
        """
        Get entity name from session.
        Args:
            session: Session object
        Returns:
            Entity name or None
        """
        if hasattr(session, 'cookies'):
            return session.cookies.get('entity_name')
        # Fallback: search entities for this session
        for entity_name, entity_data in self._entities.items():
            if entity_data.get('session') is session:
                return entity_name
        return None

    def is_entity_authenticated(self, entity_name: str) -> bool:
        """
        Check if an entity is authenticated.
        Args:
            entity_name: Name of the entity
        Returns:
            True if authenticated, False otherwise
        """
        if entity_name not in self._entities:
            return False
        entity = self._entities[entity_name]
        return entity.get('logged_in', False) or bool(
            entity.get('headers_authorization') and entity.get('headers_cookie')
        )

    def get_authenticated_entities(self) -> list[str]:
        """
        Get list of authenticated entity names.
        Returns:
            List of authenticated entity names
        """
        return [
            entity_name 
            for entity_name in self._entities.keys()
            if self.is_entity_authenticated(entity_name)
        ]
