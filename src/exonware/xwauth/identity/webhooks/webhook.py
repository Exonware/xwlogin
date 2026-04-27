#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/webhooks/webhook.py
Webhook Model
Webhook entity model that extends xwsystem.shared.XWObject for consistent
identity, timestamps, and serialization across the eXonware ecosystem.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from __future__ import annotations
from typing import Any
from datetime import datetime
from exonware.xwsystem import get_logger
from exonware.xwsystem.shared import XWObject
logger = get_logger(__name__)


class Webhook(XWObject):
    """
    Webhook entity model.
    Extends xwsystem.shared.XWObject for consistent identity management,
    timestamps, and serialization.
    Provides:
    - Identity: id (primary identifier), uid (UUID from XWObject)
    - Timestamps: created_at, updated_at
    - Serialization: to_dict(), to_native(), from_dict()
    - Storage: save(), load() (abstract - implement in subclasses or use storage adapter)
    """

    def __init__(
        self,
        id: str | None = None,
        url: str | None = None,
        events: list[str] | None = None,
        secret: str | None = None,
        active: bool = True,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ):
        """
        Initialize webhook.
        Args:
            id: Optional webhook identifier (if not provided, uses XWObject.uid)
            url: Webhook URL endpoint
            events: List of events to subscribe to
            secret: Webhook secret for HMAC signature
            active: Whether webhook is active
            created_at: Creation timestamp (defaults to now)
            updated_at: Last update timestamp (defaults to now)
        """
        super().__init__(object_id=id)
        # Use provided id or fall back to uid from XWObject
        self._id = id or self.uid
        # Webhook-specific fields
        self._url = url
        self._events = events or []
        self._secret = secret
        self._active = active
        # Timestamps
        now = datetime.now()
        self._created_at = created_at or now
        self._updated_at = updated_at or now
    @property

    def id(self) -> str:
        """Get the unique webhook identifier."""
        return self._id
    @property

    def created_at(self) -> datetime:
        """Get the creation timestamp."""
        return self._created_at
    @property

    def updated_at(self) -> datetime:
        """Get the last update timestamp."""
        return self._updated_at
    @property

    def url(self) -> Optional[str]:
        """Get webhook URL."""
        return self._url
    @url.setter

    def url(self, value: Optional[str]) -> None:
        """Set webhook URL."""
        self._url = value
        self._update_timestamp()
    @property

    def events(self) -> list[str]:
        """Get subscribed events."""
        return self._events
    @events.setter

    def events(self, value: list[str]) -> None:
        """Set subscribed events."""
        self._events = value
        self._update_timestamp()
    @property

    def secret(self) -> Optional[str]:
        """Get webhook secret."""
        return self._secret
    @secret.setter

    def secret(self, value: Optional[str]) -> None:
        """Set webhook secret."""
        self._secret = value
        self._update_timestamp()
    @property

    def active(self) -> bool:
        """Get active status."""
        return self._active
    @active.setter

    def active(self, value: bool) -> None:
        """Set active status."""
        self._active = value
        self._update_timestamp()

    def _update_timestamp(self) -> None:
        """Update the updated_at timestamp."""
        self._updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """
        Convert webhook to dictionary.
        Includes all standard XWObject fields (id, uid, created_at, updated_at)
        plus webhook-specific fields.
        """
        return {
            'id': self.id,
            'uid': self.uid,
            'url': self.url,
            'events': self.events,
            'active': self.active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    @classmethod

    def from_dict(cls, data: dict[str, Any]) -> 'Webhook':
        """
        Create webhook from dictionary.
        Supports both id and uid fields.
        """
        # Parse timestamps
        created_at = None
        if 'created_at' in data:
            created_at = datetime.fromisoformat(data['created_at']) if isinstance(data['created_at'], str) else data['created_at']
        updated_at = None
        if 'updated_at' in data:
            updated_at = datetime.fromisoformat(data['updated_at']) if isinstance(data['updated_at'], str) else data['updated_at']
        return cls(
            id=data.get('id') or data.get('uid'),
            url=data.get('url'),
            events=data.get('events', []),
            secret=data.get('secret'),  # Note: secret may be excluded for security
            active=data.get('active', True),
            created_at=created_at,
            updated_at=updated_at,
        )

    def save(self, *args, **kwargs) -> None:
        """
        Save webhook to storage.
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide persistence.
        Example:
            # Use with storage adapter
            storage_adapter.save_webhook(self)
        """
        raise NotImplementedError(
            "Webhook.save() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like WebhookStorageAdapter.save_webhook(webhook) instead."
        )

    def load(self, *args, **kwargs) -> None:
        """
        Load webhook from storage.
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide loading.
        Example:
            # Use with storage adapter
            webhook = storage_adapter.load_webhook(webhook_id)
        """
        raise NotImplementedError(
            "Webhook.load() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like WebhookStorageAdapter.load_webhook(webhook_id) instead."
        )
