#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/users/user.py
User Model
User entity model that extends xwsystem.shared.XWObject for consistent
identity, timestamps, and serialization across the eXonware ecosystem.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from __future__ import annotations
from typing import Any, Optional
from datetime import datetime
from exonware.xwsystem import get_logger
from exonware.xwsystem.shared import XWObject
from exonware.xwauth.identity.defs import UserStatus
logger = get_logger(__name__)


class User(XWObject):
    """
    User entity model.
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
        id: Optional[str] = None,
        email: Optional[str] = None,
        password_hash: Optional[str] = None,
        status: UserStatus = UserStatus.ACTIVE,
        attributes: Optional[dict[str, Any]] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
    ):
        """
        Initialize user.
        Args:
            id: Optional user identifier (if not provided, uses XWObject.uid)
            email: User email address
            password_hash: Hashed password
            status: User status
            attributes: Additional user attributes
            created_at: Creation timestamp (defaults to now)
            updated_at: Last update timestamp (defaults to now)
            title: Optional user title/display name
            description: Optional user description/bio
        """
        super().__init__(object_id=id)
        # Use provided id or fall back to uid from XWObject
        self._id = id or self.uid
        # User-specific fields
        self._email = email
        self._password_hash = password_hash
        self._status = status
        self._attributes = attributes or {}
        # Timestamps
        now = datetime.now()
        self._created_at = created_at or now
        self._updated_at = updated_at or now
        # Metadata (from XWObject)
        self._title = title
        self._description = description
    @property

    def id(self) -> str:
        """Get the unique user identifier."""
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

    def email(self) -> Optional[str]:
        """Get user email address."""
        return self._email
    @email.setter

    def email(self, value: Optional[str]) -> None:
        """Set user email address."""
        self._email = value
        self._update_timestamp()
    @property

    def password_hash(self) -> Optional[str]:
        """Get password hash."""
        return self._password_hash
    @password_hash.setter

    def password_hash(self, value: Optional[str]) -> None:
        """Set password hash."""
        self._password_hash = value
        self._update_timestamp()
    @property

    def status(self) -> UserStatus:
        """Get user status."""
        return self._status
    @status.setter

    def status(self, value: UserStatus) -> None:
        """Set user status."""
        self._status = value
        self._update_timestamp()
    @property

    def attributes(self) -> dict[str, Any]:
        """Get user attributes."""
        return self._attributes

    def _update_timestamp(self) -> None:
        """Update the updated_at timestamp."""
        self._updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """
        Convert user to dictionary.
        Includes all standard XWObject fields (id, uid, created_at, updated_at,
        title, description) plus user-specific fields.
        """
        return {
            'id': self.id,
            'uid': self.uid,
            'email': self.email,
            'password_hash': self.password_hash,  # Note: Consider excluding in production
            'status': self.status.value,
            'attributes': self.attributes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'title': self.title,
            'description': self.description,
        }
    @classmethod

    def from_dict(cls, data: dict[str, Any]) -> User:
        """
        Create user from dictionary.
        Supports multiple format variations
        with uid, title, and description fields.
        """
        # Parse timestamps
        created_at = None
        if 'created_at' in data:
            created_at = datetime.fromisoformat(data['created_at']) if isinstance(data['created_at'], str) else data['created_at']
        updated_at = None
        if 'updated_at' in data:
            updated_at = datetime.fromisoformat(data['updated_at']) if isinstance(data['updated_at'], str) else data['updated_at']
        return cls(
            id=data.get('id') or data.get('uid'),  # Support both id and uid
            email=data.get('email'),
            password_hash=data.get('password_hash'),
            status=UserStatus(data.get('status', 'active')) if isinstance(data.get('status'), str) else data.get('status', UserStatus.ACTIVE),
            attributes=data.get('attributes', {}),
            created_at=created_at,
            updated_at=updated_at,
            title=data.get('title'),
            description=data.get('description'),
        )

    def save(self, *args, **kwargs) -> None:
        """
        Save user to storage.
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide persistence.
        Example:
            # Use with storage adapter
            storage_adapter.save_user(self)
        """
        raise NotImplementedError(
            "User.save() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like UserStorageAdapter.save_user(user) instead."
        )

    def load(self, *args, **kwargs) -> None:
        """
        Load user from storage.
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide loading.
        Example:
            # Use with storage adapter
            user = storage_adapter.load_user(user_id)
        """
        raise NotImplementedError(
            "User.load() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like UserStorageAdapter.load_user(user_id) instead."
        )
