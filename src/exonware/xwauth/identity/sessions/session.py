#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/sessions/session.py

Session Model

Session data model that extends xwsystem.shared.XWObject for consistent
identity, timestamps, and serialization across the eXonware ecosystem.

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from datetime import datetime, timedelta

from exonware.xwsystem import get_logger
from exonware.xwsystem.shared import XWObject

from exonware.xwauth.identity.defs import SessionStatus

logger = get_logger(__name__)


class Session(XWObject):
    """
    Session data model.
    
    Extends xwsystem.shared.XWObject for consistent identity management,
    timestamps, and serialization.
    
    Provides:
    - Identity: id (primary identifier), uid (UUID from XWObject)
    - Timestamps: created_at, updated_at (maps to last_accessed_at)
    - Serialization: to_dict(), to_native()
    - Storage: save(), load() (abstract - implement in subclasses or use storage adapter)
    """
    
    def __init__(
        self,
        id: str | None = None,
        user_id: str = "",
        expires_at: datetime | None = None,
        status: SessionStatus = SessionStatus.ACTIVE,
        csrf_token: str | None = None,
        attributes: dict[str, Any] | None = None,
        created_at: datetime | None = None,
        last_accessed_at: datetime | None = None,
    ):
        """
        Initialize session.
        
        Args:
            id: Optional session identifier (if not provided, uses XWObject.uid)
            user_id: User identifier this session belongs to
            expires_at: Session expiration timestamp
            status: Session status
            csrf_token: Optional CSRF token
            attributes: Additional session attributes
            created_at: Creation timestamp (defaults to now)
            last_accessed_at: Last access timestamp (defaults to now, maps to updated_at)
        """
        super().__init__(object_id=id)
        
        # Use provided id or fall back to uid from XWObject
        self._id = id or self.uid
        
        # Session-specific fields
        self._user_id = user_id
        self._expires_at = expires_at or (datetime.now() + timedelta(hours=24))
        self._status = status
        self._csrf_token = csrf_token
        self._attributes = attributes or {}
        
        # Timestamps
        now = datetime.now()
        self._created_at = created_at or now
        self._last_accessed_at = last_accessed_at or now
    
    @property
    def id(self) -> str:
        """Get the unique session identifier."""
        return self._id
    
    @property
    def created_at(self) -> datetime:
        """Get the creation timestamp."""
        return self._created_at
    
    @property
    def updated_at(self) -> datetime:
        """
        Get the last update timestamp.
        
        Maps to last_accessed_at for session tracking.
        """
        return self._last_accessed_at
    
    @property
    def user_id(self) -> str:
        """Get user identifier."""
        return self._user_id
    
    @property
    def expires_at(self) -> datetime:
        """Get expiration timestamp."""
        return self._expires_at
    
    @property
    def status(self) -> SessionStatus:
        """Get session status."""
        return self._status
    
    @status.setter
    def status(self, value: SessionStatus) -> None:
        """Set session status."""
        self._status = value
        self._update_timestamp()
    
    @property
    def csrf_token(self) -> str | None:
        """Get CSRF token."""
        return self._csrf_token
    
    @csrf_token.setter
    def csrf_token(self, value: str | None) -> None:
        """Set CSRF token."""
        self._csrf_token = value
        self._update_timestamp()
    
    @property
    def attributes(self) -> dict[str, Any]:
        """Get session attributes."""
        return self._attributes
    
    @property
    def last_accessed_at(self) -> datetime:
        """Get last accessed timestamp (alias for updated_at)."""
        return self._last_accessed_at
    
    def _update_timestamp(self) -> None:
        """Update the updated_at timestamp (and last_accessed_at)."""
        self._last_accessed_at = datetime.now()
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now() > self.expires_at
    
    def is_active(self) -> bool:
        """Check if session is active."""
        return self.status == SessionStatus.ACTIVE and not self.is_expired()
    
    def update_access_time(self) -> None:
        """Update last accessed time."""
        self._update_timestamp()
    
    def to_dict(self) -> dict[str, Any]:
        """
        Convert session to dictionary.
        
        Includes all standard XWObject fields (id, uid, created_at, updated_at)
        plus session-specific fields.
        """
        return {
            'id': self.id,
            'uid': self.uid,
            'user_id': self.user_id,
            'expires_at': self.expires_at.isoformat(),
            'status': self.status.value,
            'csrf_token': self.csrf_token,
            'attributes': self.attributes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_accessed_at': self.last_accessed_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Session':
        """
        Create session from dictionary.
        
        Backward compatible with previous format. Also supports new format
        with uid field.
        """
        # Parse timestamps
        created_at = None
        if 'created_at' in data:
            created_at = datetime.fromisoformat(data['created_at']) if isinstance(data['created_at'], str) else data['created_at']
        
        last_accessed_at = None
        if 'last_accessed_at' in data:
            last_accessed_at = datetime.fromisoformat(data['last_accessed_at']) if isinstance(data['last_accessed_at'], str) else data['last_accessed_at']
        elif 'updated_at' in data:
            # Support updated_at as alias for last_accessed_at
            last_accessed_at = datetime.fromisoformat(data['updated_at']) if isinstance(data['updated_at'], str) else data['updated_at']
        
        expires_at = None
        if 'expires_at' in data:
            expires_at = datetime.fromisoformat(data['expires_at']) if isinstance(data['expires_at'], str) else data['expires_at']
        
        return cls(
            id=data.get('id') or data.get('uid'),  # Support both id and uid
            user_id=data.get('user_id', ''),
            expires_at=expires_at,
            status=SessionStatus(data.get('status', 'active')) if isinstance(data.get('status'), str) else data.get('status', SessionStatus.ACTIVE),
            csrf_token=data.get('csrf_token'),
            attributes=data.get('attributes', {}),
            created_at=created_at,
            last_accessed_at=last_accessed_at,
        )
    
    def save(self, *args, **kwargs) -> None:
        """
        Save session to storage.
        
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide persistence.
        
        Example:
            # Use with storage adapter
            storage_adapter.save_session(self)
        """
        raise NotImplementedError(
            "Session.save() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like SessionStorageAdapter.save_session(session) instead."
        )
    
    def load(self, *args, **kwargs) -> None:
        """
        Load session from storage.
        
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide loading.
        
        Example:
            # Use with storage adapter
            session = storage_adapter.load_session(session_id)
        """
        raise NotImplementedError(
            "Session.load() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like SessionStorageAdapter.load_session(session_id) instead."
        )
