#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/organizations/organization.py
Organization Model
Organization entity model that extends xwsystem.shared.XWObject for consistent
identity, timestamps, and serialization across the eXonware ecosystem.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from __future__ import annotations
from typing import Any, Optional
from datetime import datetime
from exonware.xwsystem import get_logger
from exonware.xwsystem.shared import XWObject
logger = get_logger(__name__)


class Organization(XWObject):
    """
    Organization entity model.
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
        name: Optional[str] = None,
        slug: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        attributes: Optional[dict[str, Any]] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        """
        Initialize organization.
        Args:
            id: Optional organization identifier (if not provided, uses XWObject.uid)
            name: Organization name
            slug: URL-friendly organization identifier
            description: Organization description
            metadata: Organization metadata (settings, config, etc.)
            attributes: Additional organization attributes
            created_at: Creation timestamp (defaults to now)
            updated_at: Last update timestamp (defaults to now)
        """
        super().__init__(object_id=id)
        # Use provided id or fall back to uid from XWObject
        self._id = id or self.uid
        # Organization-specific fields
        self._name = name
        self._slug = slug
        self._description = description
        self._metadata = metadata or {}
        self._attributes = attributes or {}
        # Timestamps
        now = datetime.now()
        self._created_at = created_at or now
        self._updated_at = updated_at or now
    @property

    def id(self) -> str:
        """Get the unique organization identifier."""
        return self._id
    @property

    def name(self) -> Optional[str]:
        """Get organization name."""
        return self._name
    @name.setter

    def name(self, value: Optional[str]) -> None:
        """Set organization name."""
        self._name = value
        self._update_timestamp()
    @property

    def slug(self) -> Optional[str]:
        """Get organization slug."""
        return self._slug
    @slug.setter

    def slug(self, value: Optional[str]) -> None:
        """Set organization slug."""
        self._slug = value
        self._update_timestamp()
    @property

    def description(self) -> Optional[str]:
        """Get organization description."""
        return self._description
    @description.setter

    def description(self, value: Optional[str]) -> None:
        """Set organization description."""
        self._description = value
        self._update_timestamp()
    @property

    def metadata(self) -> dict[str, Any]:
        """Get organization metadata."""
        return self._metadata
    @metadata.setter

    def metadata(self, value: dict[str, Any]) -> None:
        """Set organization metadata."""
        self._metadata = value or {}
        self._update_timestamp()
    @property

    def attributes(self) -> dict[str, Any]:
        """Get organization attributes."""
        return self._attributes
    @attributes.setter

    def attributes(self, value: dict[str, Any]) -> None:
        """Set organization attributes."""
        self._attributes = value or {}
        self._update_timestamp()
    @property

    def created_at(self) -> datetime:
        """Get the creation timestamp."""
        return self._created_at
    @property

    def updated_at(self) -> datetime:
        """Get the last update timestamp."""
        return self._updated_at

    def _update_timestamp(self) -> None:
        """Update the updated_at timestamp."""
        self._updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """
        Convert organization to dictionary.
        Includes all standard XWObject fields (id, uid, created_at, updated_at)
        plus organization-specific fields.
        """
        return {
            'id': self.id,
            'uid': self.uid,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'metadata': self.metadata,
            'attributes': self.attributes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
    @classmethod

    def from_dict(cls, data: dict[str, Any]) -> 'Organization':
        """
        Create organization from dictionary.
        Supports multiple format variations
        with uid field.
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
            name=data.get('name'),
            slug=data.get('slug'),
            description=data.get('description'),
            metadata=data.get('metadata', {}),
            attributes=data.get('attributes', {}),
            created_at=created_at,
            updated_at=updated_at,
        )

    def save(self, *args, **kwargs) -> None:
        """
        Save organization to storage.
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide persistence.
        Example:
            # Use with storage adapter
            storage_adapter.save_organization(self)
        """
        raise NotImplementedError(
            "Organization.save() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like OrganizationStorageAdapter.save_organization(org) instead."
        )

    def load(self, *args, **kwargs) -> None:
        """
        Load organization from storage.
        This is an abstract method from XWObject. Implement in subclasses
        or use a storage adapter to provide loading.
        Example:
            # Use with storage adapter
            org = storage_adapter.load_organization(org_id)
        """
        raise NotImplementedError(
            "Organization.load() must be implemented by storage adapter or subclass. "
            "Use a storage adapter like OrganizationStorageAdapter.load_organization(org_id) instead."
        )
