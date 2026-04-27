#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/organizations/lifecycle.py
Organization Lifecycle Management
Organization CRUD operations and lifecycle management.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Optional, Any
import uuid
import re
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWAuthError
from .organization import Organization
logger = get_logger(__name__)


class OrganizationLifecycle:
    """
    Organization lifecycle management.
    Handles organization CRUD operations via IStorageProvider.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize organization lifecycle manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        logger.debug("OrganizationLifecycle initialized")

    async def create_organization(
        self,
        name: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        attributes: Optional[dict[str, Any]] = None,
        owner_id: Optional[str] = None,
    ) -> Organization:
        """
        Create new organization.
        Args:
            name: Organization name
            slug: Optional URL-friendly identifier (auto-generated if not provided)
            description: Optional organization description
            metadata: Optional organization metadata
            attributes: Optional organization attributes
            owner_id: Optional owner user ID (creator becomes owner if not provided)
        Returns:
            Created organization
        Raises:
            XWAuthError: If validation fails
        """
        # Validate name
        if not name or not name.strip():
            raise XWAuthError(
                "Organization name is required",
                error_code="invalid_name"
            )
        # Generate slug if not provided
        if not slug:
            slug = self._generate_slug(name)
        # Validate slug format
        if not re.match(r'^[a-z0-9-]+$', slug):
            raise XWAuthError(
                "Invalid slug format. Use lowercase letters, numbers, and hyphens only.",
                error_code="invalid_slug"
            )
        # Check if slug already exists
        existing = await self._get_organization_by_slug(slug)
        if existing:
            raise XWAuthError(
                f"Organization with slug '{slug}' already exists",
                error_code="slug_exists"
            )
        # Create organization
        org = Organization(
            id=str(uuid.uuid4()),
            name=name.strip(),
            slug=slug,
            description=description,
            metadata=metadata or {},
            attributes=attributes or {},
        )
        # Save to storage
        await self._save_organization(org)
        # Add owner as member with 'owner' role
        if owner_id:
            await self._add_member(org.id, owner_id, "owner")
        logger.debug(f"Created organization: {org.id} ({org.slug})")
        return org

    async def get_organization(self, org_id: str) -> Optional[Organization]:
        """
        Get organization by ID.
        Args:
            org_id: Organization identifier
        Returns:
            Organization object or None
        """
        return await self._get_organization(org_id)

    async def get_organization_by_slug(self, slug: str) -> Optional[Organization]:
        """
        Get organization by slug.
        Args:
            slug: Organization slug
        Returns:
            Organization object or None
        """
        return await self._get_organization_by_slug(slug)

    async def update_organization(
        self,
        org_id: str,
        updates: dict[str, Any]
    ) -> Organization:
        """
        Update organization.
        Args:
            org_id: Organization identifier
            updates: Dictionary of fields to update
        Returns:
            Updated organization
        Raises:
            XWAuthError: If organization not found or validation fails
        """
        org = await self._get_organization(org_id)
        if not org:
            raise XWAuthError(
                f"Organization not found: {org_id}",
                error_code="org_not_found"
            )
        # Validate slug if being updated
        if 'slug' in updates:
            new_slug = updates['slug']
            if not re.match(r'^[a-z0-9-]+$', new_slug):
                raise XWAuthError(
                    "Invalid slug format. Use lowercase letters, numbers, and hyphens only.",
                    error_code="invalid_slug"
                )
            # Check if slug already exists (excluding current org)
            existing = await self._get_organization_by_slug(new_slug)
            if existing and existing.id != org_id:
                raise XWAuthError(
                    f"Organization with slug '{new_slug}' already exists",
                    error_code="slug_exists"
                )
        # Update organization
        for key, value in updates.items():
            if hasattr(org, key):
                setattr(org, key, value)
        # Save updated organization
        await self._save_organization(org)
        logger.debug(f"Updated organization: {org_id}")
        return org

    async def delete_organization(self, org_id: str) -> None:
        """
        Delete organization.
        Args:
            org_id: Organization identifier
        Raises:
            XWAuthError: If organization not found
        """
        org = await self._get_organization(org_id)
        if not org:
            raise XWAuthError(
                f"Organization not found: {org_id}",
                error_code="org_not_found"
            )
        await self._delete_organization(org_id)
        logger.debug(f"Deleted organization: {org_id}")

    async def list_user_organizations(self, user_id: str) -> list[Organization]:
        """
        List all organizations a user belongs to.
        Args:
            user_id: User identifier
        Returns:
            List of organizations
        """
        # Get user's organization memberships
        memberships = await self._get_user_memberships(user_id)
        # Get organizations
        orgs = []
        for membership in memberships:
            org = await self._get_organization(membership.get('org_id'))
            if org:
                orgs.append(org)
        return orgs

    def _generate_slug(self, name: str) -> str:
        """Generate URL-friendly slug from name."""
        # Convert to lowercase
        slug = name.lower()
        # Replace spaces and special chars with hyphens
        slug = re.sub(r'[^a-z0-9]+', '-', slug)
        # Remove leading/trailing hyphens
        slug = slug.strip('-')
        # Limit length
        if len(slug) > 50:
            slug = slug[:50]
        return slug
    # Storage helper methods (using storage interface)

    async def _save_organization(self, org: Organization) -> None:
        """Save organization to storage."""
        if hasattr(self._storage, 'write'):
            await self._storage.write(f"org:{org.id}", org.to_dict())
        else:
            # Fallback to in-memory storage
            if not hasattr(self._storage, '_organizations'):
                self._storage._organizations = {}
            self._storage._organizations[org.id] = org.to_dict()

    async def _get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization from storage."""
        if hasattr(self._storage, 'read'):
            data = await self._storage.read(f"org:{org_id}")
            if data:
                return Organization.from_dict(data)
        else:
            # Fallback to in-memory storage
            if hasattr(self._storage, '_organizations'):
                data = self._storage._organizations.get(org_id)
                if data:
                    return Organization.from_dict(data)
        return None

    async def _get_organization_by_slug(self, slug: str) -> Optional[Organization]:
        """Get organization by slug from storage."""
        # This is a simplified implementation - in production, you'd want an index
        if hasattr(self._storage, 'read'):
            # Try to find by slug (would need indexing in real implementation)
            # For now, we'll use a simple search
            pass
        else:
            # Fallback: search in-memory storage
            if hasattr(self._storage, '_organizations'):
                for org_data in self._storage._organizations.values():
                    if isinstance(org_data, dict) and org_data.get('slug') == slug:
                        return Organization.from_dict(org_data)
        return None

    async def _delete_organization(self, org_id: str) -> None:
        """Delete organization from storage."""
        if hasattr(self._storage, 'delete'):
            await self._storage.delete(f"org:{org_id}")
        else:
            # Fallback to in-memory storage
            if hasattr(self._storage, '_organizations'):
                self._storage._organizations.pop(org_id, None)

    async def _add_member(self, org_id: str, user_id: str, role: str) -> None:
        """Add member to organization."""
        membership_key = f"org_member:{org_id}:{user_id}"
        membership_data = {
            "org_id": org_id,
            "user_id": user_id,
            "role": role,
        }
        if hasattr(self._storage, 'write'):
            await self._storage.write(membership_key, membership_data)
        else:
            if not hasattr(self._storage, '_org_memberships'):
                self._storage._org_memberships = {}
            self._storage._org_memberships[membership_key] = membership_data

    async def _get_user_memberships(self, user_id: str) -> list[dict[str, Any]]:
        """Get all organization memberships for a user."""
        memberships = []
        if hasattr(self._storage, 'read'):
            # Would need to query by user_id (would need indexing in real implementation)
            pass
        else:
            # Fallback: search in-memory storage
            if hasattr(self._storage, '_org_memberships'):
                for key, membership in self._storage._org_memberships.items():
                    if membership.get('user_id') == user_id:
                        memberships.append(membership)
        return memberships
