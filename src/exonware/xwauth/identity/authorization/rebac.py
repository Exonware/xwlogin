#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/authorization/rebac.py
ReBAC Implementation
Relationship-Based Access Control (Zanzibar-style) implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWAuthorizationError
from exonware.xwauth.identity.contracts import IAuthorizer
from exonware.xwauth.identity.base import ABaseAuthorizer
logger = get_logger(__name__)


class ReBACAuthorizer(ABaseAuthorizer, IAuthorizer):
    """
    Relationship-Based Access Control implementation.
    Zanzibar-style authorization based on relationships between entities.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize ReBAC authorizer.
        Args:
            auth: XWAuth instance
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        self._relationships: dict[tuple[str, str, str], bool] = {}  # (user, relation, resource) -> allowed
        logger.debug("ReBACAuthorizer initialized")

    async def check_permission(
        self,
        user_id: str,
        resource: str,
        action: str
    ) -> bool:
        """
        Check if user has permission based on relationships.
        Implements relationship traversal (Zanzibar-style) to check:
        - Direct relationships
        - Indirect relationships through groups/roles
        - Hierarchical relationships (parent-child)
        Args:
            user_id: User identifier
            resource: Resource identifier
            action: Action to check (maps to relation)
        Returns:
            True if user has permission, False otherwise
        """
        # Check direct relationship
        key = (user_id, action, resource)
        if key in self._relationships:
            return self._relationships[key]
        # Relationship traversal: Check indirect relationships
        # 1. Check group memberships
        user = await self._storage.get_user(user_id)
        if user:
            user_attrs = user.attributes if hasattr(user, 'attributes') else {}
            groups = user_attrs.get('groups', [])
            for group_id in groups:
                group_key = (f"group:{group_id}", action, resource)
                if group_key in self._relationships:
                    return self._relationships[group_key]
        # 2. Check role-based relationships
        from .rbac import RBACAuthorizer
        rbac = RBACAuthorizer(self._auth)
        roles = await rbac.get_user_roles(user_id)
        for role in roles:
            role_key = (f"role:{role}", action, resource)
            if role_key in self._relationships:
                return self._relationships[role_key]
        # 3. Check hierarchical relationships (parent resources)
        # If resource has parent, check parent permissions
        resource_parts = resource.split(':')
        if len(resource_parts) > 1:
            # Try parent resource (e.g., "doc:123" -> check "doc:*")
            parent_resource = f"{resource_parts[0]}:*"
            parent_key = (user_id, action, parent_resource)
            if parent_key in self._relationships:
                return self._relationships[parent_key]
        return False

    async def get_user_roles(self, user_id: str) -> list[str]:
        """
        Get user roles (for compatibility with IAuthorizer).
        Args:
            user_id: User identifier
        Returns:
            List of role names (empty for ReBAC)
        """
        return []

    async def add_relationship(self, user_id: str, relation: str, resource: str) -> None:
        """
        Add relationship between user and resource.
        Args:
            user_id: User identifier
            relation: Relation type (e.g., 'owner', 'member', 'viewer')
            resource: Resource identifier
        """
        key = (user_id, relation, resource)
        self._relationships[key] = True
        logger.debug(f"Added relationship: {user_id} {relation} {resource}")
