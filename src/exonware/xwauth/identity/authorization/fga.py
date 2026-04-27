#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/authorization/fga.py
Fine-Grained Authorization (FGA) Manager
Zanzibar-style relationship-based access control with tuple storage and checking.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWAuthError
logger = get_logger(__name__)


class FGAManager:
    """
    Fine-Grained Authorization manager.
    Implements Zanzibar-style relationship-based access control with tuple storage.
    Supports tuples like: (user:123, relation:editor, object:doc:456)
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize FGA manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._storage = auth.storage
        logger.debug("FGAManager initialized")

    async def check(
        self,
        user: str,
        relation: str,
        object: str,
    ) -> bool:
        """
        Check if a user has a relation to an object (Zanzibar-style).
        Args:
            user: User identifier (e.g., "user:123")
            relation: Relation type (e.g., "viewer", "editor", "owner")
            object: Object identifier (e.g., "doc:456")
        Returns:
            True if the relationship exists, False otherwise
        """
        # Check direct relationship
        tuple_key = self._tuple_key(user, relation, object)
        exists = await self._tuple_exists(tuple_key)
        if exists:
            return True
        # Relationship traversal: Check indirect relationships (Zanzibar-style)
        # 1. Check group memberships
        user_id = user.replace('user:', '') if user.startswith('user:') else user
        user_obj = await self._storage.get_user(user_id)
        if user_obj:
            user_attrs = user_obj.attributes if hasattr(user_obj, 'attributes') else {}
            groups = user_attrs.get('groups', [])
            for group_id in groups:
                group_user = f"group:{group_id}"
                group_tuple_key = self._tuple_key(group_user, relation, object)
                if await self._tuple_exists(group_tuple_key):
                    return True
        # 2. Check role-based relationships
        from .rbac import RBACAuthorizer
        rbac = RBACAuthorizer(self._auth)
        roles = await rbac.get_user_roles(user_id)
        for role in roles:
            role_user = f"role:{role}"
            role_tuple_key = self._tuple_key(role_user, relation, object)
            if await self._tuple_exists(role_tuple_key):
                return True
        # 3. Check hierarchical relationships (parent objects)
        # If object has parent, check parent permissions
        object_parts = object.split(':')
        if len(object_parts) > 1:
            # Try parent object (e.g., "doc:123" -> check "doc:*")
            parent_object = f"{object_parts[0]}:*"
            parent_tuple_key = self._tuple_key(user, relation, parent_object)
            if await self._tuple_exists(parent_tuple_key):
                return True
        # 4. Check transitive relationships (e.g., member -> viewer)
        # If user is a member, they might have viewer access
        if relation != 'viewer':
            viewer_tuple_key = self._tuple_key(user, 'viewer', object)
            if await self._tuple_exists(viewer_tuple_key):
                return True
        return False

    async def write_tuples(
        self,
        tuples: list[dict[str, str]],
    ) -> dict[str, Any]:
        """
        Write relationship tuples.
        Args:
            tuples: List of tuples, each with 'user', 'relation', 'object'
        Returns:
            Dictionary with write results
        """
        written = []
        errors = []
        for tuple_data in tuples:
            user = tuple_data.get('user')
            relation = tuple_data.get('relation')
            object = tuple_data.get('object')
            if not all([user, relation, object]):
                errors.append({
                    'tuple': tuple_data,
                    'error': 'Missing required fields: user, relation, object'
                })
                continue
            try:
                await self._write_tuple(user, relation, object)
                written.append({
                    'user': user,
                    'relation': relation,
                    'object': object,
                })
            except Exception as e:
                errors.append({
                    'tuple': tuple_data,
                    'error': str(e)
                })
        return {
            'written': written,
            'errors': errors,
        }

    async def delete_tuples(
        self,
        tuples: list[dict[str, str]],
    ) -> dict[str, Any]:
        """
        Delete relationship tuples.
        Args:
            tuples: List of tuples to delete, each with 'user', 'relation', 'object'
        Returns:
            Dictionary with delete results
        """
        deleted = []
        errors = []
        for tuple_data in tuples:
            user = tuple_data.get('user')
            relation = tuple_data.get('relation')
            object = tuple_data.get('object')
            if not all([user, relation, object]):
                errors.append({
                    'tuple': tuple_data,
                    'error': 'Missing required fields: user, relation, object'
                })
                continue
            try:
                await self._delete_tuple(user, relation, object)
                deleted.append({
                    'user': user,
                    'relation': relation,
                    'object': object,
                })
            except Exception as e:
                errors.append({
                    'tuple': tuple_data,
                    'error': str(e)
                })
        return {
            'deleted': deleted,
            'errors': errors,
        }

    async def expand(
        self,
        user: str,
        relation: str,
        object: str,
    ) -> dict[str, Any]:
        """
        Expand permission tree for debugging.
        Shows all relationships that grant access, including indirect ones.
        Args:
            user: User identifier
            relation: Relation type
            object: Object identifier
        Returns:
            Dictionary with permission tree
        """
        # Check direct relationship
        tuple_key = self._tuple_key(user, relation, object)
        direct = await self._tuple_exists(tuple_key)
        result = {
            'user': user,
            'relation': relation,
            'object': object,
            'allowed': direct,
            'paths': [],
        }
        if direct:
            result['paths'].append({
                'type': 'direct',
                'tuple': {
                    'user': user,
                    'relation': relation,
                    'object': object,
                }
            })
        # Relationship traversal: Find indirect paths
        paths_found = []
        # 1. Check group memberships
        user_id = user.replace('user:', '') if user.startswith('user:') else user
        user_obj = await self._storage.get_user(user_id)
        if user_obj:
            user_attrs = user_obj.attributes if hasattr(user_obj, 'attributes') else {}
            groups = user_attrs.get('groups', [])
            for group_id in groups:
                group_user = f"group:{group_id}"
                group_tuple_key = self._tuple_key(group_user, relation, object)
                if await self._tuple_exists(group_tuple_key):
                    paths_found.append({
                        'type': 'group_membership',
                        'tuple': {
                            'user': group_user,
                            'relation': relation,
                            'object': object,
                        },
                        'path': [f"{user} -> member of {group_user} -> {relation} {object}"]
                    })
        # 2. Check role hierarchies
        from .rbac import RBACAuthorizer
        rbac = RBACAuthorizer(self._auth)
        roles = await rbac.get_user_roles(user_id)
        for role in roles:
            role_user = f"role:{role}"
            role_tuple_key = self._tuple_key(role_user, relation, object)
            if await self._tuple_exists(role_tuple_key):
                paths_found.append({
                    'type': 'role_based',
                    'tuple': {
                        'user': role_user,
                        'relation': relation,
                        'object': object,
                    },
                    'path': [f"{user} -> has role {role} -> {relation} {object}"]
                })
        # 3. Check object hierarchies (parent-child relationships)
        object_parts = object.split(':')
        if len(object_parts) > 1:
            parent_object = f"{object_parts[0]}:*"
            parent_tuple_key = self._tuple_key(user, relation, parent_object)
            if await self._tuple_exists(parent_tuple_key):
                paths_found.append({
                    'type': 'object_hierarchy',
                    'tuple': {
                        'user': user,
                        'relation': relation,
                        'object': parent_object,
                    },
                    'path': [f"{user} -> {relation} {parent_object} (parent of {object})"]
                })
        result['paths'].extend(paths_found)
        result['allowed'] = result['allowed'] or len(paths_found) > 0
        return result

    async def list_user_permissions(
        self,
        user_id: str,
    ) -> list[dict[str, Any]]:
        """
        List all permissions for a user.
        Args:
            user_id: User identifier
        Returns:
            List of permission tuples
        """
        # Get all tuples for this user
        user_prefix = f"user:{user_id}"
        tuples = await self._list_tuples_by_user(user_prefix)
        permissions = []
        for tuple_data in tuples:
            permissions.append({
                'user': tuple_data.get('user'),
                'relation': tuple_data.get('relation'),
                'object': tuple_data.get('object'),
            })
        return permissions

    def _tuple_key(self, user: str, relation: str, object: str) -> str:
        """Generate storage key for a tuple."""
        return f"fga_tuple:{user}:{relation}:{object}"

    async def _write_tuple(self, user: str, relation: str, object: str) -> None:
        """Write a tuple to storage."""
        tuple_key = self._tuple_key(user, relation, object)
        tuple_data = {
            'user': user,
            'relation': relation,
            'object': object,
            'created_at': datetime.now().isoformat(),
        }
        if hasattr(self._storage, 'write'):
            await self._storage.write(tuple_key, tuple_data)
        else:
            # Fallback to in-memory storage
            if not hasattr(self._storage, '_fga_tuples'):
                self._storage._fga_tuples = {}
            self._storage._fga_tuples[tuple_key] = tuple_data
        logger.debug(f"Wrote tuple: {user} {relation} {object}")

    async def _delete_tuple(self, user: str, relation: str, object: str) -> None:
        """Delete a tuple from storage."""
        tuple_key = self._tuple_key(user, relation, object)
        if hasattr(self._storage, 'delete'):
            await self._storage.delete(tuple_key)
        else:
            # Fallback to in-memory storage
            if hasattr(self._storage, '_fga_tuples'):
                self._storage._fga_tuples.pop(tuple_key, None)
        logger.debug(f"Deleted tuple: {user} {relation} {object}")

    async def _tuple_exists(self, tuple_key: str) -> bool:
        """Check if a tuple exists."""
        if hasattr(self._storage, 'read'):
            data = await self._storage.read(tuple_key)
            return data is not None
        else:
            # Fallback to in-memory storage
            if hasattr(self._storage, '_fga_tuples'):
                return tuple_key in self._storage._fga_tuples
        return False

    async def _list_tuples_by_user(self, user_prefix: str) -> list[dict[str, Any]]:
        """List all tuples for a user."""
        tuples = []
        if hasattr(self._storage, 'read'):
            # Would need indexing in real implementation
            pass
        else:
            # Fallback: search in-memory storage
            if hasattr(self._storage, '_fga_tuples'):
                for key, tuple_data in self._storage._fga_tuples.items():
                    if key.startswith(f"fga_tuple:{user_prefix}"):
                        tuples.append(tuple_data)
        return tuples
