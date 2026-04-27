#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/authorization/abac.py
ABAC Implementation
Attribute-Based Access Control implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWAuthorizationError
from exonware.xwauth.identity.contracts import IAuthorizer
from exonware.xwauth.identity.base import ABaseAuthorizer
logger = get_logger(__name__)


class ABACAuthorizer(ABaseAuthorizer, IAuthorizer):
    """
    Attribute-Based Access Control implementation.
    Makes authorization decisions based on user, resource, and environment attributes.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize ABAC authorizer.
        Args:
            auth: XWAuth instance
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        logger.debug("ABACAuthorizer initialized")

    async def check_permission(
        self,
        user_id: str,
        resource: str,
        action: str
    ) -> bool:
        """
        Check if user has permission based on attributes.
        Evaluates policies based on:
        - User attributes (role, department, clearance level, etc.)
        - Resource attributes (type, sensitivity, owner, etc.)
        - Environment attributes (time, location, IP, etc.)
        - Action attributes (read, write, delete, etc.)
        Args:
            user_id: User identifier
            resource: Resource identifier
            action: Action to check
        Returns:
            True if user has permission, False otherwise
        """
        # Get user attributes
        user = await self._storage.get_user(user_id)
        if not user:
            return False
        user_attrs = user.attributes if hasattr(user, 'attributes') else {}
        # Get resource attributes (from storage or resource metadata)
        resource_attrs = await self._get_resource_attributes(resource)
        # Get environment attributes (context)
        env_attrs = self._get_environment_attributes()
        # Evaluate policy based on attributes
        return await self._evaluate_policy(user_attrs, resource_attrs, action, env_attrs)

    async def _get_resource_attributes(self, resource: str) -> dict[str, Any]:
        """
        Get resource attributes.
        Args:
            resource: Resource identifier
        Returns:
            Resource attributes dictionary
        """
        # Try to get resource from storage (if it's a user-managed resource)
        # For now, parse resource identifier for basic attributes
        resource_attrs = {}
        if ':' in resource:
            parts = resource.split(':')
            resource_attrs['type'] = parts[0]
            resource_attrs['id'] = parts[1] if len(parts) > 1 else None
        # Check if resource has stored attributes
        if hasattr(self._storage, 'get_resource'):
            try:
                resource_obj = await self._storage.get_resource(resource)
                if resource_obj:
                    resource_attrs.update(resource_obj.attributes if hasattr(resource_obj, 'attributes') else {})
            except Exception:
                pass  # Resource storage not available
        return resource_attrs

    def _get_environment_attributes(self) -> dict[str, Any]:
        """
        Get environment attributes (context).
        Returns:
            Environment attributes dictionary
        """
        from datetime import datetime
        return {
            'timestamp': datetime.now().isoformat(),
            'time_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
        }

    async def _evaluate_policy(
        self,
        user_attrs: dict[str, Any],
        resource_attrs: dict[str, Any],
        action: str,
        env_attrs: dict[str, Any]
    ) -> bool:
        """
        Evaluate ABAC policy.
        Basic policy evaluation engine that checks:
        - User role matches resource access requirements
        - User clearance level >= resource sensitivity
        - Time-based access restrictions
        - Resource ownership
        Args:
            user_attrs: User attributes
            resource_attrs: Resource attributes
            action: Action to check
            env_attrs: Environment attributes
        Returns:
            True if policy allows, False otherwise
        """
        # Policy 1: Check user role
        user_role = user_attrs.get('role')
        required_role = resource_attrs.get('required_role')
        if required_role and user_role != required_role:
            # Check role hierarchy (admin > manager > user)
            role_hierarchy = {'admin': 3, 'manager': 2, 'user': 1}
            user_level = role_hierarchy.get(user_role, 0)
            required_level = role_hierarchy.get(required_role, 999)
            if user_level < required_level:
                return False
        # Policy 2: Check clearance level
        user_clearance = user_attrs.get('clearance_level', 0)
        resource_sensitivity = resource_attrs.get('sensitivity_level', 0)
        if user_clearance < resource_sensitivity:
            return False
        # Policy 3: Check time-based restrictions
        time_restriction = resource_attrs.get('access_hours')
        if time_restriction:
            current_hour = env_attrs.get('time_of_day', 0)
            if not (time_restriction.get('start', 0) <= current_hour <= time_restriction.get('end', 23)):
                return False
        # Policy 4: Check resource ownership
        if action in ['delete', 'modify']:
            resource_owner = resource_attrs.get('owner_id')
            if resource_owner and resource_owner != user_attrs.get('id'):
                # Check if user is admin (can override ownership)
                if user_role != 'admin':
                    return False
        # Policy 5: Check action-specific permissions
        user_permissions = user_attrs.get('permissions', [])
        required_permission = f"{resource_attrs.get('type', 'resource')}:{action}"
        if user_permissions and required_permission not in user_permissions:
            # Check wildcard permissions
            if f"*:{action}" not in user_permissions and f"{resource_attrs.get('type', 'resource')}:*" not in user_permissions:
                return False
        # Default: Allow if no restrictions matched
        return True

    async def get_user_roles(self, user_id: str) -> list[str]:
        """
        Get user roles (for compatibility with IAuthorizer).
        Args:
            user_id: User identifier
        Returns:
            List of role names (empty for ABAC)
        """
        return []
