"""
Schema integration contracts for xwauth.
Company: eXonware.com
"""

from typing import Any, Optional, Protocol, runtime_checkable
@runtime_checkable


class IAccessControlSchema(Protocol):
    """Interface for schema-based access control definitions."""

    async def define_access_control(
        self,
        schema: dict[str, Any],
        permissions: dict[str, Any],
        **opts
    ) -> dict[str, Any]:
        """Define access control schema. Returns schema with access control embedded."""
        ...
@runtime_checkable


class IAuthorizationValidator(Protocol):
    """Interface for authorization validation using schemas."""

    async def validate_authorization(
        self,
        data: Any,
        schema: dict[str, Any],
        user_permissions: list[str],
        **opts
    ) -> dict[str, Any]:
        """Validate authorization. Returns dict with 'authorized' (bool) and 'errors' (list)."""
        ...
@runtime_checkable


class ISecurityRulesValidator(Protocol):
    """Interface for security rules validation using schemas."""

    async def validate_security_rule(
        self,
        data: Any,
        schema: dict[str, Any],
        rule_type: str,
        **opts
    ) -> dict[str, Any]:
        """Validate security rule. Returns dict with 'valid' (bool) and 'errors' (list)."""
        ...
