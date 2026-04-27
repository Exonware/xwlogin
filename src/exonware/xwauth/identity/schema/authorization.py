"""
Authorization validation using schemas for xwauth.
Company: eXonware.com
"""

from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.contracts import IAuthorizationValidator
logger = get_logger(__name__)


class AuthorizationValidator(IAuthorizationValidator):
    """Authorization validator using schema access control."""

    def __init__(self):
        logger.debug("AuthorizationValidator initialized")

    async def validate_authorization(
        self,
        data: Any,
        schema: dict[str, Any],
        user_permissions: list[str],
        operation: str = 'read',
        **opts
    ) -> dict[str, Any]:
        try:
            access_control = schema.get('x-access-control', {})
            required_permissions = access_control.get(operation, [])
            authorized = False
            if required_permissions:
                authorized = any(perm in user_permissions for perm in required_permissions)
            else:
                authorized = True
            if not authorized:
                return {
                    'authorized': False,
                    'errors': [f"User lacks required permissions for {operation} operation"],
                    'required_permissions': required_permissions,
                    'user_permissions': user_permissions
                }
            return {'authorized': True, 'errors': [], 'operation': operation}
        except Exception as e:
            logger.error(f"Authorization validation failed: {e}")
            return {'authorized': False, 'errors': [f"Authorization error: {str(e)}"]}
