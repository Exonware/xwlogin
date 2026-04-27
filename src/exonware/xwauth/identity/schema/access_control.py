"""
Access control schema for xwauth.
Company: eXonware.com
"""

from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.contracts import IAccessControlSchema
logger = get_logger(__name__)


class AccessControlSchema(IAccessControlSchema):
    """Schema-based access control definitions."""

    def __init__(self):
        logger.debug("AccessControlSchema initialized")

    async def define_access_control(
        self,
        schema: dict[str, Any],
        permissions: dict[str, Any],
        **opts
    ) -> dict[str, Any]:
        schema_with_ac = schema.copy()
        if 'x-access-control' not in schema_with_ac:
            schema_with_ac['x-access-control'] = {}
        schema_with_ac['x-access-control'].update(permissions)
        logger.debug("Access control defined for schema")
        return schema_with_ac
