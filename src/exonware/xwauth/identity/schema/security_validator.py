"""
Security rules validation using schemas for xwauth.
Uses xwschema for validation logic.
"""

from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwschema import XWSchema
from exonware.xwauth.identity.contracts import ISecurityRulesValidator
logger = get_logger(__name__)


class SecurityRulesValidator(ISecurityRulesValidator):
    """Security/authorization rules validator using xwschema."""

    def __init__(self):
        self._validator = XWSchema({})
        logger.debug("SecurityRulesValidator initialized")

    async def validate_security_rule(
        self,
        data: Any,
        schema: dict[str, Any],
        rule_type: str,
        **opts
    ) -> dict[str, Any]:
        try:
            is_valid, errors = self._validator.validate_schema(data, schema)
            return {
                'valid': is_valid,
                'errors': errors if isinstance(errors, list) else [str(errors)] if errors else [],
                'rule_type': rule_type,
                'type': 'security'
            }
        except Exception as e:
            logger.error(f"Security rule validation failed for {rule_type}: {e}")
            return {
                'valid': False,
                'errors': [f"Validation error: {str(e)}"],
                'rule_type': rule_type,
                'type': 'security'
            }
