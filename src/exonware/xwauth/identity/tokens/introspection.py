#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/tokens/introspection.py
Token Introspection (RFC 7662)
Token introspection endpoint implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from datetime import datetime, timezone
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.errors import XWTokenError
from .jwt import JWTTokenManager
from .opaque import OpaqueTokenManager
logger = get_logger(__name__)

# Opaque-token ``attributes`` must not override RFC 7662 / security fields
# derived from authoritative storage (expiry, subject, client, scope, …).
_OPAQUE_ATTRS_INTROSPECTION_DENYLIST = frozenset(
    {
        "active",
        "sub",
        "client_id",
        "scope",
        "scopes",
        "exp",
        "username",
        "iat",
        "iss",
        "aud",
        "jti",
        "token_id",
        # Already mapped from storage / attrs above; do not re-apply via merge.
        "roles",
        "session_id",
        "aal",
        "amr",
        "tenant_id",
        "org_id",
        "project_id",
    }
)


class TokenIntrospection:
    """
    Token introspection implementation (RFC 7662).
    Provides token introspection endpoint for validating and getting token information.
    """

    def __init__(
        self,
        jwt_manager: JWTTokenManager | None = None,
        opaque_manager: OpaqueTokenManager | None = None
    ):
        """
        Initialize token introspection.
        Args:
            jwt_manager: JWT token manager (optional)
            opaque_manager: Opaque token manager (optional)
        """
        self._jwt_manager = jwt_manager
        self._opaque_manager = opaque_manager
        logger.debug("TokenIntrospection initialized")

    async def introspect(self, token: str, token_type_hint: str | None = None) -> dict[str, Any]:
        """
        Introspect token (RFC 7662 Section 2.1).
        Args:
            token: Token to introspect
            token_type_hint: Optional hint about token type ("access_token" or "refresh_token")
        Returns:
            Introspection response (RFC 7662 Section 2.2)
        """
        # Try to introspect as JWT first
        if self._jwt_manager:
            try:
                payload = self._jwt_manager.validate_token(token)
                # Check if expired
                exp = payload.get('exp')
                is_active = True
                if exp:
                    is_active = datetime.now(timezone.utc).timestamp() < exp
                scopes = payload.get('scope', '')
                if isinstance(scopes, list):
                    scope_str = ' '.join([str(s) for s in scopes])
                else:
                    scope_str = str(scopes or '')
                response = {
                    'active': is_active,
                    'client_id': payload.get('client_id'),
                    'username': payload.get('sub'),  # Subject
                    'scope': scope_str,
                    'exp': exp,
                    'iat': payload.get('iat'),
                    'sub': payload.get('sub'),
                    'aud': payload.get('aud'),
                    'iss': payload.get('iss'),
                    'jti': payload.get('jti'),
                    'token_id': payload.get('jti'),
                    'session_id': payload.get('session_id'),
                    'aal': payload.get('aal'),
                    'amr': payload.get('amr', []),
                    'tenant_id': payload.get('tenant_id') or payload.get('tid'),
                    'org_id': payload.get('org_id') or payload.get('organization_id'),
                    'project_id': payload.get('project_id') or payload.get('application_id'),
                    'roles': payload.get('roles', []),
                    'scopes': [s for s in scope_str.split(' ') if s],
                }
                if response.get('jti') and self._jwt_manager.is_jti_revoked(str(response.get('jti'))):
                    response['active'] = False
                return response
            except Exception:
                # Not a valid JWT, try opaque
                pass
        # Try to introspect as opaque token
        if self._opaque_manager:
            try:
                token_data = await self._opaque_manager.get_token(token)
                if token_data:
                    expires_at = token_data.get('expires_at')
                    is_active = True
                    if expires_at:
                        expires_dt = datetime.fromisoformat(expires_at)
                        is_active = datetime.now() < expires_dt
                    attrs = token_data.get('attributes') or {}
                    response = {
                        'active': is_active,
                        'client_id': token_data.get('client_id'),
                        'username': token_data.get('user_id'),
                        'scope': ' '.join(token_data.get('scopes', [])),
                        'exp': int(datetime.fromisoformat(expires_at).timestamp()) if expires_at else None,
                        'sub': token_data.get('user_id'),
                        'scopes': token_data.get('scopes', []),
                        'session_id': attrs.get('session_id'),
                        'aal': attrs.get('aal'),
                        'amr': attrs.get('amr', []),
                        'tenant_id': attrs.get('tenant_id') or attrs.get('tid'),
                        'roles': attrs.get('roles', []),
                        'token_id': token_data.get('token_id'),
                    }
                    if isinstance(attrs, dict):
                        for attr_key, attr_val in attrs.items():
                            if attr_key in _OPAQUE_ATTRS_INTROSPECTION_DENYLIST:
                                continue
                            response[attr_key] = attr_val
                    return response
            except Exception:
                pass
        # Token not found or invalid
        return {
            'active': False
        }
