#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/grants/client_credentials.py
Client Credentials Grant Implementation
OAuth 2.0 Client Credentials grant type (RFC 6749 Section 4.4).
Used for machine-to-machine authentication.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError, XWUnauthorizedClientError
from exonware.xwauth.identity.core.grants.base import ABaseGrant
logger = get_logger(__name__)


class ClientCredentialsGrant(ABaseGrant):
    """
    Client Credentials grant type implementation.
    Used for machine-to-machine authentication where no user is involved.
    """
    @property

    def grant_type(self) -> GrantType:
        """Get grant type."""
        return GrantType.CLIENT_CREDENTIALS

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Validate client credentials grant request.
        Args:
            request: Request parameters
        Returns:
            Validated request data
        Raises:
            XWOAuthError: If validation fails
        """
        # Required parameters
        client_id = request.get('client_id')
        client_secret = request.get('client_secret')
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request",
                error_description="client_id parameter is required"
            )
        if not client_secret:
            raise XWUnauthorizedClientError(
                "client_secret is required for confidential clients",
                error_code="invalid_client",
                error_description="client_secret parameter is required"
            )
        # Validate client credentials
        self._validate_client(client_id, client_secret)
        # Validate scopes
        scopes = self._validate_scope(request.get('scope'))
        return {
            'client_id': client_id,
            'client_secret': client_secret,
            'scopes': scopes,
        }

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Process client credentials grant request.
        Issues access token directly (no authorization code or user involved).
        Args:
            request: Validated request parameters
        Returns:
            Token response dictionary
        """
        logger.debug(f"Processing client credentials grant for client: {request['client_id']}")
        # Get token manager from auth instance
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager:
            raise XWOAuthError(
                "Token manager not available",
                error_code="server_error",
                error_description="Token manager is not initialized"
            )
        # Generate access token (no user_id for client credentials grant)
        access_token = await token_manager.generate_access_token(
            user_id=None,
            client_id=request['client_id'],
            scopes=request['scopes']
        )
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': self._config.access_token_lifetime,
            'scope': ' '.join(request['scopes']) if request['scopes'] else None,
        }
