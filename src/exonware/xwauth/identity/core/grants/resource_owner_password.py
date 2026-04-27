#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/grants/resource_owner_password.py
Resource Owner Password Credentials Grant Implementation
OAuth 2.0 Resource Owner Password Credentials grant type (RFC 6749 Section 4.3).
Note: This grant type is discouraged and should only be used when other flows are not viable.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any, Optional
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError, XWInvalidCredentialsError
from exonware.xwauth.identity.core.grants.base import ABaseGrant
logger = get_logger(__name__)


class ResourceOwnerPasswordGrant(ABaseGrant):
    """
    Resource Owner Password Credentials grant type implementation.
    Note: This grant type is discouraged (RFC 6749 Section 4.3) and should
    only be used when other flows are not viable. Consider using Authorization
    Code grant with PKCE instead.
    """
    @property

    def grant_type(self) -> GrantType:
        """Get grant type."""
        return GrantType.RESOURCE_OWNER_PASSWORD

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Validate resource owner password credentials grant request.
        Args:
            request: Request parameters
        Returns:
            Validated request data
        Raises:
            XWOAuthError: If validation fails
        """
        # OAuth 2.1: Password grant disabled by default
        if getattr(self._config, "oauth21_compliant", True):
            if not getattr(self._config, "allow_password_grant", False):
                raise XWInvalidRequestError(
                    "Password grant is disabled (OAuth 2.1 compliance)",
                    error_code="unsupported_grant_type",
                    error_description="Resource owner password credentials grant is not allowed. Use authorization code grant with PKCE instead."
                )
        # Required parameters
        client_id = request.get('client_id')
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request",
                error_description="client_id parameter is required"
            )
        username = request.get('username')
        password = request.get('password')
        if not username:
            raise XWInvalidRequestError(
                "username is required",
                error_code="invalid_request",
                error_description="username parameter is required"
            )
        if not password:
            raise XWInvalidRequestError(
                "password is required",
                error_code="invalid_request",
                error_description="password parameter is required"
            )
        # Validate client
        client_secret = request.get('client_secret')
        self._validate_client(client_id, client_secret)
        # Validate scopes
        scopes = self._validate_scope(request.get('scope'))
        return {
            'client_id': client_id,
            'client_secret': client_secret,
            'username': username,
            'password': password,
            'scopes': scopes,
        }

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Process resource owner password credentials grant request.
        Validates user credentials and issues tokens directly.
        Args:
            request: Validated request parameters
        Returns:
            Token response dictionary
        """
        username = request['username']
        password = request['password']
        logger.debug(f"Processing resource owner password grant for user: {username}")
        # Authenticate via lazy façade on ``handlers._common`` (login extra required).
        from exonware.xwauth.identity.handlers import _common as _handler_common

        authenticator = _handler_common.get_email_password_authenticator(self._auth)
        # Try to authenticate (username field treated as email)
        try:
            user_id = await authenticator.authenticate({
                'email': username,  # RFC 6749 uses 'username' but we treat it as email
                'password': password
            })
        except XWInvalidCredentialsError:
            # If email lookup fails, user doesn't exist or password is wrong
            raise XWInvalidCredentialsError(
                "Invalid username or password",
                error_code="invalid_grant",
                error_description="The provided authorization grant is invalid"
            )
        if not user_id:
            raise XWInvalidCredentialsError(
                "Invalid username or password",
                error_code="invalid_grant",
                error_description="The provided authorization grant is invalid"
            )
        # Get token manager from auth instance
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager:
            raise XWOAuthError(
                "Token manager not available",
                error_code="server_error",
                error_description="Token manager is not initialized"
            )
        # Generate access token
        access_token = await token_manager.generate_access_token(
            user_id=user_id,
            client_id=request['client_id'],
            scopes=request['scopes']
        )
        # Generate refresh token
        refresh_token = await token_manager.generate_refresh_token(
            user_id=user_id,
            client_id=request['client_id']
        )
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': self._config.access_token_lifetime,
            'refresh_token': refresh_token,
            'scope': ' '.join(request['scopes']) if request['scopes'] else None,
        }
