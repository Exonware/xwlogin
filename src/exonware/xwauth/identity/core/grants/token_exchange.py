#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/grants/token_exchange.py
Token Exchange Grant (RFC 8693)
Implements OAuth 2.0 Token Exchange grant type for exchanging tokens.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime, timedelta
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError, XWUnauthorizedClientError
from exonware.xwauth.identity.core.grants.base import ABaseGrant
logger = get_logger(__name__)


class TokenExchangeGrant(ABaseGrant):
    """
    Token Exchange grant handler (RFC 8693).
    Allows exchanging one token for another token, potentially with different
    scopes, audiences, or resource identifiers.
    """
    @property

    def grant_type(self) -> GrantType:
        """Get grant type."""
        return GrantType.TOKEN_EXCHANGE

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Validate token exchange request.
        Args:
            request: Request parameters
        Returns:
            Validated request data
        Raises:
            XWOAuthError: If validation fails
        """
        # Require client authentication
        client_id = request.get('client_id')
        client_secret = request.get('client_secret')
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request"
            )
        # Validate client
        client = self._validate_client(client_id, client_secret, require_secret=True)
        # Validate subject_token (required)
        subject_token = request.get('subject_token')
        if not subject_token:
            raise XWInvalidRequestError(
                "subject_token is required",
                error_code="invalid_request"
            )
        # Validate subject_token_type (required)
        subject_token_type = request.get('subject_token_type')
        if not subject_token_type:
            raise XWInvalidRequestError(
                "subject_token_type is required",
                error_code="invalid_request"
            )
        # Validate requested_token_type (optional, defaults to access_token)
        requested_token_type = request.get('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token')
        # Validate subject_token_type is supported
        supported_subject_types = [
            'urn:ietf:params:oauth:token-type:access_token',
            'urn:ietf:params:oauth:token-type:refresh_token',
        ]
        if subject_token_type not in supported_subject_types:
            raise XWInvalidRequestError(
                f"Unsupported subject_token_type: {subject_token_type}",
                error_code="invalid_request"
            )
        # Validate requested_token_type is supported
        supported_requested_types = [
            'urn:ietf:params:oauth:token-type:access_token',
        ]
        if requested_token_type not in supported_requested_types:
            raise XWInvalidRequestError(
                f"Unsupported requested_token_type: {requested_token_type}",
                error_code="invalid_request"
            )
        # Optional parameters
        audience = request.get('audience')
        scope = request.get('scope')
        resource = request.get('resource')
        # Parse scope
        requested_scopes = []
        if scope:
            requested_scopes = scope.split() if isinstance(scope, str) else scope
        return {
            'client_id': client_id,
            'client': client,
            'subject_token': subject_token,
            'subject_token_type': subject_token_type,
            'requested_token_type': requested_token_type,
            'audience': audience,
            'scope': requested_scopes,
            'resource': resource,
        }

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Process token exchange request.
        Args:
            request: Validated request parameters
        Returns:
            Token response dictionary
        """
        subject_token = request['subject_token']
        subject_token_type = request['subject_token_type']
        requested_token_type = request['requested_token_type']
        audience = request.get('audience')
        requested_scopes = request.get('scope', [])
        resource = request.get('resource')
        client_id = request['client_id']
        # Introspect subject token to get user info and existing scopes
        introspect_result = await self._auth.introspect_token(subject_token)
        if not introspect_result.get('active'):
            raise XWInvalidRequestError(
                "Invalid or expired subject_token",
                error_code="invalid_grant"
            )
        # Extract user info from introspection
        user_id = introspect_result.get('sub') or introspect_result.get('user_id')
        existing_scopes = introspect_result.get('scope', '')
        existing_scopes_list = existing_scopes.split() if isinstance(existing_scopes, str) else existing_scopes
        # Determine final scopes
        # If requested_scopes provided, validate they are subset of existing scopes
        if requested_scopes:
            # Validate requested scopes are subset of existing scopes
            invalid_scopes = [s for s in requested_scopes if s not in existing_scopes_list]
            if invalid_scopes:
                raise XWInvalidRequestError(
                    f"Requested scopes not granted in subject token: {', '.join(invalid_scopes)}",
                    error_code="invalid_scope"
                )
            final_scopes = requested_scopes
        else:
            # Use existing scopes
            final_scopes = existing_scopes_list
        # Generate new access token
        token_manager = self._auth._token_manager
        new_access_token = await token_manager.generate_access_token(
            user_id=user_id,
            client_id=client_id,
            scopes=final_scopes
        )
        # Build token response
        response: dict[str, Any] = {
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'issued_token_type': requested_token_type,
            'expires_in': self._config.access_token_lifetime,
            'scope': ' '.join(final_scopes) if final_scopes else None,
        }
        # Add audience if provided
        if audience:
            response['audience'] = audience
        logger.debug(f"Token exchange completed for client: {client_id}, user: {user_id}")
        return response
