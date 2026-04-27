#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/oauth1/server.py
OAuth 1.0 Server Implementation
Implements OAuth 1.0 authorization server (RFC 5849).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime, timedelta
import secrets
import base64
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWInvalidRequestError, XWUnauthorizedClientError
from .signature import OAuth1Signature
from .request_validator import OAuth1RequestValidator
logger = get_logger(__name__)


class OAuth1Server:
    """
    OAuth 1.0 authorization server (RFC 5849).
    Handles OAuth 1.0 three-legged authorization flow:
    1. Request Token (temporary credentials)
    2. User Authorization
    3. Access Token (token credentials)
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize OAuth 1.0 server.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        self._storage = auth.storage
        self._validator = OAuth1RequestValidator(auth)
        logger.debug("OAuth1Server initialized")

    async def request_token(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Request temporary credentials (request token) (RFC 5849 Section 2.1).
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body
        Returns:
            Request token response
        """
        # Validate request
        validated = await self._validator.validate_request(method, url, headers, body)
        consumer_key = validated['consumer_key']
        # Generate request token
        request_token = self._generate_token()
        request_token_secret = self._generate_token_secret()
        # Store request token
        await self._store_request_token(
            request_token,
            request_token_secret,
            consumer_key
        )
        return {
            'oauth_token': request_token,
            'oauth_token_secret': request_token_secret,
            'oauth_callback_confirmed': 'true',
        }

    async def authorize(
        self,
        request_token: str,
        user_id: str,
        callback_url: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Authorize request token (RFC 5849 Section 2.2).
        Args:
            request_token: Request token
            user_id: User identifier
            callback_url: Callback URL (optional)
        Returns:
            Authorization response with verifier
        """
        # Get request token
        token_data = await self._get_request_token(request_token)
        if not token_data:
            raise XWInvalidRequestError(
                "Invalid request token",
                error_code="invalid_token"
            )
        # Generate verifier
        verifier = self._generate_verifier()
        # Store authorization
        await self._store_authorization(
            request_token,
            user_id,
            verifier,
            callback_url
        )
        return {
            'oauth_token': request_token,
            'oauth_verifier': verifier,
        }

    async def access_token(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Exchange request token for access token (RFC 5849 Section 2.3).
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body
        Returns:
            Access token response
        """
        # Validate request
        validated = await self._validator.validate_request(method, url, headers, body)
        request_token = validated.get('token')
        if not request_token:
            raise XWInvalidRequestError(
                "oauth_token required",
                error_code="invalid_request"
            )
        # Get verifier from parameters
        oauth_params = validated.get('oauth_params', {})
        verifier = oauth_params.get('oauth_verifier')
        if not verifier:
            raise XWInvalidRequestError(
                "oauth_verifier required",
                error_code="invalid_request"
            )
        # Verify authorization
        auth_data = await self._get_authorization(request_token, verifier)
        if not auth_data:
            raise XWInvalidRequestError(
                "Invalid request token or verifier",
                error_code="invalid_token"
            )
        # Generate access token
        access_token = self._generate_token()
        access_token_secret = self._generate_token_secret()
        # Store access token
        await self._store_access_token(
            access_token,
            access_token_secret,
            validated['consumer_key'],
            auth_data['user_id']
        )
        # Delete request token (one-time use)
        await self._delete_request_token(request_token)
        return {
            'oauth_token': access_token,
            'oauth_token_secret': access_token_secret,
        }

    def _generate_token(self) -> str:
        """Generate OAuth 1.0 token."""
        random_bytes = secrets.token_bytes(16)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')

    def _generate_token_secret(self) -> str:
        """Generate OAuth 1.0 token secret."""
        random_bytes = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')

    def _generate_verifier(self) -> str:
        """Generate OAuth 1.0 verifier."""
        random_bytes = secrets.token_bytes(8)
        return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')

    async def _store_request_token(
        self,
        token: str,
        token_secret: str,
        consumer_key: str
    ) -> None:
        """Store request token in storage."""
        token_data = {
            'token': token,
            'token_secret': token_secret,
            'consumer_key': consumer_key,
            'type': 'request',
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(minutes=10)).isoformat(),
        }
        if hasattr(self._storage, 'write'):
            await self._storage.write(f"oauth1_token:{token}", token_data)
        else:
            if not hasattr(self._storage, '_oauth1_tokens'):
                self._storage._oauth1_tokens = {}
            self._storage._oauth1_tokens[token] = token_data

    async def _get_request_token(self, token: str) -> Optional[dict[str, Any]]:
        """Get request token from storage."""
        if hasattr(self._storage, 'read'):
            return await self._storage.read(f"oauth1_token:{token}")
        else:
            if hasattr(self._storage, '_oauth1_tokens'):
                return self._storage._oauth1_tokens.get(token)
        return None

    async def _delete_request_token(self, token: str) -> None:
        """Delete request token from storage."""
        if hasattr(self._storage, 'delete'):
            await self._storage.delete(f"oauth1_token:{token}")
        else:
            if hasattr(self._storage, '_oauth1_tokens'):
                self._storage._oauth1_tokens.pop(token, None)

    async def _store_authorization(
        self,
        request_token: str,
        user_id: str,
        verifier: str,
        callback_url: Optional[str]
    ) -> None:
        """Store authorization data."""
        auth_data = {
            'request_token': request_token,
            'user_id': user_id,
            'verifier': verifier,
            'callback_url': callback_url,
            'created_at': datetime.now().isoformat(),
        }
        if hasattr(self._storage, 'write'):
            await self._storage.write(f"oauth1_auth:{request_token}:{verifier}", auth_data)
        else:
            if not hasattr(self._storage, '_oauth1_authorizations'):
                self._storage._oauth1_authorizations = {}
            self._storage._oauth1_authorizations[f"{request_token}:{verifier}"] = auth_data

    async def _get_authorization(
        self,
        request_token: str,
        verifier: str
    ) -> Optional[dict[str, Any]]:
        """Get authorization data."""
        if hasattr(self._storage, 'read'):
            return await self._storage.read(f"oauth1_auth:{request_token}:{verifier}")
        else:
            if hasattr(self._storage, '_oauth1_authorizations'):
                return self._storage._oauth1_authorizations.get(f"{request_token}:{verifier}")
        return None

    async def _store_access_token(
        self,
        token: str,
        token_secret: str,
        consumer_key: str,
        user_id: str
    ) -> None:
        """Store access token in storage."""
        token_data = {
            'token': token,
            'token_secret': token_secret,
            'consumer_key': consumer_key,
            'user_id': user_id,
            'type': 'access',
            'created_at': datetime.now().isoformat(),
        }
        if hasattr(self._storage, 'write'):
            await self._storage.write(f"oauth1_token:{token}", token_data)
        else:
            if not hasattr(self._storage, '_oauth1_tokens'):
                self._storage._oauth1_tokens = {}
            self._storage._oauth1_tokens[token] = token_data
