#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/oauth1/request_validator.py
OAuth 1.0 Request Validator
Validates OAuth 1.0 requests according to RFC 5849.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from datetime import datetime, timedelta
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWInvalidRequestError, XWUnauthorizedClientError
from .signature import OAuth1Signature
logger = get_logger(__name__)


class OAuth1RequestValidator:
    """
    OAuth 1.0 request validator (RFC 5849).
    Validates OAuth 1.0 requests including signature verification.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize OAuth 1.0 request validator.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        self._storage = auth.storage
        logger.debug("OAuth1RequestValidator initialized")

    async def validate_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Validate OAuth 1.0 request.
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body (optional)
        Returns:
            Validated request data with consumer_key, token, etc.
        Raises:
            XWInvalidRequestError: If request is invalid
        """
        # Extract OAuth parameters from Authorization header
        oauth_params = self._extract_oauth_params(headers)
        # Validate required OAuth parameters
        required_params = ['oauth_consumer_key', 'oauth_signature_method', 'oauth_signature', 'oauth_timestamp', 'oauth_nonce']
        for param in required_params:
            if param not in oauth_params:
                raise XWInvalidRequestError(
                    f"Missing required OAuth parameter: {param}",
                    error_code="invalid_request"
                )
        # Validate signature method
        if oauth_params['oauth_signature_method'] != 'HMAC-SHA1':
            raise XWInvalidRequestError(
                "Unsupported signature method. Only HMAC-SHA1 is supported",
                error_code="invalid_request"
            )
        # Validate timestamp (within 5 minutes)
        timestamp = int(oauth_params['oauth_timestamp'])
        now = int(datetime.now().timestamp())
        if abs(now - timestamp) > 300:  # 5 minutes
            raise XWInvalidRequestError(
                "OAuth timestamp too old or too far in future",
                error_code="invalid_request"
            )
        # Get consumer (client) from storage
        consumer_key = oauth_params['oauth_consumer_key']
        consumer = await self._get_consumer(consumer_key)
        if not consumer:
            raise XWUnauthorizedClientError(
                "Invalid consumer key",
                error_code="invalid_consumer"
            )
        # Get token if provided
        token_key = oauth_params.get('oauth_token')
        token_secret = ""
        if token_key:
            token_data = await self._get_token(token_key)
            if token_data:
                token_secret = token_data.get('token_secret', '')
        # Collect all parameters for signature verification
        # OAuth 1.0 signature includes: OAuth params + query string + body params
        from urllib.parse import parse_qs, urlparse
        body_param_dict: dict[str, str] = {}
        all_params = oauth_params.copy()
        # Extract query string parameters from URL
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            for key, values in query_params.items():
                if values:
                    val = values[0]
                    if key not in all_params:
                        all_params[key] = val
        # Extract body parameters
        if body:
            body_params = parse_qs(body)
            for key, values in body_params.items():
                if values:
                    val = values[0]
                    body_param_dict[key] = val
                    if key not in all_params:
                        all_params[key] = val
        # Verify signature
        provided_signature = oauth_params['oauth_signature']
        is_valid = OAuth1Signature.verify_signature(
            method=method,
            url=url,
            parameters=all_params,
            consumer_secret=consumer.get('consumer_secret', ''),
            token_secret=token_secret,
            provided_signature=provided_signature
        )
        if not is_valid:
            raise XWUnauthorizedClientError(
                "Invalid OAuth signature",
                error_code="invalid_signature"
            )
        # Merge body params (e.g. oauth_verifier) into oauth_params so access_token can use them
        merged_oauth = {**body_param_dict, **oauth_params}
        return {
            'consumer_key': consumer_key,
            'token': token_key,
            'oauth_params': merged_oauth,
        }

    def _extract_oauth_params(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Extract OAuth parameters from Authorization header.
        Args:
            headers: Request headers
        Returns:
            Dictionary of OAuth parameters
        """
        auth_header = headers.get('Authorization', '')
        if not auth_header.startswith('OAuth '):
            raise XWInvalidRequestError(
                "Missing or invalid Authorization header",
                error_code="invalid_request"
            )
        # Parse OAuth parameters (percent-encoded in header; decode for base-string reuse)
        from urllib.parse import unquote
        oauth_string = auth_header[6:]  # Remove "OAuth "
        params = {}
        for pair in oauth_string.split(','):
            pair = pair.strip()
            if '=' in pair:
                key, value = pair.split('=', 1)
                key = unquote(key.strip().strip('"'))
                value = unquote(value.strip().strip('"'))
                params[key] = value
        return params

    async def _get_consumer(self, consumer_key: str) -> Optional[dict[str, Any]]:
        """
        Get consumer (OAuth 1.0 client) from storage.
        Args:
            consumer_key: Consumer key
        Returns:
            Consumer data or None
        """
        # Try to get from storage
        if hasattr(self._storage, 'read'):
            consumer_data = await self._storage.read(f"oauth1_consumer:{consumer_key}")
            if consumer_data:
                return consumer_data
        # Fallback: check registered clients (convert OAuth 2.0 client to OAuth 1.0 consumer)
        client = self._config.get_registered_client(consumer_key)
        if client:
            return {
                'consumer_key': consumer_key,
                'consumer_secret': client.get('client_secret', ''),
            }
        return None

    async def _get_token(self, token_key: str) -> Optional[dict[str, Any]]:
        """
        Get OAuth 1.0 token from storage.
        Args:
            token_key: Token key
        Returns:
            Token data or None
        """
        # Try to get from storage
        if hasattr(self._storage, 'read'):
            token_data = await self._storage.read(f"oauth1_token:{token_key}")
            if token_data:
                return token_data
        else:
            # Fallback: check _oauth1_tokens dict (for MockStorageProvider)
            if hasattr(self._storage, '_oauth1_tokens'):
                return self._storage._oauth1_tokens.get(token_key)
        return None
