#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/oauth1/client.py
OAuth 1.0 Client Implementation
Implements OAuth 1.0 client for making authenticated requests (RFC 5849).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any
from urllib.parse import urlencode
from exonware.xwsystem import get_logger
from .signature import OAuth1Signature
logger = get_logger(__name__)


class OAuth1Client:
    """
    OAuth 1.0 client for making authenticated requests (RFC 5849).
    Handles OAuth 1.0 three-legged flow from client side.
    """

    def __init__(
        self,
        consumer_key: str,
        consumer_secret: str,
        request_token_url: str,
        authorization_url: str,
        access_token_url: str
    ):
        """
        Initialize OAuth 1.0 client.
        Args:
            consumer_key: Consumer key (client ID)
            consumer_secret: Consumer secret (client secret)
            request_token_url: Request token endpoint URL
            authorization_url: Authorization endpoint URL
            access_token_url: Access token endpoint URL
        """
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self._request_token_url = request_token_url
        self._authorization_url = authorization_url
        self._access_token_url = access_token_url
        logger.debug("OAuth1Client initialized")

    def get_authorization_url(
        self,
        request_token: str,
        callback_url: str | None = None
    ) -> str:
        """
        Get authorization URL for user authorization.
        Args:
            request_token: Request token
            callback_url: Callback URL (optional)
        Returns:
            Authorization URL
        """
        params = {'oauth_token': request_token}
        if callback_url:
            params['oauth_callback'] = callback_url
        query_string = urlencode(params)
        return f"{self._authorization_url}?{query_string}"

    def sign_request(
        self,
        method: str,
        url: str,
        parameters: dict[str, Any] | None = None,
        token: str | None = None,
        token_secret: str | None = None
    ) -> dict[str, str]:
        """
        Sign OAuth 1.0 request.
        Args:
            method: HTTP method
            url: Request URL
            parameters: Request parameters
            token: OAuth token (optional)
            token_secret: Token secret (optional)
        Returns:
            Authorization header value
        """
        # Build OAuth parameters
        oauth_params = {
            'oauth_consumer_key': self._consumer_key,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(OAuth1Signature.generate_timestamp()),
            'oauth_nonce': OAuth1Signature.generate_nonce(),
            'oauth_version': '1.0',
        }
        if token:
            oauth_params['oauth_token'] = token
        # OAuth-prefixed request parameters (e.g., oauth_callback) are part of
        # Authorization header in our integration flow and must be included both
        # in signature base string and transmitted OAuth params.
        if parameters:
            for key, value in parameters.items():
                if str(key).startswith("oauth_"):
                    oauth_params[key] = value
        # Merge with request parameters for signature base string
        all_params = oauth_params.copy()
        if parameters:
            all_params.update(parameters)
        # Generate signature
        base_string = OAuth1Signature.generate_signature_base_string(
            method, url, all_params
        )
        signature = OAuth1Signature.generate_signature(
            base_string,
            self._consumer_secret,
            token_secret or ''
        )
        oauth_params['oauth_signature'] = signature
        # Build Authorization header
        oauth_string = ', '.join([
            f'{OAuth1Signature._percent_encode(k)}="{OAuth1Signature._percent_encode(str(v))}"'
            for k, v in sorted(oauth_params.items())
        ])
        return {'Authorization': f'OAuth {oauth_string}'}
