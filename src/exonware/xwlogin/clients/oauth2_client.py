#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/clients/oauth2_client.py
OAuth 2.0 Client (Enhanced)
Enhanced OAuth 2.0 client with async support and multiple HTTP backends.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs
from exonware.xwsystem import get_logger
logger = get_logger(__name__)
# Try to import HTTP clients
try:
    import httpx
    USE_HTTPX = True
except ImportError:
    USE_HTTPX = False
try:
    import aiohttp
    USE_AIOHTTP = True
except ImportError:
    USE_AIOHTTP = False
try:
    import requests
    USE_REQUESTS = True
except ImportError:
    USE_REQUESTS = False


class OAuth2Session:
    """
    OAuth 2.0 client session (similar to requests-oauthlib).
    Supports multiple HTTP backends (httpx, aiohttp, requests).
    Format-agnostic - works with any HTTP client.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        token: Optional[dict[str, Any]] = None,
        http_backend: str = "httpx"  # httpx, aiohttp, requests
    ):
        """
        Initialize OAuth 2.0 session.
        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret (optional for public clients)
            token: Existing token dictionary (optional)
            http_backend: HTTP client backend ("httpx", "aiohttp", "requests")
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self._token = token
        self._http_backend = http_backend
        logger.debug(f"OAuth2Session initialized with {http_backend} backend")

    def authorization_url(
        self,
        authorization_url: str,
        redirect_uri: Optional[str] = None,
        scope: Optional[list[str]] = None,
        state: Optional[str] = None,
        **kwargs
    ) -> tuple[str, str]:
        """
        Get authorization URL and state.
        Args:
            authorization_url: Authorization endpoint URL
            redirect_uri: Redirect URI
            scope: List of scopes
            state: State parameter (auto-generated if not provided)
            **kwargs: Additional parameters
        Returns:
            Tuple of (authorization_url, state)
        """
        from exonware.xwsystem.security.hazmat import secure_random
        import base64
        if not state:
            random_bytes = secure_random(16)
            state = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        params = {
            'response_type': 'code',
            'client_id': self._client_id,
            'state': state,
            **kwargs
        }
        if redirect_uri:
            params['redirect_uri'] = redirect_uri
        if scope:
            params['scope'] = ' '.join(scope)
        query_string = urlencode(params)
        full_url = f"{authorization_url}?{query_string}"
        return full_url, state

    async def fetch_token(
        self,
        token_url: str,
        code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        grant_type: str = "authorization_code",
        **kwargs
    ) -> dict[str, Any]:
        """
        Fetch access token from token endpoint.
        Args:
            token_url: Token endpoint URL
            code: Authorization code (for authorization_code grant)
            redirect_uri: Redirect URI
            grant_type: Grant type
            **kwargs: Additional parameters
        Returns:
            Token response dictionary
        """
        data = {
            'grant_type': grant_type,
            'client_id': self._client_id,
            **kwargs
        }
        if code:
            data['code'] = code
        if redirect_uri:
            data['redirect_uri'] = redirect_uri
        if self._client_secret:
            data['client_secret'] = self._client_secret
        # Use appropriate HTTP backend
        if self._http_backend == "httpx" and USE_HTTPX:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_url,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                response.raise_for_status()
                token_data = response.json()
        elif self._http_backend == "aiohttp" and USE_AIOHTTP:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    token_url,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                ) as response:
                    response.raise_for_status()
                    token_data = await response.json()
        elif self._http_backend == "requests" and USE_REQUESTS:
            response = requests.post(
                token_url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            response.raise_for_status()
            token_data = response.json()
        else:
            raise ValueError(f"HTTP backend {self._http_backend} not available")
        self._token = token_data
        return token_data

    async def refresh_token(
        self,
        token_url: str,
        refresh_token: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Refresh access token.
        Args:
            token_url: Token endpoint URL
            refresh_token: Refresh token (uses stored token if not provided)
        Returns:
            New token response dictionary
        """
        if not refresh_token:
            refresh_token = self._token.get('refresh_token') if self._token else None
        if not refresh_token:
            raise ValueError("Refresh token required")
        return await self.fetch_token(
            token_url,
            grant_type='refresh_token',
            refresh_token=refresh_token
        )

    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Any:
        """
        Make authenticated request using access token.
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
        Returns:
            HTTP response
        """
        if not self._token:
            raise ValueError("No token available. Call fetch_token() first.")
        access_token = self._token.get('access_token')
        if not access_token:
            raise ValueError("No access token in token data")
        # Add Authorization header
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f"Bearer {access_token}"
        kwargs['headers'] = headers
        # Use appropriate HTTP backend
        if self._http_backend == "httpx" and USE_HTTPX:
            async with httpx.AsyncClient() as client:
                response = await client.request(method, url, **kwargs)
                return response
        elif self._http_backend == "aiohttp" and USE_AIOHTTP:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, **kwargs) as response:
                    return response
        elif self._http_backend == "requests" and USE_REQUESTS:
            return requests.request(method, url, **kwargs)
        else:
            raise ValueError(f"HTTP backend {self._http_backend} not available")
