#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/deezer.py
Deezer OAuth Provider
Deezer OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class DeezerProvider(ABaseProvider):
    """Deezer OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://connect.deezer.com/oauth/auth.php"
    TOKEN_URL = "https://connect.deezer.com/oauth/access_token.php"
    USERINFO_URL = "https://api.deezer.com/user/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Deezer provider.
        Args:
            client_id: Deezer App ID
            client_secret: Deezer App Secret
            **kwargs: Additional configuration
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.USERINFO_URL,
            **kwargs
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "deezer"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.DEEZER

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token.
        Deezer returns token in query string format, not JSON.
        Args:
            code: Authorization code
            redirect_uri: Redirect URI
        Returns:
            Token response dictionary
        """
        params = {
            'app_id': self._client_id,
            'secret': self._client_secret,
            'code': code,
            'output': 'json',
        }
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self._token_url,
            params=params
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Token exchange failed: {response.status_code}",
                error_code="token_exchange_failed",
                context={'status_code': response.status_code, 'response': response.text}
            )
        return response.json()

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Deezer.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Deezer requires access_token as query parameter
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?access_token={access_token}"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Deezer user info format
        return {
            'id': str(user_info.get('id')),
            'name': user_info.get('name'),
            'username': user_info.get('name'),
            'avatar_url': user_info.get('picture_medium'),
        }
