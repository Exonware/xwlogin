#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/twitch.py
Twitch OAuth Provider
Twitch OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class TwitchProvider(ABaseProvider):
    """Twitch OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://id.twitch.tv/oauth2/authorize"
    TOKEN_URL = "https://id.twitch.tv/oauth2/token"
    USERINFO_URL = "https://api.twitch.tv/helix/users"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Twitch provider.
        Args:
            client_id: Twitch Client ID
            client_secret: Twitch Client Secret
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
        return "twitch"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.TWITCH

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Twitch.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Twitch requires Client-ID header in addition to Bearer token
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={
                'Authorization': f'Bearer {access_token}',
                'Client-ID': self._client_id
            }
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        data = response.json()
        user_info = data.get('data', [{}])[0] if data.get('data') else {}
        # Normalize Twitch user info format
        return {
            'id': user_info.get('id'),
            'login': user_info.get('login'),
            'display_name': user_info.get('display_name'),
            'email': user_info.get('email'),
            'profile_image_url': user_info.get('profile_image_url'),
            'broadcaster_type': user_info.get('broadcaster_type'),
        }
