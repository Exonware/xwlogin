#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/playstation.py
PlayStation OAuth Provider
PlayStation Network (PSN) OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class PlayStationProvider(ABaseProvider):
    """PlayStation Network (PSN) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize"
    TOKEN_URL = "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/token"
    USERINFO_URL = "https://us-prof.np.community.playstation.net/userProfile/v1/users/me/profile2"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize PlayStation provider.
        Args:
            client_id: PlayStation Client ID
            client_secret: PlayStation Client Secret
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
        return "playstation"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.PLAYSTATION

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from PlayStation Network.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # PSN requires specific headers
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        profile = user_info.get('profile', {})
        # Normalize PlayStation user info format
        return {
            'id': profile.get('onlineId'),
            'username': profile.get('onlineId'),
            'avatar_url': profile.get('avatarUrls', [{}])[0].get('avatarUrl') if profile.get('avatarUrls') else None,
        }
