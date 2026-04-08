#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/steam.py
Steam OAuth Provider
Steam OpenID provider implementation (Steam uses OpenID, not OAuth 2.0).
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


class SteamProvider(ABaseProvider):
    """
    Steam authentication provider.
    Note: Steam uses OpenID 2.0, not OAuth 2.0.
    This is a simplified implementation that may need OpenID support.
    """
    # Steam OpenID endpoints
    AUTHORIZATION_URL = "https://steamcommunity.com/openid/login"
    TOKEN_URL = "https://steamcommunity.com/openid/login"  # OpenID doesn't use token endpoint
    USERINFO_URL = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/"

    def __init__(self, client_id: str, client_secret: str = "", **kwargs):
        """
        Initialize Steam provider.
        Args:
            client_id: Steam API Key
            client_secret: Not used for Steam (OpenID doesn't require secret)
            **kwargs: Additional configuration
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret or "",
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.USERINFO_URL,
            **kwargs
        )
        logger.warning(
            "Steam uses OpenID 2.0, not OAuth 2.0. "
            "This implementation may need OpenID support for full functionality."
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "steam"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.STEAM

    async def get_user_info(self, steam_id: str) -> dict[str, Any]:
        """
        Get user information from Steam.
        Note: Steam requires Steam ID from OpenID response, then API call.
        Args:
            steam_id: Steam ID (64-bit Steam ID)
        Returns:
            User information dictionary
        """
        # Steam requires API key and Steam ID
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?key={self._client_id}&steamids={steam_id}"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        data = response.json()
        players = data.get('response', {}).get('players', [])
        user_info = players[0] if players else {}
        # Normalize Steam user info format
        return {
            'id': user_info.get('steamid'),
            'username': user_info.get('personaname'),
            'avatar_url': user_info.get('avatarfull'),
            'profile_url': user_info.get('profileurl'),
        }
