#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/epic_games.py
Epic Games OAuth Provider
Epic Games / Epic Online Services (EOS) OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class EpicGamesProvider(ABaseProvider):
    """Epic Games / Epic Online Services (EOS) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.epicgames.com/id/authorize"
    TOKEN_URL = "https://api.epicgames.dev/auth/v1/oauth/token"
    USERINFO_URL = "https://api.epicgames.dev/epic/oauth/v1/userInfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Epic Games provider.
        Args:
            client_id: Epic Games Client ID
            client_secret: Epic Games Client Secret
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
        return "epic_games"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.EPIC_GAMES

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Epic Games.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Epic Games user info format
        return {
            'id': user_info.get('sub'),
            'email': user_info.get('email'),
            'display_name': user_info.get('displayName'),
            'preferred_username': user_info.get('preferred_username'),
        }
