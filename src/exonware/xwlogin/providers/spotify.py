#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/spotify.py
Spotify OAuth Provider
Spotify OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class SpotifyProvider(ABaseProvider):
    """Spotify OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://accounts.spotify.com/authorize"
    TOKEN_URL = "https://accounts.spotify.com/api/token"
    USERINFO_URL = "https://api.spotify.com/v1/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Spotify provider.
        Args:
            client_id: Spotify OAuth client ID
            client_secret: Spotify OAuth client secret
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
        return "spotify"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CUSTOM  # Spotify not in enum yet

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Spotify.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Spotify user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('email'),
            'display_name': user_info.get('display_name'),
            'country': user_info.get('country'),
            'images': user_info.get('images', []),
            'product': user_info.get('product'),  # free, premium, etc.
        }
