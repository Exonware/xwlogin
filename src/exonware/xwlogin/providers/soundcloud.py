#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/soundcloud.py
SoundCloud OAuth Provider
SoundCloud OAuth 2.0 provider implementation.
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


class SoundCloudProvider(ABaseProvider):
    """SoundCloud OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://soundcloud.com/connect"
    TOKEN_URL = "https://api.soundcloud.com/oauth2/token"
    USERINFO_URL = "https://api.soundcloud.com/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize SoundCloud provider.
        Args:
            client_id: SoundCloud OAuth client ID
            client_secret: SoundCloud OAuth client secret
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
        return "soundcloud"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.SOUNDCLOUD

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from SoundCloud.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize SoundCloud user info format
        return {
            'id': str(user_info.get('id')),
            'username': user_info.get('username'),
            'full_name': user_info.get('full_name'),
            'avatar_url': user_info.get('avatar_url'),
            'city': user_info.get('city'),
            'country': user_info.get('country'),
        }
