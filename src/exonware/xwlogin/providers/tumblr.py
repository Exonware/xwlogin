#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tumblr.py
Tumblr OAuth Provider
Tumblr OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class TumblrProvider(ABaseProvider):
    """Tumblr OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.tumblr.com/oauth2/authorize"
    TOKEN_URL = "https://api.tumblr.com/v2/oauth2/token"
    USERINFO_URL = "https://api.tumblr.com/v2/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Tumblr provider.
        Args:
            client_id: Tumblr OAuth client ID
            client_secret: Tumblr OAuth client secret
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
        return "tumblr"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CUSTOM  # Tumblr not in enum yet

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Tumblr.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Tumblr returns user info in 'user' field
        user_data = user_info.get('user', user_info)
        # Normalize Tumblr user info format
        return {
            'id': str(user_data.get('name')),
            'username': user_data.get('name'),
            'blogs': user_data.get('blogs', []),
        }
