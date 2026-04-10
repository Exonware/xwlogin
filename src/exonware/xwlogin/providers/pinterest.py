#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/pinterest.py
Pinterest OAuth Provider
Pinterest OAuth 2.0 provider implementation.
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


class PinterestProvider(ABaseProvider):
    """Pinterest OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.pinterest.com/oauth"
    TOKEN_URL = "https://api.pinterest.com/v5/oauth/token"
    USERINFO_URL = "https://api.pinterest.com/v5/user_account"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Pinterest provider.
        Args:
            client_id: Pinterest OAuth client ID
            client_secret: Pinterest OAuth client secret
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
        return "pinterest"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CUSTOM  # Pinterest not in enum yet

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Pinterest.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Pinterest user info format
        return {
            'id': user_info.get('username'),
            'username': user_info.get('username'),
            'profile_url': user_info.get('profile_url'),
        }
