#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/wordpress.py
WordPress OAuth Provider
WordPress.com OAuth 2.0 provider implementation.
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


class WordPressProvider(ABaseProvider):
    """WordPress.com OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://public-api.wordpress.com/oauth2/authorize"
    TOKEN_URL = "https://public-api.wordpress.com/oauth2/token"
    USERINFO_URL = "https://public-api.wordpress.com/rest/v1.1/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize WordPress provider.
        Args:
            client_id: WordPress OAuth client ID
            client_secret: WordPress OAuth client secret
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
        return "wordpress"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.WORDPRESS

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from WordPress.com.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize WordPress user info format
        return {
            'id': str(user_info.get('ID')),
            'email': user_info.get('email'),
            'name': user_info.get('display_name'),
            'username': user_info.get('username'),
            'avatar_url': user_info.get('avatar_URL'),
        }
