#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/netlify.py
Netlify OAuth Provider
Netlify OAuth 2.0 provider implementation.
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


class NetlifyProvider(ABaseProvider):
    """Netlify OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://app.netlify.com/authorize"
    TOKEN_URL = "https://api.netlify.com/oauth/token"
    USERINFO_URL = "https://api.netlify.com/api/v1/user"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Netlify provider.
        Args:
            client_id: Netlify Client ID
            client_secret: Netlify Client Secret
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
        return "netlify"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.NETLIFY

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Netlify.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Netlify user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('full_name'),
            'username': user_info.get('username'),
            'avatar_url': user_info.get('avatar_url'),
        }
