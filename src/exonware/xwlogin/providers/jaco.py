#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/jaco.py
JACO OAuth Provider
JACO OAuth 2.0 provider implementation.
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


class JACOProvider(ABaseProvider):
    """JACO OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://api.jaco.tv/oauth/authorize"
    TOKEN_URL = "https://api.jaco.tv/oauth/token"
    USERINFO_URL = "https://api.jaco.tv/v1/user/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize JACO provider.
        Args:
            client_id: JACO Client ID
            client_secret: JACO Client Secret
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
        return "jaco"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.JACO

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from JACO.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize JACO user info format
        return {
            'id': str(user_info.get('id')),
            'username': user_info.get('username'),
            'name': user_info.get('display_name'),
            'avatar_url': user_info.get('avatar_url'),
        }
