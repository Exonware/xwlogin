#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/nintendo.py
Nintendo OAuth Provider
Nintendo Account OAuth 2.0 provider implementation.
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


class NintendoProvider(ABaseProvider):
    """Nintendo Account OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://accounts.nintendo.com/connect/1.0.0/authorize"
    TOKEN_URL = "https://accounts.nintendo.com/connect/1.0.0/api/token"
    USERINFO_URL = "https://api.accounts.nintendo.com/2.0.0/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Nintendo provider.
        Args:
            client_id: Nintendo Client ID
            client_secret: Nintendo Client Secret
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
        return "nintendo"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.NINTENDO

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Nintendo Account.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Nintendo user info format
        return {
            'id': user_info.get('id'),
            'nickname': user_info.get('nickname'),
            'email': user_info.get('email'),
            'language': user_info.get('language'),
        }
