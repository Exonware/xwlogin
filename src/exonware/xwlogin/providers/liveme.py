#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/liveme.py
LiveMe OAuth Provider
LiveMe OAuth 2.0 provider implementation.
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


class LiveMeProvider(ABaseProvider):
    """LiveMe OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://auth.liveme.com/oauth/authorize"
    TOKEN_URL = "https://auth.liveme.com/oauth/token"
    USERINFO_URL = "https://api.liveme.com/v1/user/profile"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize LiveMe provider.
        Args:
            client_id: LiveMe Client ID
            client_secret: LiveMe Client Secret
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
        return "liveme"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.LIVEME

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from LiveMe.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize LiveMe user info format
        return {
            'id': str(user_info.get('user_id')),
            'username': user_info.get('username'),
            'nickname': user_info.get('nickname'),
            'avatar_url': user_info.get('avatar'),
        }
