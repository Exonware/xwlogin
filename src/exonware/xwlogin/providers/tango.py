#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tango.py
Tango OAuth Provider
Tango OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class TangoProvider(ABaseProvider):
    """Tango OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://api.tango.me/oauth/authorize"
    TOKEN_URL = "https://api.tango.me/oauth/token"
    USERINFO_URL = "https://api.tango.me/v2/user/profile"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Tango provider.
        Args:
            client_id: Tango Client ID
            client_secret: Tango Client Secret
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
        return "tango"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.TANGO

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Tango.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Tango user info format
        return {
            'id': str(user_info.get('user_id')),
            'username': user_info.get('username'),
            'name': user_info.get('display_name'),
            'avatar_url': user_info.get('avatar'),
        }
