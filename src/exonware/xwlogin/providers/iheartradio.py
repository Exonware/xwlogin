#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/iheartradio.py
iHeartRadio OAuth Provider
iHeartRadio OAuth 2.0 provider implementation.
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


class IHeartRadioProvider(ABaseProvider):
    """iHeartRadio OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://api.iheart.com/oauth/authorize"
    TOKEN_URL = "https://api.iheart.com/oauth/token"
    USERINFO_URL = "https://api.iheart.com/api/v3/user/profile"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize iHeartRadio provider.
        Args:
            client_id: iHeartRadio Client ID
            client_secret: iHeartRadio Client Secret
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
        return "iheartradio"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.IHEARTRADIO

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from iHeartRadio.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize iHeartRadio user info format
        return {
            'id': str(user_info.get('userId')),
            'email': user_info.get('email'),
            'username': user_info.get('username'),
            'name': user_info.get('displayName'),
        }
