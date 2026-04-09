#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/bigo_live.py
Bigo Live OAuth Provider
Bigo Live OAuth 2.0 provider implementation.
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


class BigoLiveProvider(ABaseProvider):
    """Bigo Live OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://api.bigo.sg/oauth/authorize"
    TOKEN_URL = "https://api.bigo.sg/oauth/token"
    USERINFO_URL = "https://api.bigo.sg/v1/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Bigo Live provider.
        Args:
            client_id: Bigo Live Client ID
            client_secret: Bigo Live Client Secret
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
        return "bigo_live"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.BIGO_LIVE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Bigo Live.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Bigo Live user info format
        data = user_info.get('data', user_info)
        return {
            'id': str(data.get('uid')),
            'username': data.get('username'),
            'nickname': data.get('nickname'),
            'avatar_url': data.get('avatar'),
        }
