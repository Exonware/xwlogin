#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/douyin.py
Douyin OAuth Provider
Douyin (抖音) OAuth 2.0 provider implementation.
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


class DouyinProvider(ABaseProvider):
    """Douyin (抖音) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://open.douyin.com/platform/oauth/connect"
    TOKEN_URL = "https://open.douyin.com/oauth/access_token"
    USERINFO_URL = "https://open.douyin.com/oauth/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Douyin provider.
        Args:
            client_id: Douyin Client Key
            client_secret: Douyin Client Secret
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
        return "douyin"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.DOUYIN

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Douyin.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Douyin user info format
        data = user_info.get('data', user_info)
        return {
            'id': str(data.get('open_id')),
            'nickname': data.get('nickname'),
            'avatar_url': data.get('avatar'),
        }
