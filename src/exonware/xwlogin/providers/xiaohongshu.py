#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/xiaohongshu.py
Xiaohongshu OAuth Provider
Xiaohongshu (小红书) OAuth 2.0 provider implementation.
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


class XiaohongshuProvider(ABaseProvider):
    """Xiaohongshu (小红书) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://creator.xiaohongshu.com/oauth/authorize"
    TOKEN_URL = "https://creator.xiaohongshu.com/oauth/token"
    USERINFO_URL = "https://creator.xiaohongshu.com/api/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Xiaohongshu provider.
        Args:
            client_id: Xiaohongshu App ID
            client_secret: Xiaohongshu App Secret
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
        return "xiaohongshu"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.XIAOHONGSHU

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Xiaohongshu.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Xiaohongshu user info format
        data = user_info.get('data', user_info)
        return {
            'id': str(data.get('user_id')),
            'nickname': data.get('nickname'),
            'avatar_url': data.get('avatar'),
        }
