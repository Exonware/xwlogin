#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/zhihu.py
Zhihu OAuth Provider
Zhihu (知乎) OAuth 2.0 provider implementation.
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


class ZhihuProvider(ABaseProvider):
    """Zhihu (知乎) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.zhihu.com/oauth/authorize"
    TOKEN_URL = "https://www.zhihu.com/oauth/token"
    USERINFO_URL = "https://www.zhihu.com/api/v4/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Zhihu provider.
        Args:
            client_id: Zhihu Client ID
            client_secret: Zhihu Client Secret
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
        return "zhihu"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ZHIHU

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Zhihu.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Zhihu user info format
        return {
            'id': str(user_info.get('id')),
            'name': user_info.get('name'),
            'avatar_url': user_info.get('avatar_url'),
            'headline': user_info.get('headline'),
        }
