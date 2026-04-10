#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/zhipu_ai.py
Zhipu AI OAuth Provider
Zhipu AI OAuth 2.0 provider implementation.
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


class ZhipuAIProvider(ABaseProvider):
    """Zhipu AI OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://open.bigmodel.cn/oauth/authorize"
    TOKEN_URL = "https://open.bigmodel.cn/oauth/token"
    USERINFO_URL = "https://open.bigmodel.cn/api/paas/v4/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Zhipu AI provider.
        Args:
            client_id: Zhipu AI API Key
            client_secret: Zhipu AI API Secret
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
        return "zhipu_ai"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ZHIPU_AI

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Zhipu AI.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Zhipu AI user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
        }
