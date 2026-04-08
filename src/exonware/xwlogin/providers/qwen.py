#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/qwen.py
Qwen OAuth Provider
Qwen AI OAuth 2.0 provider implementation (Alibaba's Qwen model).
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


class QwenProvider(ABaseProvider):
    """Qwen AI OAuth 2.0 provider (Alibaba's Qwen model)."""
    # Qwen uses Alibaba Cloud OAuth (same as Tongyi)
    AUTHORIZATION_URL = "https://signin.aliyun.com/oauth2/v1/auth"
    TOKEN_URL = "https://oauth.aliyun.com/oauth2/v1/token"
    USERINFO_URL = "https://dashscope.aliyuncs.com/api/v1/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Qwen provider.
        Args:
            client_id: Alibaba Cloud OAuth Client ID
            client_secret: Alibaba Cloud OAuth Client Secret
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
        return "qwen"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.QWEN

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Qwen.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Qwen user info format
        return {
            'id': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
        }
