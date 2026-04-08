#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/iflytek.py
iFlytek OAuth Provider
iFlytek Spark AI OAuth 2.0 provider implementation.
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


class IFlytekProvider(ABaseProvider):
    """iFlytek Spark AI OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://openapi.xfyun.cn/oauth/authorize"
    TOKEN_URL = "https://openapi.xfyun.cn/oauth/token"
    USERINFO_URL = "https://openapi.xfyun.cn/v1/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize iFlytek provider.
        Args:
            client_id: iFlytek App ID
            client_secret: iFlytek API Secret
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
        return "iflytek"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.IFlyTEK

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from iFlytek.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize iFlytek user info format
        return {
            'id': str(user_info.get('uid')),
            'name': user_info.get('name'),
        }
