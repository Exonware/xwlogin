#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/yandex.py
Yandex OAuth Provider
Yandex OAuth 2.0 provider implementation.
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


class YandexProvider(ABaseProvider):
    """Yandex OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://oauth.yandex.ru/authorize"
    TOKEN_URL = "https://oauth.yandex.ru/token"
    USERINFO_URL = "https://login.yandex.ru/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Yandex provider.
        Args:
            client_id: Yandex OAuth client ID
            client_secret: Yandex OAuth client secret
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
        return "yandex"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.YANDEX

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Yandex.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Yandex user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('default_email'),
            'name': user_info.get('real_name'),
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'avatar_url': user_info.get('default_avatar_id'),
            'login': user_info.get('login'),
        }
