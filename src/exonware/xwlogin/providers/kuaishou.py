#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/kuaishou.py
Kuaishou OAuth Provider
Kuaishou (快手) OAuth 2.0 provider implementation.
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


class KuaishouProvider(ABaseProvider):
    """Kuaishou (快手) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://open.kuaishou.com/oauth2/authorize"
    TOKEN_URL = "https://open.kuaishou.com/oauth2/access_token"
    USERINFO_URL = "https://open.kuaishou.com/openapi/user_info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Kuaishou provider.
        Args:
            client_id: Kuaishou App ID
            client_secret: Kuaishou App Secret
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
        return "kuaishou"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.KUAISHOU

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Kuaishou.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Kuaishou user info format
        data = user_info.get('data', user_info)
        return {
            'id': str(data.get('open_id')),
            'nickname': data.get('nickname'),
            'avatar_url': data.get('avatar'),
        }
