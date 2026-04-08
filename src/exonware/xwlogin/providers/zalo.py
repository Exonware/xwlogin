#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/zalo.py
Zalo OAuth Provider
Zalo OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class ZaloProvider(ABaseProvider):
    """Zalo OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://oauth.zalo.me/v4/oa/permission"
    TOKEN_URL = "https://oauth.zalo.me/v4/oa/access_token"
    USERINFO_URL = "https://graph.zalo.me/v2.0/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Zalo provider.
        Args:
            client_id: Zalo App ID
            client_secret: Zalo App Secret
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
        return "zalo"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ZALO

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Zalo.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Zalo requires access_token as query parameter
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?access_token={access_token}&fields=id,name,picture"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        data = user_info.get('data', user_info)
        # Normalize Zalo user info format
        return {
            'id': str(data.get('id')),
            'name': data.get('name'),
            'picture': data.get('picture', {}).get('data', {}).get('url'),
        }
