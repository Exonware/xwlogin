#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tiktok.py
TikTok OAuth Provider
TikTok OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class TikTokProvider(ABaseProvider):
    """TikTok OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.tiktok.com/v2/auth/authorize"
    TOKEN_URL = "https://open-api.tiktok.com/platform/oauth/access_token"
    USERINFO_URL = "https://open-api.tiktok.com/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize TikTok provider.
        Args:
            client_id: TikTok Client Key
            client_secret: TikTok Client Secret
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
        return "tiktok"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.TIKTOK

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from TikTok.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # TikTok requires specific request format
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        # TikTok API requires specific fields parameter
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'},
            params={'fields': 'open_id,union_id,avatar_url,display_name'}
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        data = response.json()
        user_info = data.get('data', {}).get('user', {})
        # Normalize TikTok user info format
        return {
            'id': user_info.get('open_id'),
            'union_id': user_info.get('union_id'),
            'display_name': user_info.get('display_name'),
            'avatar_url': user_info.get('avatar_url'),
        }
