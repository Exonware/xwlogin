#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/weibo.py
Weibo OAuth Provider
Weibo (Sina Weibo) OAuth 2.0 provider implementation.
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


class WeiboProvider(ABaseProvider):
    """Weibo (Sina Weibo) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://api.weibo.com/oauth2/authorize"
    TOKEN_URL = "https://api.weibo.com/oauth2/access_token"
    USERINFO_URL = "https://api.weibo.com/2/users/show.json"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Weibo provider.
        Args:
            client_id: Weibo OAuth app key
            client_secret: Weibo OAuth app secret
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
        return "weibo"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.WEIBO

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Weibo.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Weibo requires access_token and uid as query parameters
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        # First get uid from token info (Weibo returns uid in token response)
        # For now, we'll use a simplified approach
        url = f"{self.USERINFO_URL}?access_token={access_token}"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Weibo user info format
        return {
            'id': str(user_info.get('id')),
            'name': user_info.get('screen_name'),
            'display_name': user_info.get('name'),
            'avatar_url': user_info.get('avatar_large'),
            'location': user_info.get('location'),
        }
