#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/stack_overflow.py
Stack Overflow OAuth Provider
Stack Overflow OAuth 2.0 provider implementation.
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


class StackOverflowProvider(ABaseProvider):
    """Stack Overflow OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://stackoverflow.com/oauth"
    TOKEN_URL = "https://stackoverflow.com/oauth/access_token/json"
    USERINFO_URL = "https://api.stackexchange.com/2.3/me"

    def __init__(self, client_id: str, client_secret: str, key: str, **kwargs):
        """
        Initialize Stack Overflow provider.
        Args:
            client_id: Stack Overflow OAuth client ID
            client_secret: Stack Overflow OAuth client secret
            key: Stack Overflow API key (required)
            **kwargs: Additional configuration
        """
        self.key = key
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
        return "stack_overflow"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.STACK_OVERFLOW

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Stack Overflow.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Stack Overflow API requires key parameter
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?key={self.key}&access_token={access_token}&site=stackoverflow"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        data = response.json()
        items = data.get('items', [])
        user_info = items[0] if items else {}
        # Normalize Stack Overflow user info format
        return {
            'id': str(user_info.get('user_id')),
            'name': user_info.get('display_name'),
            'profile_image': user_info.get('profile_image'),
            'reputation': user_info.get('reputation'),
        }
