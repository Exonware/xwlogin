#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/rakuten.py
Rakuten OAuth Provider
Rakuten OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class RakutenProvider(ABaseProvider):
    """Rakuten OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://app.rakuten.co.jp/services/authorize"
    TOKEN_URL = "https://app.rakuten.co.jp/services/token"
    USERINFO_URL = "https://app.rakuten.co.jp/services/api/UserProfile/GetUserProfile/20170426"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Rakuten provider.
        Args:
            client_id: Rakuten Application ID
            client_secret: Rakuten Application Secret
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
        return "rakuten"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.RAKUTEN

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Rakuten.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Rakuten requires applicationId and access_token as query parameters
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?applicationId={self._client_id}&access_token={access_token}"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        data = response.json()
        user_info = data.get('Body', {})
        # Normalize Rakuten user info format
        return {
            'id': str(user_info.get('userId')),
            'nickname': user_info.get('nickname'),
            'email': user_info.get('email'),
        }
