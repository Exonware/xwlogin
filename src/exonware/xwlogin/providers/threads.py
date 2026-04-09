#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/threads.py
Threads OAuth Provider
Threads (Meta) OAuth 2.0 provider implementation.
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


class ThreadsProvider(ABaseProvider):
    """Threads (Meta) OAuth 2.0 provider."""
    # Threads uses Instagram Basic Display API (same as Instagram)
    AUTHORIZATION_URL = "https://api.instagram.com/oauth/authorize"
    TOKEN_URL = "https://api.instagram.com/oauth/access_token"
    USERINFO_URL = "https://graph.threads.net/v1.0/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Threads provider.
        Args:
            client_id: Threads App ID
            client_secret: Threads App Secret
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
        return "threads"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.THREADS

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Threads.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Threads requires fields parameter
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        fields = "id,username"
        url = f"{self.USERINFO_URL}?fields={fields}"
        response = await self._async_http_client.get(
            url,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Threads user info format
        return {
            'id': str(user_info.get('id')),
            'username': user_info.get('username'),
        }
