#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/rocket_chat.py
Rocket.Chat OAuth Provider
Rocket.Chat OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class RocketChatProvider(ABaseProvider):
    """Rocket.Chat OAuth 2.0 provider."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        server_url: str = "https://open.rocket.chat",
        **kwargs
    ):
        """
        Initialize Rocket.Chat provider.
        Args:
            client_id: Rocket.Chat OAuth Client ID
            client_secret: Rocket.Chat OAuth Client Secret
            server_url: Rocket.Chat server URL (default: https://open.rocket.chat)
            **kwargs: Additional configuration
        """
        # Rocket.Chat uses OAuth endpoints on the server
        authorization_url = f"{server_url}/oauth/authorize"
        token_url = f"{server_url}/oauth/token"
        userinfo_url = f"{server_url}/api/v1/me"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        self.server_url = server_url
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "rocket_chat"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ROCKET_CHAT

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Rocket.Chat.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        data = user_info.get('user', user_info)
        # Normalize Rocket.Chat user info format
        return {
            'id': data.get('_id'),
            'username': data.get('username'),
            'name': data.get('name'),
            'email': data.get('emails', [{}])[0].get('address') if data.get('emails') else None,
        }
