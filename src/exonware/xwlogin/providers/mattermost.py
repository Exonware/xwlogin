#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/mattermost.py
Mattermost OAuth Provider
Mattermost OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class MattermostProvider(ABaseProvider):
    """Mattermost OAuth 2.0 provider."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        server_url: str = "https://mattermost.com",
        **kwargs
    ):
        """
        Initialize Mattermost provider.
        Args:
            client_id: Mattermost OAuth Client ID
            client_secret: Mattermost OAuth Client Secret
            server_url: Mattermost server URL (default: https://mattermost.com)
            **kwargs: Additional configuration
        """
        # Mattermost uses OAuth endpoints on the server
        authorization_url = f"{server_url}/oauth/authorize"
        token_url = f"{server_url}/oauth/token"
        userinfo_url = f"{server_url}/api/v4/users/me"
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
        return "mattermost"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MATTERMOST

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Mattermost.
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
        # Normalize Mattermost user info format
        return {
            'id': user_info.get('id'),
            'username': user_info.get('username'),
            'email': user_info.get('email'),
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'name': f"{user_info.get('first_name', '')} {user_info.get('last_name', '')}".strip(),
        }
