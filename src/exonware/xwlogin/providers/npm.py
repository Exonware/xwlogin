#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/npm.py
npm OAuth Provider
npm (Node Package Manager) OAuth 2.0 provider implementation.
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


class NPMProvider(ABaseProvider):
    """npm OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.npmjs.com/oauth/authorize"
    TOKEN_URL = "https://www.npmjs.com/oauth/token"
    USERINFO_URL = "https://registry.npmjs.org/-/npm/v1/user"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize npm provider.
        Args:
            client_id: npm Client ID
            client_secret: npm Client Secret
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
        return "npm"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.NPM

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from npm.
        Args:
            access_token: Access token (npm uses tokens, not standard OAuth)
        Returns:
            User information dictionary
        """
        # npm uses tokens in Authorization header
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize npm user info format
        return {
            'id': user_info.get('name'),  # npm uses username as ID
            'username': user_info.get('name'),
            'email': user_info.get('email'),
        }
