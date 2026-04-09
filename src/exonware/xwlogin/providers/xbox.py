#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/xbox.py
Xbox OAuth Provider
Xbox Live OAuth 2.0 provider implementation.
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


class XboxProvider(ABaseProvider):
    """Xbox Live OAuth 2.0 provider."""
    # Xbox uses Microsoft OAuth endpoints but with Xbox-specific scopes
    AUTHORIZATION_URL = "https://login.live.com/oauth20_authorize.srf"
    TOKEN_URL = "https://login.live.com/oauth20_token.srf"
    USERINFO_URL = "https://userinfo.xboxlive.com/users/me/profile"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Xbox provider.
        Args:
            client_id: Xbox Live Client ID
            client_secret: Xbox Live Client Secret
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
        return "xbox"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.XBOX

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Xbox-specific authorization parameters."""
        return {
            'scope': 'XboxLive.signin XboxLive.offline_access',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Xbox Live.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Xbox requires XSTS token exchange first, then user info
        # This is a simplified implementation
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={
                'Authorization': f'Bearer {access_token}',
                'x-xbl-contract-version': '1'
            }
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Xbox user info format
        return {
            'id': user_info.get('xuid'),
            'gamertag': user_info.get('gamertag'),
            'name': user_info.get('displayName'),
        }
