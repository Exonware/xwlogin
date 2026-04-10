#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/ubisoft.py
Ubisoft OAuth Provider
Ubisoft Connect (formerly Uplay) OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class UbisoftProvider(ABaseProvider):
    """Ubisoft Connect OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://public-ubiservices.ubi.com/v3/profiles/sessions"
    TOKEN_URL = "https://public-ubiservices.ubi.com/v3/profiles/sessions"
    USERINFO_URL = "https://public-ubiservices.ubi.com/v1/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Ubisoft provider.
        Args:
            client_id: Ubisoft App ID
            client_secret: Ubisoft App Secret
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
        return "ubisoft"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.UBISOFT

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Ubisoft Connect.
        Args:
            access_token: Access token (session ticket)
        Returns:
            User information dictionary
        """
        # Ubisoft uses session tickets instead of standard OAuth tokens
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={
                'Authorization': f'Ubi_v1 t={access_token}',
                'Ubi-AppId': self._client_id
            }
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Ubisoft user info format
        return {
            'id': user_info.get('userId'),
            'username': user_info.get('username'),
            'email': user_info.get('email'),
            'name': user_info.get('nameOnPlatform'),
        }
