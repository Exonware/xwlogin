#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/renren.py
RenRen OAuth Provider
RenRen OAuth 2.0 provider implementation.
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


class RenRenProvider(ABaseProvider):
    """RenRen OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://graph.renren.com/oauth/authorize"
    TOKEN_URL = "https://graph.renren.com/oauth/token"
    USERINFO_URL = "https://api.renren.com/v2/user/get"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize RenRen provider.
        Args:
            client_id: RenRen OAuth API key
            client_secret: RenRen OAuth secret key
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
        return "renren"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.RENREN

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from RenRen.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # RenRen requires access_token as query parameter
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?access_token={access_token}"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize RenRen user info format
        return {
            'id': str(user_info.get('id')),
            'name': user_info.get('name'),
            'avatar_url': user_info.get('avatar', [{}])[0].get('url') if user_info.get('avatar') else None,
        }
