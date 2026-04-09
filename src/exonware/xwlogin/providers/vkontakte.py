#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/vkontakte.py
vKontakte OAuth Provider
vKontakte (VK) OAuth 2.0 provider implementation.
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


class VKontakteProvider(ABaseProvider):
    """vKontakte (VK) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://oauth.vk.com/authorize"
    TOKEN_URL = "https://oauth.vk.com/access_token"
    USERINFO_URL = "https://api.vk.com/method/users.get"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize vKontakte provider.
        Args:
            client_id: VK OAuth application ID
            client_secret: VK OAuth secret key
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
        return "vkontakte"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.VKONTAKTE

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get vKontakte-specific authorization parameters."""
        return {
            'display': 'page',  # or 'popup', 'mobile'
            'v': '5.131',  # API version
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from vKontakte.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # VK API requires access_token as query parameter
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?access_token={access_token}&v=5.131&fields=photo_200,email"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        data = response.json()
        response_data = data.get('response', [])
        user_info = response_data[0] if response_data else {}
        # Normalize vKontakte user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': f"{user_info.get('first_name', '')} {user_info.get('last_name', '')}".strip(),
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'photo': user_info.get('photo_200'),
        }
