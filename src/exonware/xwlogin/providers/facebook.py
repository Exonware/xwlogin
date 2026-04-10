#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/facebook.py
Facebook OAuth Provider
Facebook OAuth 2.0 provider implementation.
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


class FacebookProvider(ABaseProvider):
    """Facebook OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.facebook.com/v22.0/dialog/oauth"
    TOKEN_URL = "https://graph.facebook.com/v22.0/oauth/access_token"
    USERINFO_URL = "https://graph.facebook.com/v22.0/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Facebook provider.
        Args:
            client_id: Facebook OAuth client ID
            client_secret: Facebook OAuth client secret
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
        return "facebook"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.FACEBOOK

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Facebook-specific authorization parameters."""
        return {
            'display': 'popup',  # or 'page', 'touch', 'wap'
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Facebook.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Facebook requires fields parameter
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        # Request specific fields
        fields = "id,name,email,picture"
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
        # Normalize Facebook user info format
        picture_data = user_info.get('picture', {})
        picture_url = None
        if isinstance(picture_data, dict):
            picture_url = picture_data.get('data', {}).get('url')
        return {
            'id': user_info.get('id'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': picture_url,
        }
