#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/apple_music.py
Apple Music OAuth Provider
Apple Music OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class AppleMusicProvider(ABaseProvider):
    """Apple Music OAuth 2.0 provider."""
    # Apple Music uses Apple's OAuth endpoints with MusicKit scopes
    AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize"
    TOKEN_URL = "https://appleid.apple.com/auth/token"
    USERINFO_URL = "https://api.music.apple.com/v1/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Apple Music provider.
        Args:
            client_id: Apple Services ID (for MusicKit)
            client_secret: Apple Private Key (JWT signed secret)
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
        return "apple_music"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.APPLE_MUSIC

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Apple Music-specific authorization parameters."""
        return {
            'response_mode': 'form_post',
            'scope': 'music',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Apple Music.
        Args:
            access_token: Access token (Music User Token)
        Returns:
            User information dictionary
        """
        # Apple Music requires Music User Token
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={
                'Authorization': f'Bearer {access_token}',
                'Music-User-Token': access_token
            }
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Apple Music user info format
        return {
            'id': user_info.get('id'),
            'name': user_info.get('attributes', {}).get('name'),
        }
