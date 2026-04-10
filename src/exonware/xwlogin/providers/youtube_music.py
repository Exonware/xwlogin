#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/youtube_music.py
YouTube Music OAuth Provider
YouTube Music OAuth 2.0 provider implementation.
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


class YouTubeMusicProvider(ABaseProvider):
    """YouTube Music OAuth 2.0 provider."""
    # YouTube Music uses Google OAuth endpoints with YouTube Music scopes
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/youtube/v3/channels"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize YouTube Music provider.
        Args:
            client_id: Google OAuth Client ID (with YouTube Music API access)
            client_secret: Google OAuth Client Secret
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
        return "youtube_music"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.YOUTUBE_MUSIC

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get YouTube Music-specific authorization parameters."""
        return {
            'access_type': 'offline',
            'prompt': 'consent',
            'scope': 'https://www.googleapis.com/auth/youtube.readonly',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from YouTube Music.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # YouTube Music requires specific API call to get channel info
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        url = f"{self.USERINFO_URL}?part=snippet&mine=true"
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
        data = response.json()
        items = data.get('items', [])
        channel = items[0] if items else {}
        snippet = channel.get('snippet', {})
        # Normalize YouTube Music user info format
        return {
            'id': channel.get('id'),
            'title': snippet.get('title'),
            'description': snippet.get('description'),
            'thumbnail': snippet.get('thumbnails', {}).get('default', {}).get('url'),
        }
