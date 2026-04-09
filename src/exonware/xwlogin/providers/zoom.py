#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/zoom.py
Zoom OAuth Provider
Zoom OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class ZoomProvider(ABaseProvider):
    """Zoom OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://zoom.us/oauth/authorize"
    TOKEN_URL = "https://zoom.us/oauth/token"
    USERINFO_URL = "https://api.zoom.us/v2/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Zoom provider.
        Args:
            client_id: Zoom OAuth App Client ID
            client_secret: Zoom OAuth App Client Secret
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
        return "zoom"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ZOOM

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Zoom-specific authorization parameters."""
        return {
            'response_type': 'code',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Zoom.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Zoom user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('email'),
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'name': f"{user_info.get('first_name', '')} {user_info.get('last_name', '')}".strip(),
            'display_name': user_info.get('display_name'),
            'avatar_url': user_info.get('pic_url'),
        }
