#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/snapchat.py
Snapchat OAuth Provider
Snapchat OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class SnapchatProvider(ABaseProvider):
    """Snapchat OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://accounts.snapchat.com/login/oauth2/authorize"
    TOKEN_URL = "https://accounts.snapchat.com/login/oauth2/access_token"
    USERINFO_URL = "https://kit.snapchat.com/v1/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Snapchat provider.
        Args:
            client_id: Snapchat Client ID
            client_secret: Snapchat Client Secret
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
        return "snapchat"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.SNAPCHAT

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Snapchat.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Snapchat user info format
        return {
            'id': user_info.get('external_id'),
            'display_name': user_info.get('display_name'),
            'avatar_url': user_info.get('bitmoji', {}).get('avatar') if user_info.get('bitmoji') else None,
        }
