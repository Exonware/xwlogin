#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tidal.py
Tidal OAuth Provider
Tidal OAuth 2.1 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class TidalProvider(ABaseProvider):
    """Tidal OAuth 2.1 provider."""
    AUTHORIZATION_URL = "https://login.tidal.com/authorize"
    TOKEN_URL = "https://auth.tidal.com/v1/oauth2/token"
    USERINFO_URL = "https://api.tidal.com/v1/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Tidal provider.
        Args:
            client_id: Tidal Client ID
            client_secret: Tidal Client Secret
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
        return "tidal"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.TIDAL

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Tidal.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Tidal user info format
        return {
            'id': str(user_info.get('id')),
            'username': user_info.get('username'),
            'email': user_info.get('email'),
            'first_name': user_info.get('firstName'),
            'last_name': user_info.get('lastName'),
        }
