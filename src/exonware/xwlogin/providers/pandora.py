#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/pandora.py
Pandora OAuth Provider
Pandora OAuth 2.0 provider implementation.
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


class PandoraProvider(ABaseProvider):
    """Pandora OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.pandora.com/oauth/v1/authorize"
    TOKEN_URL = "https://www.pandora.com/oauth/v1/token"
    USERINFO_URL = "https://www.pandora.com/api/v1/user"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Pandora provider.
        Args:
            client_id: Pandora Client ID
            client_secret: Pandora Client Secret
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
        return "pandora"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.PANDORA

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Pandora.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Pandora user info format
        return {
            'id': str(user_info.get('userId')),
            'email': user_info.get('email'),
            'username': user_info.get('username'),
            'name': user_info.get('firstName'),
        }
