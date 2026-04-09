#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/akhtaboot.py
Akhtaboot OAuth Provider
Akhtaboot OAuth 2.0 provider implementation (Middle East job platform).
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


class AkhtabootProvider(ABaseProvider):
    """Akhtaboot OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.akhtaboot.com/oauth/authorize"
    TOKEN_URL = "https://www.akhtaboot.com/oauth/token"
    USERINFO_URL = "https://www.akhtaboot.com/api/v1/user/profile"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Akhtaboot provider.
        Args:
            client_id: Akhtaboot Client ID
            client_secret: Akhtaboot Client Secret
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
        return "akhtaboot"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.AKHTABOOT

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Akhtaboot.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Akhtaboot user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'phone': user_info.get('phone'),
        }
