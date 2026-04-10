#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/careem.py
Careem OAuth Provider
Careem OAuth 2.0 provider implementation.
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


class CareemProvider(ABaseProvider):
    """Careem OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://api.careem.com/oauth/authorize"
    TOKEN_URL = "https://api.careem.com/oauth/token"
    USERINFO_URL = "https://api.careem.com/v1/customers/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Careem provider.
        Args:
            client_id: Careem API client ID
            client_secret: Careem API client secret
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
        return "careem"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CAREEM

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Careem.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Careem user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'phone': user_info.get('phone'),
        }
