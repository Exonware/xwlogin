#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/wire.py
Wire OAuth Provider
Wire OAuth 2.0 provider implementation.
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


class WireProvider(ABaseProvider):
    """Wire OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://prod-nginz-https.wire.com/oauth/authorize"
    TOKEN_URL = "https://prod-nginz-https.wire.com/oauth/token"
    USERINFO_URL = "https://prod-nginz-https.wire.com/api/v1/self"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Wire provider.
        Args:
            client_id: Wire Client ID
            client_secret: Wire Client Secret
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
        return "wire"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.WIRE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Wire.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Wire user info format
        return {
            'id': user_info.get('id'),
            'name': user_info.get('name'),
            'email': user_info.get('email'),
            'handle': user_info.get('handle'),
        }
