#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/replit.py
Replit OAuth Provider
Replit OAuth 2.0 / OpenID Connect provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class ReplitProvider(ABaseProvider):
    """Replit OAuth 2.0 / OpenID Connect provider."""
    AUTHORIZATION_URL = "https://replit.com/oauth/authorize"
    TOKEN_URL = "https://replit.com/oauth/token"
    USERINFO_URL = "https://replit.com/oauth/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Replit provider.
        Args:
            client_id: Replit Client ID
            client_secret: Replit Client Secret
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
        return "replit"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.REPLIT

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Replit.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Replit user info format (OpenID Connect)
        return {
            'id': user_info.get('sub'),
            'username': user_info.get('preferred_username'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'avatar_url': user_info.get('picture'),
        }
