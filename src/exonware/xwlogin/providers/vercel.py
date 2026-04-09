#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/vercel.py
Vercel OAuth Provider
Vercel OAuth 2.0 provider implementation.
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


class VercelProvider(ABaseProvider):
    """Vercel OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://vercel.com/oauth/authorize"
    TOKEN_URL = "https://api.vercel.com/login/oauth/token"
    USERINFO_URL = "https://api.vercel.com/login/oauth/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Vercel provider.
        Args:
            client_id: Vercel Client ID
            client_secret: Vercel Client Secret
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
        return "vercel"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.VERCEL

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Vercel.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Vercel user info format (OpenID Connect)
        return {
            'id': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'username': user_info.get('preferred_username'),
            'avatar_url': user_info.get('picture'),
        }
