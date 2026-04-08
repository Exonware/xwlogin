#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/etsy.py
Etsy OAuth Provider
Etsy OAuth 2.0 provider implementation (requires PKCE).
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


class EtsyProvider(ABaseProvider):
    """Etsy OAuth 2.0 provider (requires PKCE)."""
    AUTHORIZATION_URL = "https://www.etsy.com/oauth/connect"
    TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token"
    USERINFO_URL = "https://api.etsy.com/v3/application/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Etsy provider.
        Args:
            client_id: Etsy API Key (keystring)
            client_secret: Etsy Shared Secret
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
        return "etsy"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ETSY

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Etsy-specific authorization parameters."""
        return {
            'code_challenge_method': 'S256',  # Etsy requires PKCE
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Etsy.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Etsy user info format
        return {
            'id': str(user_info.get('user_id')),
            'username': user_info.get('login_name'),
            'email': user_info.get('primary_email'),
        }
