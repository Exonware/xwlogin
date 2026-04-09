#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/google.py
Google OAuth Provider
Google OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 20-Dec-2025
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class GoogleProvider(ABaseProvider):
    """Google OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Google provider.
        Args:
            client_id: Google OAuth client ID
            client_secret: Google OAuth client secret
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
        return self.provider_type.value
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.GOOGLE

    @property
    def oidc_issuer(self) -> str | None:
        return "https://accounts.google.com"

    @property
    def oidc_jwks_uri(self) -> str | None:
        return "https://www.googleapis.com/oauth2/v3/certs"

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Google-specific authorization parameters."""
        return {
            'access_type': 'offline',  # Request refresh token
            'prompt': 'consent',  # Force consent screen
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Google.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Google user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'verified_email': user_info.get('verified_email', False),
        }
