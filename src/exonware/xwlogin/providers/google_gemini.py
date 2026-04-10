#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/google_gemini.py
Google Gemini OAuth Provider
Google Gemini OAuth 2.0 provider implementation.
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


class GoogleGeminiProvider(ABaseProvider):
    """Google Gemini OAuth 2.0 provider."""
    # Google Gemini uses Google OAuth endpoints
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Google Gemini provider.
        Args:
            client_id: Google OAuth Client ID (with Gemini API access)
            client_secret: Google OAuth Client Secret
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
        return "google_gemini"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.GOOGLE_GEMINI

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Google Gemini-specific authorization parameters."""
        return {
            'access_type': 'offline',
            'prompt': 'consent',
            'scope': 'https://www.googleapis.com/auth/generative-language',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Google Gemini.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Google Gemini user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
        }
