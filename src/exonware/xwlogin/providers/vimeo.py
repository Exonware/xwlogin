#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/vimeo.py
Vimeo OAuth Provider
Vimeo OAuth 2.0 provider implementation.
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


class VimeoProvider(ABaseProvider):
    """Vimeo OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://api.vimeo.com/oauth/authorize"
    TOKEN_URL = "https://api.vimeo.com/oauth/access_token"
    USERINFO_URL = "https://api.vimeo.com/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Vimeo provider.
        Args:
            client_id: Vimeo OAuth client ID
            client_secret: Vimeo OAuth client secret
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
        return "vimeo"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CUSTOM  # Vimeo not in enum yet

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Vimeo.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Vimeo user info format
        return {
            'id': str(user_info.get('uri', '').split('/')[-1]),
            'name': user_info.get('name'),
            'link': user_info.get('link'),
            'pictures': user_info.get('pictures', {}),
        }
