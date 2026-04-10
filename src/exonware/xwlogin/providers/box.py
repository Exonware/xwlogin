#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/box.py
Box OAuth Provider
Box OAuth 2.0 provider implementation.
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


class BoxProvider(ABaseProvider):
    """Box OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://account.box.com/api/oauth2/authorize"
    TOKEN_URL = "https://api.box.com/oauth2/token"
    USERINFO_URL = "https://api.box.com/2.0/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Box provider.
        Args:
            client_id: Box OAuth client ID
            client_secret: Box OAuth client secret
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
        return "box"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.BOX

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Box.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Box user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('login'),
            'name': user_info.get('name'),
            'avatar_url': user_info.get('avatar_url'),
        }
