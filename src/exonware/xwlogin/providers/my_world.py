#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/my_world.py
My World OAuth Provider
My World (Мой Мир) OAuth 2.0 provider implementation.
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


class MyWorldProvider(ABaseProvider):
    """My World (Мой Мир) OAuth 2.0 provider."""
    # My World uses Mail.ru OAuth endpoints
    AUTHORIZATION_URL = "https://oauth.mail.ru/oauth/authorize"
    TOKEN_URL = "https://oauth.mail.ru/token"
    USERINFO_URL = "https://oauth.mail.ru/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize My World provider.
        Args:
            client_id: Mail.ru Client ID (My World uses Mail.ru OAuth)
            client_secret: Mail.ru Client Secret
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
        return "my_world"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MY_WORLD

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from My World.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize My World user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'name': f"{user_info.get('first_name', '')} {user_info.get('last_name', '')}".strip(),
        }
