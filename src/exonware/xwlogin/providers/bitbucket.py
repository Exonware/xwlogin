#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/bitbucket.py
Bitbucket OAuth Provider
Bitbucket OAuth 2.0 provider implementation.
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


class BitbucketProvider(ABaseProvider):
    """Bitbucket OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://bitbucket.org/site/oauth2/authorize"
    TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"
    USERINFO_URL = "https://api.bitbucket.org/2.0/user"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Bitbucket provider.
        Args:
            client_id: Bitbucket OAuth client ID
            client_secret: Bitbucket OAuth client secret
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
        return "bitbucket"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.BITBUCKET

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Bitbucket.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Bitbucket user info format
        return {
            'id': user_info.get('uuid'),
            'email': user_info.get('email'),
            'name': user_info.get('display_name'),
            'username': user_info.get('username'),
            'avatar_url': user_info.get('links', {}).get('avatar', {}).get('href'),
        }
