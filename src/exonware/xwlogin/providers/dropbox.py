#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/dropbox.py
Dropbox OAuth Provider
Dropbox OAuth 2.0 provider implementation.
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


class DropboxProvider(ABaseProvider):
    """Dropbox OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://www.dropbox.com/oauth2/authorize"
    TOKEN_URL = "https://api.dropbox.com/oauth2/token"
    USERINFO_URL = "https://api.dropbox.com/2/users/get_current_account"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Dropbox provider.
        Args:
            client_id: Dropbox OAuth client ID
            client_secret: Dropbox OAuth client secret
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
        return "dropbox"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.DROPBOX

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Dropbox.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Dropbox user info format
        return {
            'id': user_info.get('account_id'),
            'email': user_info.get('email'),
            'name': user_info.get('name', {}).get('display_name'),
            'country': user_info.get('country'),
            'locale': user_info.get('locale'),
        }
