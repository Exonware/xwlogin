#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/line.py
Line OAuth Provider
Line OAuth 2.0 provider implementation.
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


class LineProvider(ABaseProvider):
    """Line OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://access.line.me/oauth2/v2.1/authorize"
    TOKEN_URL = "https://api.line.me/oauth2/v2.1/token"
    USERINFO_URL = "https://api.line.me/v2/profile"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Line provider.
        Args:
            client_id: Line Channel ID
            client_secret: Line Channel Secret
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
        return "line"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.LINE

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Line-specific authorization parameters."""
        return {
            'response_type': 'code',
            'scope': 'profile openid email',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Line.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Line user info format
        return {
            'id': user_info.get('userId'),
            'name': user_info.get('displayName'),
            'picture': user_info.get('pictureUrl'),
            'email': user_info.get('email'),
        }
