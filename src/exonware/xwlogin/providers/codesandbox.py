#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/codesandbox.py
CodeSandbox OAuth Provider
CodeSandbox OAuth 2.0 provider implementation.
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


class CodeSandboxProvider(ABaseProvider):
    """CodeSandbox OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://codesandbox.io/oauth/authorize"
    TOKEN_URL = "https://codesandbox.io/oauth/token"
    USERINFO_URL = "https://codesandbox.io/api/v1/users/current"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize CodeSandbox provider.
        Args:
            client_id: CodeSandbox Client ID
            client_secret: CodeSandbox Client Secret
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
        return "codesandbox"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.CODESANDBOX

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from CodeSandbox.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize CodeSandbox user info format
        user_data = user_info.get('user', user_info)
        return {
            'id': str(user_data.get('id')),
            'username': user_data.get('username'),
            'name': user_data.get('name'),
            'avatar_url': user_data.get('avatar_url'),
        }
