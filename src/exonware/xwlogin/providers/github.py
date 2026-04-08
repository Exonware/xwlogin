#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/github.py
GitHub OAuth Provider
GitHub OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 20-Dec-2025
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class GitHubProvider(ABaseProvider):
    """GitHub OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USERINFO_URL = "https://api.github.com/user"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize GitHub provider.
        Args:
            client_id: GitHub OAuth client ID
            client_secret: GitHub OAuth client secret
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
        return "github"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.GITHUB

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token.
        GitHub requires Accept header for JSON response.
        Args:
            code: Authorization code
            redirect_uri: Redirect URI
        Returns:
            Token response dictionary
        """
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self._client_id,
            'client_secret': self._client_secret,
        }
        # Use parent class implementation which handles HTTP client initialization
        return await super().exchange_code_for_token(code, redirect_uri)

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from GitHub.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize GitHub user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name') or user_info.get('login'),
            'avatar_url': user_info.get('avatar_url'),
            'login': user_info.get('login'),
        }
