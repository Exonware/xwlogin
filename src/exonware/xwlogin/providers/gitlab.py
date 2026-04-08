#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/gitlab.py
GitLab OAuth Provider
GitLab OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class GitLabProvider(ABaseProvider):
    """GitLab OAuth 2.0 provider."""
    # Default GitLab.com endpoints
    AUTHORIZATION_URL = "https://gitlab.com/oauth/authorize"
    TOKEN_URL = "https://gitlab.com/oauth/token"
    USERINFO_URL = "https://gitlab.com/api/v4/user"

    def __init__(self, client_id: str, client_secret: str, gitlab_url: Optional[str] = None, **kwargs):
        """
        Initialize GitLab provider.
        Args:
            client_id: GitLab OAuth client ID
            client_secret: GitLab OAuth client secret
            gitlab_url: Custom GitLab instance URL (default: gitlab.com)
            **kwargs: Additional configuration
        """
        if gitlab_url:
            # Remove trailing slash
            gitlab_url = gitlab_url.rstrip('/')
            authorization_url = f"{gitlab_url}/oauth/authorize"
            token_url = f"{gitlab_url}/oauth/token"
            userinfo_url = f"{gitlab_url}/api/v4/user"
        else:
            authorization_url = self.AUTHORIZATION_URL
            token_url = self.TOKEN_URL
            userinfo_url = self.USERINFO_URL
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "gitlab"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.GITLAB

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from GitLab.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize GitLab user info format
        return {
            'id': str(user_info.get('id')),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'username': user_info.get('username'),
            'avatar_url': user_info.get('avatar_url'),
        }
