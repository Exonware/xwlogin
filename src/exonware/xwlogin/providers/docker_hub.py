#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/docker_hub.py
Docker Hub OAuth Provider
Docker Hub OAuth 2.0 provider implementation.
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


class DockerHubProvider(ABaseProvider):
    """Docker Hub OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://hub.docker.com/v2/oauth2/authorize"
    TOKEN_URL = "https://hub.docker.com/v2/oauth2/token"
    USERINFO_URL = "https://hub.docker.com/v2/users/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Docker Hub provider.
        Args:
            client_id: Docker Hub Client ID
            client_secret: Docker Hub Client Secret
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
        return "docker_hub"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.DOCKER_HUB

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Docker Hub.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Docker Hub user info format
        return {
            'id': str(user_info.get('id')),
            'username': user_info.get('username'),
            'email': user_info.get('email'),
            'full_name': user_info.get('full_name'),
        }
