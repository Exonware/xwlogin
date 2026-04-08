#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/periscope.py
Periscope OAuth Provider
Periscope OAuth 2.0 provider implementation.
Note: Periscope was shut down in 2021, but this provider is included
for historical compatibility and potential future use.
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


class PeriscopeProvider(ABaseProvider):
    """Periscope OAuth 2.0 provider."""
    # Note: Periscope was shut down in 2021
    # These endpoints may not be active
    AUTHORIZATION_URL = "https://api.periscope.tv/oauth/authorize"
    TOKEN_URL = "https://api.periscope.tv/oauth/token"
    USERINFO_URL = "https://api.periscope.tv/v2/user/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Periscope provider.
        Note: Periscope was shut down in 2021. This provider is included
        for historical compatibility.
        Args:
            client_id: Periscope Client ID
            client_secret: Periscope Client Secret
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
        logger.warning(
            "Periscope was shut down in 2021. "
            "This provider is included for historical compatibility only."
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "periscope"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.PERISCOPE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Periscope.
        Note: Periscope was shut down in 2021.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Periscope user info format
        return {
            'id': str(user_info.get('id')),
            'username': user_info.get('username'),
            'display_name': user_info.get('display_name'),
            'avatar_url': user_info.get('profile_image_url'),
        }
