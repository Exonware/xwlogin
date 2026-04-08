#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/threema.py
Threema OAuth Provider
Threema OAuth 2.0 provider implementation.
Note: Threema uses ID-based authentication rather than traditional OAuth 2.0.
This provider is a placeholder for potential future API integration.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class ThreemaProvider(ABaseProvider):
    """Threema OAuth 2.0 provider (placeholder - Threema uses ID-based auth)."""
    # Placeholder endpoints - Threema does not provide OAuth 2.0
    AUTHORIZATION_URL = "https://gateway.threema.ch/oauth/authorize"
    TOKEN_URL = "https://gateway.threema.ch/oauth/token"
    USERINFO_URL = "https://gateway.threema.ch/api/v1/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Threema provider.
        Warning: Threema does not currently support OAuth 2.0 for user authentication.
        This provider is a placeholder for potential future API integration.
        Args:
            client_id: Threema Client ID (if available)
            client_secret: Threema Client Secret (if available)
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
            "Threema does not currently support OAuth 2.0. "
            "This provider is a placeholder for future integration."
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "threema"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.THREEMA

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Threema.
        Note: This method is a placeholder as Threema does not support OAuth 2.0.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        raise XWProviderConnectionError(
            "Threema does not support OAuth 2.0 authentication. "
            "Please use Threema ID-based authentication instead.",
            error_code="oauth_not_supported",
            context={'provider': 'threema'}
        )
