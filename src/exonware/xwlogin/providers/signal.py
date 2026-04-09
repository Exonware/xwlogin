#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/signal.py
Signal OAuth Provider
Signal OAuth 2.0 provider implementation.
Note: Signal primarily uses phone number authentication and does not
provide traditional OAuth 2.0 for user authentication. This provider
is a placeholder for potential future Signal API integration.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class SignalProvider(ABaseProvider):
    """Signal OAuth 2.0 provider (placeholder - Signal uses phone number auth)."""
    # Placeholder endpoints - Signal does not provide OAuth 2.0
    AUTHORIZATION_URL = "https://signal.org/oauth/authorize"
    TOKEN_URL = "https://signal.org/oauth/token"
    USERINFO_URL = "https://signal.org/api/v1/user/info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Signal provider.
        Warning: Signal does not currently support OAuth 2.0 for user authentication.
        This provider is a placeholder for potential future API integration.
        Args:
            client_id: Signal Client ID (if available)
            client_secret: Signal Client Secret (if available)
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
            "Signal does not currently support OAuth 2.0. "
            "This provider is a placeholder for future integration."
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "signal"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.SIGNAL

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Signal.
        Note: This method is a placeholder as Signal does not support OAuth 2.0.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        raise XWProviderConnectionError(
            "Signal does not support OAuth 2.0 authentication. "
            "Please use phone number-based authentication instead.",
            error_code="oauth_not_supported",
            context={'provider': 'signal'}
        )
