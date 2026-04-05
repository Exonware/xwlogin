#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/bluesky.py
Bluesky OAuth Provider
Bluesky OAuth 2.0 provider implementation.
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


class BlueskyProvider(ABaseProvider):
    """Bluesky OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://bsky.social/xrpc/com.atproto.server.createSession"
    TOKEN_URL = "https://bsky.social/xrpc/com.atproto.server.createSession"
    USERINFO_URL = "https://bsky.social/xrpc/com.atproto.identity.resolveHandle"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Bluesky provider.
        Note: Bluesky uses ATProto authentication, not standard OAuth 2.0.
        This is a simplified implementation.
        Args:
            client_id: Bluesky App Password (identifier)
            client_secret: Bluesky App Password (secret)
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
            "Bluesky uses ATProto authentication, not standard OAuth 2.0. "
            "This is a simplified implementation."
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "bluesky"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.BLUESKY

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Bluesky.
        Note: Bluesky uses ATProto, which has a different authentication model.
        This is a placeholder implementation.
        Args:
            access_token: Access token (or session token for Bluesky)
        Returns:
            User information dictionary
        """
        logger.warning("Bluesky user info requires ATProto implementation")
        return {
            'id': None,
            'handle': None,
        }
