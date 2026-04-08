#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/evernote.py
Evernote OAuth Provider
Evernote OAuth 1.0a provider implementation (Evernote uses OAuth 1.0a, not 2.0).
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


class EvernoteProvider(ABaseProvider):
    """
    Evernote OAuth provider.
    Note: Evernote uses OAuth 1.0a, not OAuth 2.0.
    This is a simplified implementation that may need OAuth 1.0a support.
    """
    # Evernote uses OAuth 1.0a endpoints
    # Production
    REQUEST_TOKEN_URL = "https://www.evernote.com/oauth"
    AUTHORIZATION_URL = "https://www.evernote.com/OAuth.action"
    ACCESS_TOKEN_URL = "https://www.evernote.com/oauth"
    USERINFO_URL = "https://www.evernote.com/edam/user"
    # Sandbox
    SANDBOX_REQUEST_TOKEN_URL = "https://sandbox.evernote.com/oauth"
    SANDBOX_AUTHORIZATION_URL = "https://sandbox.evernote.com/OAuth.action"
    SANDBOX_ACCESS_TOKEN_URL = "https://sandbox.evernote.com/oauth"
    SANDBOX_USERINFO_URL = "https://sandbox.evernote.com/edam/user"

    def __init__(self, client_id: str, client_secret: str, sandbox: bool = False, **kwargs):
        """
        Initialize Evernote provider.
        Args:
            client_id: Evernote OAuth consumer key
            client_secret: Evernote OAuth consumer secret
            sandbox: Use sandbox environment (default: False)
            **kwargs: Additional configuration
        """
        # Note: Evernote uses OAuth 1.0a, so these URLs are placeholders
        # Full OAuth 1.0a implementation would be needed
        if sandbox:
            authorization_url = self.SANDBOX_AUTHORIZATION_URL
            token_url = self.SANDBOX_ACCESS_TOKEN_URL
            userinfo_url = self.SANDBOX_USERINFO_URL
        else:
            authorization_url = self.AUTHORIZATION_URL
            token_url = self.ACCESS_TOKEN_URL
            userinfo_url = self.USERINFO_URL
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        logger.warning(
            "Evernote uses OAuth 1.0a, not OAuth 2.0. "
            "This implementation may need OAuth 1.0a support for full functionality."
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "evernote"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.EVERNOTE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Evernote.
        Note: This is a placeholder. Evernote requires OAuth 1.0a implementation.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Evernote API requires OAuth 1.0a signing
        # This is a simplified implementation
        logger.warning("Evernote user info requires OAuth 1.0a implementation")
        return {
            'id': None,
            'name': None,
        }
