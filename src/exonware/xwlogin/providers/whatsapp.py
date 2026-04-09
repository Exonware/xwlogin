#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/whatsapp.py
WhatsApp OAuth Provider
WhatsApp OAuth 2.0 provider implementation.
Note: WhatsApp primarily uses phone number authentication. This provider
implements OAuth 2.0 for WhatsApp Business API access.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class WhatsAppProvider(ABaseProvider):
    """WhatsApp OAuth 2.0 provider (for WhatsApp Business API)."""
    # WhatsApp Business API uses Facebook OAuth
    AUTHORIZATION_URL = "https://www.facebook.com/v18.0/dialog/oauth"
    TOKEN_URL = "https://graph.facebook.com/v18.0/oauth/access_token"
    USERINFO_URL = "https://graph.facebook.com/v18.0/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize WhatsApp provider.
        Args:
            client_id: Facebook App ID (WhatsApp Business API uses Facebook OAuth)
            client_secret: Facebook App Secret
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
        return "whatsapp"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.WHATSAPP

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get WhatsApp-specific authorization parameters."""
        return {
            'scope': 'whatsapp_business_management,whatsapp_business_messaging',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from WhatsApp Business API.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize WhatsApp user info format
        return {
            'id': user_info.get('id'),
            'name': user_info.get('name'),
        }
