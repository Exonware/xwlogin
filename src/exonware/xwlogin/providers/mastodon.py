#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/mastodon.py
Mastodon OAuth Provider
Mastodon OAuth 2.0 provider implementation (instance-specific).
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


class MastodonProvider(ABaseProvider):
    """Mastodon OAuth 2.0 provider (instance-specific)."""

    def __init__(self, client_id: str, client_secret: str, instance_url: str, **kwargs):
        """
        Initialize Mastodon provider.
        Args:
            client_id: Mastodon Client ID
            client_secret: Mastodon Client Secret
            instance_url: Mastodon instance URL (e.g., 'https://mastodon.social')
            **kwargs: Additional configuration
        """
        instance_url = instance_url.rstrip('/')
        authorization_url = f"{instance_url}/oauth/authorize"
        token_url = f"{instance_url}/oauth/token"
        userinfo_url = f"{instance_url}/api/v1/accounts/verify_credentials"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        self.instance_url = instance_url
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "mastodon"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MASTODON

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Mastodon.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Mastodon user info format
        return {
            'id': str(user_info.get('id')),
            'username': user_info.get('username'),
            'display_name': user_info.get('display_name'),
            'avatar': user_info.get('avatar'),
            'acct': user_info.get('acct'),  # Full account name (username@domain)
        }
