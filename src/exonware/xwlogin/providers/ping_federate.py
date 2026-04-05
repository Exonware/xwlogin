#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/ping_federate.py
PingFederate OAuth Provider
PingFederate OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class PingFederateProvider(ABaseProvider):
    """PingFederate OAuth 2.0 provider."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        pingfederate_url: str,
        **kwargs
    ):
        """
        Initialize PingFederate provider.
        Args:
            client_id: PingFederate OAuth client ID
            client_secret: PingFederate OAuth client secret
            pingfederate_url: PingFederate server URL (e.g., 'https://pingfederate.example.com')
            **kwargs: Additional configuration
        """
        pingfederate_url = pingfederate_url.rstrip('/')
        authorization_url = f"{pingfederate_url}/as/authorization.oauth2"
        token_url = f"{pingfederate_url}/as/token.oauth2"
        userinfo_url = f"{pingfederate_url}/as/userinfo.oauth2"
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
        return "ping_federate"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.PING_FEDERATE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from PingFederate.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize PingFederate user info format (OpenID Connect)
        return {
            'id': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
            'preferred_username': user_info.get('preferred_username'),
        }
