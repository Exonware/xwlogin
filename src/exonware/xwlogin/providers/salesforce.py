#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/salesforce.py
Salesforce OAuth Provider
Salesforce OAuth 2.0 provider implementation (production, sandbox, and community).
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


class SalesforceProvider(ABaseProvider):
    """Salesforce OAuth 2.0 provider."""
    # Production endpoints
    AUTHORIZATION_URL = "https://login.salesforce.com/services/oauth2/authorize"
    TOKEN_URL = "https://login.salesforce.com/services/oauth2/token"
    USERINFO_URL = "https://login.salesforce.com/services/oauth2/userinfo"
    # Sandbox endpoints
    SANDBOX_AUTHORIZATION_URL = "https://test.salesforce.com/services/oauth2/authorize"
    SANDBOX_TOKEN_URL = "https://test.salesforce.com/services/oauth2/token"
    SANDBOX_USERINFO_URL = "https://test.salesforce.com/services/oauth2/userinfo"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        instance_url: Optional[str] = None,
        sandbox: bool = False,
        **kwargs
    ):
        """
        Initialize Salesforce provider.
        Args:
            client_id: Salesforce OAuth client ID
            client_secret: Salesforce OAuth client secret
            instance_url: Custom Salesforce instance URL (for community/My Domain)
            sandbox: Use sandbox environment (default: False)
            **kwargs: Additional configuration
        """
        if instance_url:
            # Custom instance URL (community or My Domain)
            instance_url = instance_url.rstrip('/')
            authorization_url = f"{instance_url}/services/oauth2/authorize"
            token_url = f"{instance_url}/services/oauth2/token"
            userinfo_url = f"{instance_url}/services/oauth2/userinfo"
        elif sandbox:
            authorization_url = self.SANDBOX_AUTHORIZATION_URL
            token_url = self.SANDBOX_TOKEN_URL
            userinfo_url = self.SANDBOX_USERINFO_URL
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
        return "salesforce"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.SALESFORCE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Salesforce.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Salesforce user info format (OpenID Connect)
        return {
            'id': user_info.get('user_id'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
            'picture': user_info.get('picture'),
            'organization_id': user_info.get('organization_id'),
        }
