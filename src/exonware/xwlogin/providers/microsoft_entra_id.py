#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/microsoft_entra_id.py
Microsoft Entra ID OAuth Provider
Microsoft Entra ID (formerly Azure AD) OAuth 2.0 provider implementation.
This is specifically for Entra ID, separate from consumer Microsoft accounts.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class MicrosoftEntraIDProvider(ABaseProvider):
    """Microsoft Entra ID (Azure AD) OAuth 2.0 provider."""
    # Microsoft Entra ID endpoints
    AUTHORIZATION_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    USERINFO_URL = "https://graph.microsoft.com/v1.0/me"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str = "common",
        **kwargs
    ):
        """
        Initialize Microsoft Entra ID provider.
        Args:
            client_id: Azure AD application (client) ID
            client_secret: Azure AD client secret
            tenant_id: Tenant ID or 'common', 'organizations', 'consumers' (default: 'common')
            **kwargs: Additional configuration
        """
        authorization_url = self.AUTHORIZATION_URL.format(tenant=tenant_id)
        token_url = self.TOKEN_URL.format(tenant=tenant_id)
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=self.USERINFO_URL,
            **kwargs
        )
        self.tenant_id = tenant_id
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "microsoft_entra_id"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MICROSOFT_ENTRA_ID

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Microsoft Entra ID-specific authorization parameters."""
        return {
            'response_mode': 'query',
            'prompt': 'select_account',  # or 'consent', 'login', 'none'
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Microsoft Graph API.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Microsoft Entra ID user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('mail') or user_info.get('userPrincipalName'),
            'name': user_info.get('displayName'),
            'given_name': user_info.get('givenName'),
            'family_name': user_info.get('surname'),
            'job_title': user_info.get('jobTitle'),
            'department': user_info.get('department'),
        }
