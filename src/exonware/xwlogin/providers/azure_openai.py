#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/azure_openai.py
Azure OpenAI OAuth Provider
Azure OpenAI (Microsoft) OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class AzureOpenAIProvider(ABaseProvider):
    """Azure OpenAI OAuth 2.0 provider (uses Microsoft Entra ID)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str = "common",
        **kwargs
    ):
        """
        Initialize Azure OpenAI provider.
        Args:
            client_id: Azure AD application (client) ID
            client_secret: Azure AD client secret
            tenant_id: Tenant ID or 'common', 'organizations', 'consumers' (default: 'common')
            **kwargs: Additional configuration
        """
        # Azure OpenAI uses Microsoft Entra ID OAuth endpoints
        authorization_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        userinfo_url = "https://graph.microsoft.com/v1.0/me"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        self.tenant_id = tenant_id
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "azure_openai"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.AZURE_OPENAI

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Azure OpenAI-specific authorization parameters."""
        return {
            'response_mode': 'query',
            'scope': 'https://cognitiveservices.azure.com/.default',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Azure OpenAI (via Microsoft Graph).
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Azure OpenAI user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('mail') or user_info.get('userPrincipalName'),
            'name': user_info.get('displayName'),
        }
