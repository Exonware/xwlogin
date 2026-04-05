#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/microsoft.py
Microsoft OAuth Provider
Microsoft/Azure AD OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 20-Dec-2025
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class MicrosoftProvider(ABaseProvider):
    """Microsoft/Azure AD OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    USERINFO_URL = "https://graph.microsoft.com/v1.0/me"

    def __init__(self, client_id: str, client_secret: str, tenant_id: str | None = None, **kwargs):
        """
        Initialize Microsoft provider.
        Args:
            client_id: Microsoft OAuth client ID
            client_secret: Microsoft OAuth client secret
            tenant_id: Optional tenant ID (uses 'common' if not provided)
            **kwargs: Additional configuration
        """
        # Use tenant-specific URLs if tenant_id provided.
        cleaned_tenant_id = tenant_id.strip() if isinstance(tenant_id, str) else None
        if cleaned_tenant_id:
            authorization_url = f"https://login.microsoftonline.com/{cleaned_tenant_id}/oauth2/v2.0/authorize"
            token_url = f"https://login.microsoftonline.com/{cleaned_tenant_id}/oauth2/v2.0/token"
        else:
            authorization_url = self.AUTHORIZATION_URL
            token_url = self.TOKEN_URL
        self._ms_tenant_segment = cleaned_tenant_id or "common"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=self.USERINFO_URL,
            **kwargs
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return self.provider_type.value
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MICROSOFT

    @property
    def oidc_issuer(self) -> str | None:
        """v2.0 issuer pattern; use a concrete tenant_id for strict id_token iss validation."""
        return f"https://login.microsoftonline.com/{self._ms_tenant_segment}/v2.0"

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"https://login.microsoftonline.com/{self._ms_tenant_segment}/discovery/v2.0/keys"

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Microsoft-specific authorization parameters."""
        return {
            'response_mode': 'query',
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
        # Normalize Microsoft user info format
        return {
            'id': user_info.get('id'),
            'email': user_info.get('mail') or user_info.get('userPrincipalName'),
            'name': user_info.get('displayName'),
            'given_name': user_info.get('givenName'),
            'family_name': user_info.get('surname'),
        }
