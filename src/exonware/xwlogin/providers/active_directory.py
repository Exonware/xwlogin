#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/active_directory.py
Active Directory OAuth Provider
Active Directory OAuth 2.0 provider implementation.
This provider uses ADFS or Azure AD for authentication.
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


class ActiveDirectoryProvider(ABaseProvider):
    """
    Active Directory OAuth 2.0 provider.
    This provider can work with:
    - Azure AD (Microsoft Entra ID)
    - ADFS (Active Directory Federation Services)
    - On-premises AD via ADFS
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        authority_url: str,
        **kwargs
    ):
        """
        Initialize Active Directory provider.
        Args:
            client_id: AD application client ID
            client_secret: AD client secret
            authority_url: Authority URL (Azure AD or ADFS endpoint)
            **kwargs: Additional configuration
        """
        authority_url = authority_url.rstrip('/')
        # Determine if Azure AD or ADFS based on URL
        if 'microsoftonline.com' in authority_url or 'login.microsoftonline.com' in authority_url:
            # Azure AD
            authorization_url = f"{authority_url}/oauth2/v2.0/authorize"
            token_url = f"{authority_url}/oauth2/v2.0/token"
            userinfo_url = "https://graph.microsoft.com/v1.0/me"
        else:
            # ADFS
            authorization_url = f"{authority_url}/oauth2/authorize"
            token_url = f"{authority_url}/oauth2/token"
            userinfo_url = f"{authority_url}/oauth2/userinfo"
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
        return "active_directory"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ACTIVE_DIRECTORY

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Active Directory.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Active Directory user info format
        return {
            'id': user_info.get('id') or user_info.get('sub'),
            'email': user_info.get('mail') or user_info.get('email') or user_info.get('userPrincipalName'),
            'name': user_info.get('displayName') or user_info.get('name'),
            'given_name': user_info.get('givenName'),
            'family_name': user_info.get('surname') or user_info.get('family_name'),
            'upn': user_info.get('userPrincipalName') or user_info.get('upn'),
        }
