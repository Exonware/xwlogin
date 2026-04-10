#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/adfs.py
ADFS OAuth Provider
Active Directory Federation Services (ADFS) OAuth 2.0 provider implementation.
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


class ADFSProvider(ABaseProvider):
    """Active Directory Federation Services (ADFS) OAuth 2.0 provider."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        adfs_url: str,
        resource: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize ADFS provider.
        Args:
            client_id: ADFS application client ID
            client_secret: ADFS client secret
            adfs_url: ADFS server URL (e.g., 'https://adfs.example.com/adfs')
            resource: Resource identifier (optional, for ADFS 3.0+)
            **kwargs: Additional configuration
        """
        adfs_url = adfs_url.rstrip('/')
        authorization_url = f"{adfs_url}/oauth2/authorize"
        token_url = f"{adfs_url}/oauth2/token"
        userinfo_url = f"{adfs_url}/oauth2/userinfo"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        self.resource = resource
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "adfs"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ADFS

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get ADFS-specific authorization parameters."""
        params = {}
        if self.resource:
            params['resource'] = self.resource
        return params

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from ADFS.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize ADFS user info format
        return {
            'id': user_info.get('sub') or user_info.get('upn'),
            'email': user_info.get('email') or user_info.get('upn'),
            'name': user_info.get('name'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
            'upn': user_info.get('upn'),  # User Principal Name
        }
