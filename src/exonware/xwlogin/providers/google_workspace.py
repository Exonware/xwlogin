#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/google_workspace.py
Google Workspace OAuth Provider
Google Workspace (formerly G Suite) OAuth 2.0 provider implementation.
This is specifically for Google Workspace enterprise accounts.
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


class GoogleWorkspaceProvider(ABaseProvider):
    """Google Workspace OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    # Admin SDK endpoint for workspace-specific info
    ADMIN_USERINFO_URL = "https://admin.googleapis.com/admin/directory/v1/users/{userKey}"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        domain: Optional[str] = None,
        use_admin_api: bool = False,
        **kwargs
    ):
        """
        Initialize Google Workspace provider.
        Args:
            client_id: Google OAuth client ID
            client_secret: Google OAuth client secret
            domain: Google Workspace domain (optional, for domain restriction)
            use_admin_api: Use Admin SDK API for additional workspace info (requires admin scope)
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
        self.domain = domain
        self.use_admin_api = use_admin_api
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "google_workspace"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.GOOGLE_WORKSPACE

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Google Workspace-specific authorization parameters."""
        params = {
            'access_type': 'offline',
            'prompt': 'consent',
        }
        # Add domain restriction if specified
        if self.domain:
            params['hd'] = self.domain  # Hosted domain parameter
        return params

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Google Workspace.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Google Workspace user info format
        result = {
            'id': user_info.get('id'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'verified_email': user_info.get('verified_email', False),
            'hd': user_info.get('hd'),  # Hosted domain (workspace domain)
        }
        # Optionally fetch additional workspace info from Admin SDK
        if self.use_admin_api and user_info.get('email'):
            try:
                if self._async_http_client is None:
                    from exonware.xwsystem.http_client import AsyncHttpClient
                    self._async_http_client = AsyncHttpClient()
                admin_url = self.ADMIN_USERINFO_URL.format(userKey=user_info.get('email'))
                admin_response = await self._async_http_client.get(
                    admin_url,
                    headers={'Authorization': f'Bearer {access_token}'}
                )
                if admin_response.status_code == 200:
                    admin_data = admin_response.json()
                    result.update({
                        'org_unit_path': admin_data.get('orgUnitPath'),
                        'department': admin_data.get('department'),
                        'job_title': admin_data.get('jobTitle'),
                        'manager': admin_data.get('manager'),
                    })
            except Exception as e:
                logger.warning(f"Failed to fetch Admin SDK data: {e}")
        return result
