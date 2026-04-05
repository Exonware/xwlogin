#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/matrix.py
Matrix OAuth Provider
Matrix protocol OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class MatrixProvider(ABaseProvider):
    """Matrix protocol OAuth 2.0 provider."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        homeserver_url: str = "https://matrix.org",
        **kwargs
    ):
        """
        Initialize Matrix provider.
        Args:
            client_id: Matrix Client ID
            client_secret: Matrix Client Secret
            homeserver_url: Matrix homeserver URL (default: https://matrix.org)
            **kwargs: Additional configuration
        """
        # Matrix uses OAuth endpoints on the homeserver
        authorization_url = f"{homeserver_url}/_matrix/client/r0/login/sso/redirect/oauth2/authorize"
        token_url = f"{homeserver_url}/_matrix/client/r0/login/sso/redirect/oauth2/token"
        userinfo_url = f"{homeserver_url}/_matrix/client/r0/account/whoami"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        self.homeserver_url = homeserver_url
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "matrix"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.MATRIX

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Matrix.
        Args:
            access_token: Access token (Matrix access token)
        Returns:
            User information dictionary
        """
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self.USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Matrix user info format
        return {
            'id': user_info.get('user_id'),
        }
