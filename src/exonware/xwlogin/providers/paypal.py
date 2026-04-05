#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/paypal.py
PayPal OAuth Provider
PayPal OAuth 2.0 provider implementation.
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


class PayPalProvider(ABaseProvider):
    """PayPal OAuth 2.0 provider."""
    # Production endpoints
    AUTHORIZATION_URL = "https://www.paypal.com/signin/authorize"
    TOKEN_URL = "https://api.paypal.com/v1/oauth2/token"
    USERINFO_URL = "https://api.paypal.com/v1/identity/openidconnect/userinfo"
    # Sandbox endpoints
    SANDBOX_AUTHORIZATION_URL = "https://www.sandbox.paypal.com/signin/authorize"
    SANDBOX_TOKEN_URL = "https://api.sandbox.paypal.com/v1/oauth2/token"
    SANDBOX_USERINFO_URL = "https://api.sandbox.paypal.com/v1/identity/openidconnect/userinfo"

    def __init__(self, client_id: str, client_secret: str, sandbox: bool = False, **kwargs):
        """
        Initialize PayPal provider.
        Args:
            client_id: PayPal OAuth client ID
            client_secret: PayPal OAuth client secret
            sandbox: Use sandbox environment (default: False)
            **kwargs: Additional configuration
        """
        if sandbox:
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
        return "paypal"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.PAYPAL

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token.
        PayPal requires Basic Auth for token exchange.
        Args:
            code: Authorization code
            redirect_uri: Redirect URI
        Returns:
            Token response dictionary
        """
        import base64
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
        }
        # PayPal requires Basic Authentication
        credentials = f"{self._client_id}:{self._client_secret}"
        auth_header = base64.b64encode(credentials.encode()).decode()
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.post(
            self._token_url,
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': f'Basic {auth_header}'
            }
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Token exchange failed: {response.status_code}",
                error_code="token_exchange_failed",
                context={'status_code': response.status_code, 'response': response.text}
            )
        return response.json()

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from PayPal.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize PayPal user info format (OpenID Connect)
        return {
            'id': user_info.get('user_id') or user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
        }
