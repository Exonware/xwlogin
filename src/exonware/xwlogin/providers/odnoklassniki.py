#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/odnoklassniki.py
Odnoklassniki OAuth Provider
Odnoklassniki (OK.ru) OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
import hashlib
import hmac
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class OdnoklassnikiProvider(ABaseProvider):
    """Odnoklassniki (OK.ru) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://connect.ok.ru/oauth/authorize"
    TOKEN_URL = "https://api.ok.ru/oauth/token"
    USERINFO_URL = "https://api.ok.ru/fb.do"

    def __init__(self, client_id: str, client_secret: str, application_key: str = "", **kwargs):
        """
        Initialize Odnoklassniki provider.
        Args:
            client_id: Odnoklassniki Application ID
            client_secret: Odnoklassniki Application Secret Key
            application_key: Odnoklassniki Application Key (public key)
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
        self.application_key = application_key
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "odnoklassniki"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.ODNOKLASSNIKI

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Odnoklassniki.
        Note: Odnoklassniki requires signature-based API calls.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # Odnoklassniki requires signature for API calls
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        # Build request with signature
        method = "users.getCurrentUser"
        params = {
            'application_key': self.application_key,
            'method': method,
            'access_token': access_token,
            'format': 'json'
        }
        # Create signature
        sig_string = ''.join(f"{k}={v}" for k, v in sorted(params.items()) if k != 'sig')
        sig = hashlib.md5((sig_string + self._client_secret).encode()).hexdigest()
        params['sig'] = sig
        url = f"{self.USERINFO_URL}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize Odnoklassniki user info format
        return {
            'id': str(user_info.get('uid')),
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'name': f"{user_info.get('first_name', '')} {user_info.get('last_name', '')}".strip(),
            'photo': user_info.get('pic_1'),
        }
