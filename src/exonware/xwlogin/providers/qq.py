#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/qq.py
QQ OAuth Provider
QQ OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any

from exonware.xwsystem import get_logger
from exonware.xwsystem.io.serialization.formats.text import json as xw_json
logger = get_logger(__name__)


class QQProvider(ABaseProvider):
    """QQ OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://graph.qq.com/oauth2.0/authorize"
    TOKEN_URL = "https://graph.qq.com/oauth2.0/token"
    USERINFO_URL = "https://graph.qq.com/oauth2.0/me"
    USER_DETAILS_URL = "https://graph.qq.com/user/get_user_info"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize QQ provider.
        Args:
            client_id: QQ App ID
            client_secret: QQ App Key
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
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "qq"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.QQ

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token.
        QQ returns token in query string format, not JSON.
        Args:
            code: Authorization code
            redirect_uri: Redirect URI
        Returns:
            Token response dictionary
        """
        params = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'redirect_uri': redirect_uri,
        }
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self._token_url,
            params=params
        )
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"Token exchange failed: {response.status_code}",
                error_code="token_exchange_failed",
                context={'status_code': response.status_code, 'response': response.text}
            )
        # QQ returns access_token=xxx&expires_in=xxx format
        from urllib.parse import parse_qs
        token_data = parse_qs(response.text)
        return {k: v[0] if v else None for k, v in token_data.items()}

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from QQ.
        QQ requires two API calls: first get openid, then get user details.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        # First, get openid
        openid_url = f"{self.USERINFO_URL}?access_token={access_token}"
        openid_response = await self._async_http_client.get(openid_url)
        if openid_response.status_code != 200:
            raise XWProviderConnectionError(
                f"OpenID request failed: {openid_response.status_code}",
                error_code="openid_failed",
                context={'status_code': openid_response.status_code}
            )
        # QQ returns callback( {"client_id":"xxx","openid":"xxx"} )
        import re
        openid_text = openid_response.text
        json_match = re.search(r'\{[^}]+\}', openid_text)
        if json_match:
            openid_data = xw_json.loads(json_match.group())
            openid = openid_data.get('openid')
        else:
            raise XWProviderConnectionError(
                "Failed to parse openid from QQ response",
                error_code="openid_parse_failed"
            )
        # Then get user details
        details_url = f"{self.USER_DETAILS_URL}?access_token={access_token}&oauth_consumer_key={self._client_id}&openid={openid}"
        details_response = await self._async_http_client.get(details_url)
        if details_response.status_code != 200:
            raise XWProviderConnectionError(
                f"User details request failed: {details_response.status_code}",
                error_code="user_details_failed",
                context={'status_code': details_response.status_code}
            )
        user_info = details_response.json()
        # Normalize QQ user info format
        return {
            'id': openid,
            'nickname': user_info.get('nickname'),
            'avatar_url': user_info.get('figureurl_2') or user_info.get('figureurl_1'),
            'gender': user_info.get('gender'),
        }
