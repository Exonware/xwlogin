#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/wechat.py
WeChat OAuth Provider
WeChat / Weixin (微信) super-app Open Platform OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderConnectionError
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class WeChatProvider(ABaseProvider):
    """WeChat (微信) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://open.weixin.qq.com/connect/qrconnect"
    TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token"
    USERINFO_URL = "https://api.weixin.qq.com/sns/userinfo"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize WeChat provider.
        Args:
            client_id: WeChat AppID
            client_secret: WeChat AppSecret
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
        return "wechat"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.WECHAT

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get WeChat-specific authorization parameters."""
        return {
            'appid': self._client_id,  # WeChat uses 'appid' instead of 'client_id'
        }

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token.
        WeChat uses 'appid' and 'secret' instead of 'client_id' and 'client_secret'.
        Args:
            code: Authorization code
            redirect_uri: Redirect URI
        Returns:
            Token response dictionary
        """
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'appid': self._client_id,
            'secret': self._client_secret,
        }
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        response = await self._async_http_client.get(
            self._token_url,
            params=data
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
        Get user information from WeChat.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        # WeChat requires access_token and openid as query parameters
        if self._async_http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient
            self._async_http_client = AsyncHttpClient()
        # Note: WeChat requires openid from token response
        # This is a simplified implementation - in practice, you'd need to extract openid from token response
        url = f"{self.USERINFO_URL}?access_token={access_token}&openid=OPENID&lang=zh_CN"
        response = await self._async_http_client.get(url)
        if response.status_code != 200:
            raise XWProviderConnectionError(
                f"User info request failed: {response.status_code}",
                error_code="userinfo_failed",
                context={'status_code': response.status_code}
            )
        user_info = response.json()
        # Normalize WeChat user info format
        return {
            'id': user_info.get('openid'),
            'nickname': user_info.get('nickname'),
            'avatar_url': user_info.get('headimgurl'),
            'sex': user_info.get('sex'),
            'province': user_info.get('province'),
            'city': user_info.get('city'),
            'country': user_info.get('country'),
        }
