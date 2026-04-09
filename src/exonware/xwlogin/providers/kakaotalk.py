#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/kakaotalk.py
KakaoTalk OAuth Provider
KakaoTalk OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class KakaoTalkProvider(ABaseProvider):
    """KakaoTalk OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://kauth.kakao.com/oauth/authorize"
    TOKEN_URL = "https://kauth.kakao.com/oauth/token"
    USERINFO_URL = "https://kapi.kakao.com/v2/user/me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize KakaoTalk provider.
        Args:
            client_id: Kakao REST API Key
            client_secret: Kakao Client Secret
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
        return "kakaotalk"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.KAKAOTALK

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get KakaoTalk-specific authorization parameters."""
        return {
            'response_type': 'code',
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from KakaoTalk.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize KakaoTalk user info format
        properties = user_info.get('kakao_account', {}).get('profile', {})
        return {
            'id': str(user_info.get('id')),
            'nickname': properties.get('nickname'),
            'profile_image': properties.get('profile_image_url'),
            'thumbnail_image': properties.get('thumbnail_image_url'),
            'email': user_info.get('kakao_account', {}).get('email'),
        }
