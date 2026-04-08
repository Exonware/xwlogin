#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/dingtalk.py
DingTalk OAuth Provider
DingTalk (钉钉) OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class DingTalkProvider(ABaseProvider):
    """DingTalk (钉钉) OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://oapi.dingtalk.com/connect/oauth2/sns_authorize"
    TOKEN_URL = "https://oapi.dingtalk.com/sns/gettoken"
    USERINFO_URL = "https://oapi.dingtalk.com/sns/getuserinfo_bycode"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize DingTalk provider.
        Args:
            client_id: DingTalk App ID
            client_secret: DingTalk App Secret
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
        return "dingtalk"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.DINGTALK

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from DingTalk.
        Note: DingTalk has a different flow - requires code to get user info directly.
        This is a simplified implementation.
        Args:
            access_token: Access token (or code for DingTalk)
        Returns:
            User information dictionary
        """
        logger.warning(
            "DingTalk uses a different OAuth flow. "
            "User info requires code parameter, not access token. "
            "This is a simplified implementation."
        )
        return {
            'id': None,
            'name': None,
        }
