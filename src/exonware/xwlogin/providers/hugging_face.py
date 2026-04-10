#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/hugging_face.py
Hugging Face OAuth Provider
Hugging Face OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class HuggingFaceProvider(ABaseProvider):
    """Hugging Face OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://huggingface.co/oauth/authorize"
    TOKEN_URL = "https://huggingface.co/oauth/token"
    USERINFO_URL = "https://huggingface.co/api/whoami"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Hugging Face provider.
        Args:
            client_id: Hugging Face Client ID
            client_secret: Hugging Face Client Secret
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
        return "hugging_face"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.HUGGING_FACE

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Hugging Face.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Hugging Face user info format
        return {
            'id': user_info.get('id'),
            'username': user_info.get('name'),
            'email': user_info.get('email'),
            'avatar_url': user_info.get('avatar_url'),
        }
