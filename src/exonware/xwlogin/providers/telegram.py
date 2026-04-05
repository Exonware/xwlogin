#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/telegram.py
Telegram OAuth Provider
Telegram Login Widget OAuth provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any
import hmac
import hashlib
import time
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class TelegramProvider(ABaseProvider):
    """
    Telegram authentication provider.
    Note: Telegram uses a custom authentication flow (not standard OAuth 2.0).
    This implementation supports Telegram Login Widget authentication.
    """
    # Telegram doesn't use standard OAuth endpoints
    # Instead, it uses a widget-based authentication
    AUTHORIZATION_URL = "https://oauth.telegram.org/auth"
    TOKEN_URL = "https://oauth.telegram.org/token"
    USERINFO_URL = "https://api.telegram.org/bot{bot_token}/getMe"

    def __init__(self, client_id: str, client_secret: str, bot_token: str = "", **kwargs):
        """
        Initialize Telegram provider.
        Args:
            client_id: Telegram Bot Token (used as client_id)
            client_secret: Telegram Bot Secret (for verification)
            bot_token: Telegram Bot Token for API calls
            **kwargs: Additional configuration
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.USERINFO_URL.format(bot_token=bot_token) if bot_token else "",
            **kwargs
        )
        self.bot_token = bot_token
        logger.warning(
            "Telegram uses a custom authentication flow, not standard OAuth 2.0. "
            "This implementation supports Telegram Login Widget."
        )
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "telegram"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.TELEGRAM

    def verify_telegram_auth(self, auth_data: dict[str, Any]) -> bool:
        """
        Verify Telegram authentication data.
        Args:
            auth_data: Authentication data from Telegram widget
        Returns:
            True if valid, False otherwise
        """
        # Telegram sends auth data with hash for verification
        received_hash = auth_data.get('hash')
        if not received_hash:
            return False
        # Create data check string
        auth_data_copy = {k: v for k, v in auth_data.items() if k != 'hash'}
        data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(auth_data_copy.items()))
        # Create secret key
        secret_key = hashlib.sha256(self._client_secret.encode()).digest()
        # Calculate hash
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        return calculated_hash == received_hash

    async def get_user_info(self, auth_data: dict[str, Any]) -> dict[str, Any]:
        """
        Get user information from Telegram authentication data.
        Note: Telegram doesn't use access tokens. Instead, it provides
        user data directly in the authentication response.
        Args:
            auth_data: Authentication data from Telegram widget
        Returns:
            User information dictionary
        """
        # Verify authentication data
        if not self.verify_telegram_auth(auth_data):
            raise XWProviderError(
                "Invalid Telegram authentication data",
                error_code="invalid_telegram_auth"
            )
        # Normalize Telegram user info format
        return {
            'id': str(auth_data.get('id')),
            'first_name': auth_data.get('first_name'),
            'last_name': auth_data.get('last_name'),
            'username': auth_data.get('username'),
            'photo_url': auth_data.get('photo_url'),
        }
