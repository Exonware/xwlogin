#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/discord.py
Discord OAuth Provider
Discord OAuth 2.0 provider implementation.
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


class DiscordProvider(ABaseProvider):
    """Discord OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://discord.com/api/oauth2/authorize"
    TOKEN_URL = "https://discord.com/api/oauth2/token"
    USERINFO_URL = "https://discord.com/api/users/@me"

    def __init__(self, client_id: str, client_secret: str, **kwargs):
        """
        Initialize Discord provider.
        Args:
            client_id: Discord OAuth client ID
            client_secret: Discord OAuth client secret
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
        return "discord"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.DISCORD

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Discord.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Discord user info format
        # Discord provides: id, username, discriminator, avatar, email, verified, etc.
        email = user_info.get("email")
        username = user_info.get("username")
        discriminator = user_info.get("discriminator")
        # Build display name
        if discriminator and discriminator != "0":
            display_name = f"{username}#{discriminator}"
        else:
            display_name = username
        return {
            'id': str(user_info.get('id')),
            'email': email,
            'name': display_name,
            'username': username,
            'avatar_url': f"https://cdn.discordapp.com/avatars/{user_info.get('id')}/{user_info.get('avatar')}.png" if user_info.get('avatar') else None,
            'verified': user_info.get('verified', False),
        }
