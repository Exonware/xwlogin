#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/discord_gaming.py
Discord (gaming-focused registry id) Provider
Same OAuth implementation as DiscordProvider; register as `discord_gaming` when Tier labels
need a distinct provider key (e.g. game launcher vs workplace Discord).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ProviderType
from exonware.xwsystem import get_logger
from .discord import DiscordProvider
logger = get_logger(__name__)


class DiscordGamingProvider(DiscordProvider):
    """Discord OAuth 2.0 with provider name `discord_gaming`."""

    @property
    def provider_name(self) -> str:
        return "discord_gaming"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DISCORD_GAMING
