#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/battle_net.py
Battle.net OAuth Provider
Battle.net (Blizzard) OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 25-Jan-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class BattleNetProvider(ABaseProvider):
    """Battle.net (Blizzard) OAuth 2.0 provider."""
    # Battle.net uses region-specific endpoints
    # Default to US, but can be configured for other regions
    AUTHORIZATION_URL = "https://us.battle.net/oauth/authorize"
    TOKEN_URL = "https://us.battle.net/oauth/token"
    USERINFO_URL = "https://us.battle.net/oauth/userinfo"

    def __init__(self, client_id: str, client_secret: str, region: str = "us", **kwargs):
        """
        Initialize Battle.net provider.
        Args:
            client_id: Battle.net Client ID
            client_secret: Battle.net Client Secret
            region: Region code (us, eu, kr, tw, cn) - default: us
            **kwargs: Additional configuration
        """
        # Region-specific endpoints
        region_map = {
            "us": "us.battle.net",
            "eu": "eu.battle.net",
            "kr": "kr.battle.net",
            "tw": "tw.battle.net",
            "cn": "www.battlenet.com.cn",
        }
        domain = region_map.get(region.lower(), "us.battle.net")
        authorization_url = f"https://{domain}/oauth/authorize"
        token_url = f"https://{domain}/oauth/token"
        userinfo_url = f"https://{domain}/oauth/userinfo"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            **kwargs
        )
        self.region = region.lower()
    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return "battle_net"
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.BATTLE_NET

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Battle.net.
        Args:
            access_token: Access token
        Returns:
            User information dictionary
        """
        user_info = await super().get_user_info(access_token)
        # Normalize Battle.net user info format
        return {
            'id': str(user_info.get('id')),
            'battletag': user_info.get('battletag'),
            'sub': user_info.get('sub'),
        }
