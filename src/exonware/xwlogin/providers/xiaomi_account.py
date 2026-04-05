#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/xiaomi_account.py
Xiaomi Account (小米账号) OAuth 2.0 Provider
Mi Passport authorization-code flow for ecosystem / HyperOS developer apps.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 07-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
class XiaomiAccountProvider(ABaseProvider):
    """Xiaomi Account OAuth 2.0 (authorization code)."""

    AUTHORIZATION_URL = "https://account.xiaomi.com/oauth2/authorize"
    TOKEN_URL = "https://account.xiaomi.com/oauth2/token"
    USERINFO_URL = "https://open.account.xiaomi.com/user/profile"

    def __init__(self, client_id: str, client_secret: str, **kwargs: Any):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=self.USERINFO_URL,
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "xiaomi"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.XIAOMI

    def _get_authorization_params(self) -> dict[str, Any]:
        return {}
