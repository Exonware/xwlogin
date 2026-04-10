#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/huawei_id.py
HUAWEI ID (Account Kit) OAuth 2.0 / OIDC Provider
Consumer HMS “Log in with HUAWEI ID” — OAuth v3 authorize and token endpoints.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 07-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
class HuaweiIdProvider(ABaseProvider):
    """HUAWEI ID OAuth 2.0 (authorization code; OIDC scopes such as openid)."""

    AUTHORIZATION_URL = "https://oauth-login.cloud.huawei.com/oauth2/v3/authorize"
    TOKEN_URL = "https://oauth-login.cloud.huawei.com/oauth2/v3/token"
    USERINFO_URL = "https://account.cloud.huawei.com/oauth2/v3/userinfo"

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
        return "huawei_id"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.HUAWEI_ID

    def _get_authorization_params(self) -> dict[str, Any]:
        return {}
