#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/yahoo_japan.py
Yahoo! JAPAN YConnect (OAuth 2.0 / OpenID Connect) Provider
Distinct from U.S. Yahoo (`yahoo.py`); uses auth.login.yahoo.co.jp YConnect v2.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 07-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
class YahooJapanProvider(ABaseProvider):
    """Yahoo! JAPAN ID — YConnect v2 authorization and userinfo endpoints."""

    AUTHORIZATION_URL = "https://auth.login.yahoo.co.jp/yconnect/v2/authorization"
    TOKEN_URL = "https://auth.login.yahoo.co.jp/yconnect/v2/token"
    USERINFO_URL = "https://userinfo.yahooapis.jp/yconnect/v2/attribute"

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
        return "yahoo_japan"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.YAHOO_JAPAN

    def _get_authorization_params(self) -> dict[str, Any]:
        return {"response_type": "code"}
