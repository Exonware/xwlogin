#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/naver.py
Naver OAuth Provider
Naver (South Korea) OAuth 2.0 — national portal/search IdP alongside Kakao.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 07-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
from typing import Any
class NaverProvider(ABaseProvider):
    """Naver OAuth 2.0 provider (Naver Login, Open API)."""

    AUTHORIZATION_URL = "https://nid.naver.com/oauth2.0/authorize"
    TOKEN_URL = "https://nid.naver.com/oauth2.0/token"
    USERINFO_URL = "https://openapi.naver.com/v1/nid/me"

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
        return "naver"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.NAVER

    def _get_authorization_params(self) -> dict[str, Any]:
        return {"response_type": "code"}

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        raw = await super().get_user_info(access_token)
        r = raw.get("response") if isinstance(raw, dict) else None
        if not isinstance(r, dict):
            return raw if isinstance(raw, dict) else {}
        return {
            "id": r.get("id"),
            "nickname": r.get("nickname"),
            "name": r.get("name"),
            "email": r.get("email"),
            "profile_image": r.get("profile_image"),
        }
