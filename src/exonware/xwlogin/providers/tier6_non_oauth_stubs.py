#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tier6_non_oauth_stubs.py
Providers where the primary documented integration is not browser OAuth code + userinfo.

EA (EA app / account): no public third-party OAuth spec surfaced like Steam; use first-party flows.
Peloton consumer API: session / partner-specific credentials rather than standard OAuth2 login.
Bandcamp merchant API: primarily client_credentials for approved partners — not end-user OAuth SSO.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 02-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class _NonStandardOAuthStub(ABaseProvider):
    _hint: str = "Use vendor-specific APIs or first-party authentication as documented."

    def __init__(self, client_id: str = "", client_secret: str = "", **kwargs):
        super().__init__(
            client_id=client_id or "__optional__",
            client_secret=client_secret or "__optional__",
            authorization_url="https://invalid.invalid/oauth/authorize",
            token_url="https://invalid.invalid/oauth/token",
            userinfo_url=None,
            **kwargs
        )

    async def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        state: str,
        scopes: Optional[list[str]] = None,
        nonce: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> str:
        raise XWProviderError(
            f"{self.provider_name}: {self._hint}",
            error_code="nonstandard_oauth_flow",
            suggestions=["Implement vendor REST/SDK flows instead of ABaseProvider redirects"],
        )

    async def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: Optional[str] = None,
    ) -> dict[str, Any]:
        raise XWProviderError(
            f"{self.provider_name}: {self._hint}",
            error_code="nonstandard_oauth_flow",
        )

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        raise XWProviderError(
            f"{self.provider_name}: {self._hint}",
            error_code="nonstandard_oauth_flow",
        )


class EaOriginProvider(_NonStandardOAuthStub):
    """Electronic Arts / EA app — no documented public OAuth2 authorization server for general IdP use."""

    _hint = "EA uses proprietary account flows; use official partner APIs if offered for your program."

    @property
    def provider_name(self) -> str:
        return "ea_origin"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.EA_ORIGIN


class PelotonProvider(_NonStandardOAuthStub):
    """Peloton — consumer endpoints are not exposed as standard OAuth2 for arbitrary apps."""

    _hint = "Use official Peloton partner / enterprise APIs where contractually available."

    @property
    def provider_name(self) -> str:
        return "peloton"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PELOTON


class BandcampProvider(_NonStandardOAuthStub):
    """Bandcamp partner API — OAuth2 is oriented to client_credentials for approved merch/label integrations."""

    _hint = "Approved partners use https://bandcamp.com/oauth_token with client_credentials; not browser SSO here."

    @property
    def provider_name(self) -> str:
        return "bandcamp"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.BANDCAMP
