#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tier7_api_flow_providers.py
Tier-7 financial & identity vendors without a single browser OAuth code + userinfo pair.

Plaid: Link token + Link SDK; optional OAuth redirect inside Link for some institutions.
Envestnet | Yodlee: FastLink / API token flows.
MX: MX Connect widget and API.

Trulioo, Onfido, Jumio: document/KYC API workflows — not OAuth2 social login.

These classes satisfy the provider registry contract but surface clear errors directing
callers to the vendor's documented integration (REST, SDK, or widget).
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


class _Tier7ApiFlowProvider(ABaseProvider):
    """Base for vendors where OAuth authorization-code + userinfo is not the primary API."""

    _error_code: str = "api_flow_required"
    _hint: str = "Use the vendor REST API or official SDK as documented."

    def __init__(self, client_id: str = "", client_secret: str = "", **kwargs):
        super().__init__(
            client_id=client_id or "__optional__",
            client_secret=client_secret or "__optional__",
            authorization_url="https://invalid.invalid/oauth2/authorize",
            token_url="https://invalid.invalid/oauth2/token",
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
            error_code=self._error_code,
            suggestions=[
                "See vendor docs: Link token / widget / REST verification APIs.",
                "Do not use ABaseProvider browser redirects for this integration.",
            ],
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
            error_code=self._error_code,
        )

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        raise XWProviderError(
            f"{self.provider_name}: {self._hint}",
            error_code=self._error_code,
        )


class PlaidProvider(_Tier7ApiFlowProvider):
    """Plaid — bank connection via Link (`/link/token/create`, Link SDK / OAuth-in-Link)."""

    _hint = "Use Plaid Link: create a link_token server-side, then open Link; institution OAuth is embedded."

    @property
    def provider_name(self) -> str:
        return "plaid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PLAID


class YodleeProvider(_Tier7ApiFlowProvider):
    """Envestnet | Yodlee — aggregation via FastLink / partner APIs (not this OAuth base flow)."""

    _hint = "Use Yodlee FastLink or Envestnet APIs with registered app credentials."

    @property
    def provider_name(self) -> str:
        return "yodlee"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.YODLEE


class MXProvider(_Tier7ApiFlowProvider):
    """MX — MX Connect widget and platform APIs for money management / aggregation."""

    _hint = "Use MX Connect and MX Platform API user/member flows."

    @property
    def provider_name(self) -> str:
        return "mx"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MX


class TruliooProvider(_Tier7ApiFlowProvider):
    """Trulioo — global identity verification REST APIs (no OAuth2 login parity)."""

    _hint = "Use Trulioo Normalized API / workflow APIs with API key auth."

    @property
    def provider_name(self) -> str:
        return "trulioo"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.TRULIOO


class OnfidoProvider(_Tier7ApiFlowProvider):
    """Onfido — document & facial similarity checks via REST API / SDK."""

    _hint = "Use Onfido applicant + check APIs with API token authentication."

    @property
    def provider_name(self) -> str:
        return "onfido"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ONFIDO


class JumioProvider(_Tier7ApiFlowProvider):
    """Jumio — KYC/AML Netverify / platform workflows (API-driven)."""

    _hint = "Use Jumio acquisition + workflow APIs; authentication is API token based."

    @property
    def provider_name(self) -> str:
        return "jumio"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.JUMIO
