#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/mea_emea_fintech_stubs.py
Middle East & Africa retail / wallet / payment integrations without a portable
OAuth2 authorization-code + userinfo pair for arbitrary third-party IdP use.

Noon, Careem, STC Pay, and Fawry have dedicated provider modules elsewhere.
These classes satisfy the registry contract and return actionable XWProviderError
directing implementers to partner APIs, Safaricom/Airtel portals, or Antom/AlipayHK docs.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.3
Generation Date: 06-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class _MeaEmeaNonBrowserOAuth(ABaseProvider):
    """Base for MEA/EMEA fintech where login is app, USSD, MNO, or merchant-secret APIs."""

    _hint: str = "Use the vendor’s documented partner or mobile-money API; not browser OAuth2 SSO here."

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
            suggestions=[
                "See merchant / developer documentation for the specific country and product.",
                "Do not treat these rails like Google-style social login without vendor approval.",
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
            error_code="nonstandard_oauth_flow",
        )

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        raise XWProviderError(
            f"{self.provider_name}: {self._hint}",
            error_code="nonstandard_oauth_flow",
        )


class MafCarrefourProvider(_MeaEmeaNonBrowserOAuth):
    """MAF / Carrefour UAE & KSA — retail and loyalty integrations are program-specific (partner APIs)."""

    _hint = (
        "MAF Carrefour digital and loyalty integrations vary by market; use contracted partner or mall-app APIs."
    )

    @property
    def provider_name(self) -> str:
        return "maf_carrefour"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MAF_CARREFOUR


class AlipayHKProvider(_MeaEmeaNonBrowserOAuth):
    """AlipayHK (Antom) — user auth uses INTL prepareForRedirect / applyToken flows, not this base URL pattern."""

    _hint = (
        "AlipayHK uses docs.alipay.hk INTL OAuth (e.g. prepareForRedirect, applyToken, authSite ALIPAY_HK); "
        "integrate via Ant AlipayHK SDK or server APIs, not a single static authorize URL."
    )

    @property
    def provider_name(self) -> str:
        return "alipay_hk"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ALIPAY_HK


class MPesaProvider(_MeaEmeaNonBrowserOAuth):
    """Safaricom M-Pesa — Daraja / mobile money APIs; subscriber identity via approved B2C/C2B flows, not OAuth SSO."""

    _hint = (
        "Use Safaricom Daraja (OAuth for the *merchant app* is client/API credentials; end users authorize via STK Push/USSD)."
    )

    @property
    def provider_name(self) -> str:
        return "m_pesa"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.M_PESA


class AirtelMoneyProvider(_MeaEmeaNonBrowserOAuth):
    """Airtel Money — country and product specific merchant APIs; no universal third-party OAuth IdP URL."""

    _hint = "Use Airtel Africa / India developer documentation for the relevant wallet and disbursement products."

    @property
    def provider_name(self) -> str:
        return "airtel_money"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AIRTEL_MONEY


class JumiaProvider(_MeaEmeaNonBrowserOAuth):
    """Jumia — seller and affiliate APIs use API keys or partner onboarding, not consumer OAuth for your app as IdP."""

    _hint = "Use Jumia seller center / partner program APIs as documented for your integration type."

    @property
    def provider_name(self) -> str:
        return "jumia"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.JUMIA


class TeldaProvider(_MeaEmeaNonBrowserOAuth):
    """Telda (Egypt) — banking app; third-party access is not exposed as generic OAuth2 social login here."""

    _hint = "Use Telda partner or open-banking channels only if officially offered under contract."

    @property
    def provider_name(self) -> str:
        return "telda"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.TELDA


class OpayProvider(_MeaEmeaNonBrowserOAuth):
    """OPay — merchant and payment APIs; authentication is key- or credential-based per product, not portable OAuth IdP."""

    _hint = "Follow OPay developer documentation for Nigeria (or other markets) for the specific payment product."

    @property
    def provider_name(self) -> str:
        return "opay"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.OPAY


class FlutterwaveProvider(_MeaEmeaNonBrowserOAuth):
    """Flutterwave — API access typically uses client_credentials to idp.flutterwave.com, not end-user OAuth code flow."""

    _hint = (
        "Flutterwave REST APIs use short-lived bearer tokens from client_credentials "
        "(see developer.flutterwave.com); this is not end-user SSO for your application."
    )

    @property
    def provider_name(self) -> str:
        return "flutterwave"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FLUTTERWAVE
