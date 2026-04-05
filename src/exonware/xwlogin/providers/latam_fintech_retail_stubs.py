#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/latam_fintech_retail_stubs.py
Latin America delivery, banking, media, and payment rails without a standard
OAuth2 authorization-code IdP suitable for generic social-login style wiring.

Mercado Libre uses `mercado_libre.MercadoLibreProvider`.
These providers raise XWProviderError with error_code=nonstandard_oauth_flow so
callers route to partner banking APIs, MELI/CPay docs, or national payment systems (e.g. SPEI).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 06-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)


class _LatamNonBrowserOAuth(ABaseProvider):
    """Base for LATAM apps where identity is mobile-banking, wallet, or B2B API credentials."""

    _hint: str = "Integrate via the vendor’s official developer or open-finance documentation for that country."

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
                "Use bank/wallet SDK flows, STK/P2P rails, or contracted partner APIs—not generic browser OAuth here.",
                "Confirm regulatory and sandbox access for the target market before integration.",
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


class RappiProvider(_LatamNonBrowserOAuth):
    """Rappi (delivery super-app) — partner and Turbo integrations are API/onboarding specific."""

    _hint = "Use Rappi partner or Turbo developer programs; not a public OAuth2 IdP for arbitrary third-party login."

    @property
    def provider_name(self) -> str:
        return "rappi"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.RAPPI


class NubankProvider(_LatamNonBrowserOAuth):
    """Nubank — Nu Pagamentos; open banking and partnerships use regulated APIs, not generic OAuth SSO here."""

    _hint = "Follow Nu / Nubank developer and open-finance documentation for Brazil (and other markets) under contract."

    @property
    def provider_name(self) -> str:
        return "nubank"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.NUBANK


class PicPayProvider(_LatamNonBrowserOAuth):
    """PicPay (Brazil) — wallet and acquiring products use B2B keys and app-centric user consent flows."""

    _hint = "Use PicPay developer portal flows for merchants/partners; not portable Google-style OAuth IdP."

    @property
    def provider_name(self) -> str:
        return "picpay"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PICPAY


class UolProvider(_LatamNonBrowserOAuth):
    """UOL (Universo Online) — legacy portal properties; third-party login integrations vary by product."""

    _hint = "UOL services do not expose a single standard OAuth2 social IdP for arbitrary apps; use product-specific APIs if offered."

    @property
    def provider_name(self) -> str:
        return "uol"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.UOL


class GloboProvider(_LatamNonBrowserOAuth):
    """Globo — Brazilian media group; identity for Globo ID / products is first-party, not generic third-party OAuth."""

    _hint = "Use Globo partner or identity product documentation when available under commercial agreement."

    @property
    def provider_name(self) -> str:
        return "globo"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GLOBO


class OxxoProvider(_LatamNonBrowserOAuth):
    """Oxxo (FEMSA retail) — Spin by Oxxo / financial products use proprietary onboarding, not this OAuth base."""

    _hint = "Integrate via Oxxo/Spin partner channels and Mexico financial APIs as published for your use case."

    @property
    def provider_name(self) -> str:
        return "oxxo"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.OXXO


class SpeiProvider(_LatamNonBrowserOAuth):
    """SPEI — Mexico’s interbank transfer system (Banxico rail); identities are CLABE/bank credentials, not OAuth login."""

    _hint = (
        "SPEI is a payment rail (bank-to-bank), not an OAuth identity provider. "
        "Use participating banks’ APIs or authorized PSP integrations."
    )

    @property
    def provider_name(self) -> str:
        return "spei"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SPEI


class NequiProvider(_LatamNonBrowserOAuth):
    """Nequi (Bancolombia digital wallet, Colombia) — app and partner APIs; not a generic web OAuth IdP."""

    _hint = "Use Bancolombia/Nequi developer documentation for approved wallet and payment integrations."

    @property
    def provider_name(self) -> str:
        return "nequi"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.NEQUI


class DaviviendaProvider(_LatamNonBrowserOAuth):
    """Banco Davivienda (Colombia and region) — corporate and open-banking APIs are contract and certificate driven."""

    _hint = "Follow Davivienda developer/open-banking docs for the relevant country; user auth stays in the bank channel."

    @property
    def provider_name(self) -> str:
        return "davivienda"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DAVIVIENDA


class BancolombiaProvider(_LatamNonBrowserOAuth):
    """Bancolombia — mobile and API access uses strong customer auth inside banking programs, not third-party OAuth IdP."""

    _hint = "Use Bancolombia APIs and developer onboarding for partners; not social-login OAuth in this module."

    @property
    def provider_name(self) -> str:
        return "bancolombia"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.BANCOLOMBIA


class AgrupacionDragonProvider(_LatamNonBrowserOAuth):
    """Agrupación Dragón / regional Argentine payment alliance — integrate only via contracted clearing or bank APIs."""

    _hint = (
        "Verify the exact legal entity and technical specification for your program (clearing house / bank consortium). "
        "There is no stable public OAuth2 authorize URL for arbitrary IdP use."
    )

    @property
    def provider_name(self) -> str:
        return "agrupacion_dragon"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AGRUPACION_DRAGON


class PersonalPayProvider(_LatamNonBrowserOAuth):
    """Personal Pay (Telecom Argentina wallet) — Telco/fintech product APIs are partner-scoped."""

    _hint = "Use Telecom/Personal Pay partner developer resources where published; not generic browser OAuth IdP."

    @property
    def provider_name(self) -> str:
        return "personal_pay"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PERSONAL_PAY
