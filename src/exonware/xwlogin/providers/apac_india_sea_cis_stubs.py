#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/apac_india_sea_cis_stubs.py
APAC super-apps, wallets, India national rails, Korean neobanks, and Tier-4
CIS/CEE bank identity flows without a portable OAuth2 authorize+userinfo pair
for arbitrary third-party web SSO.

For **KakaoTalk**, **LINE**, **Zalo**, **Rakuten**, **Shopee**, **Samsung Account**,
**VK**, **Yandex**, **Mail.ru**, **Odnoklassniki**, **Google**, and **Facebook**,
use the dedicated provider modules already in this package.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 07-Apr-2026
"""

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any, Optional
class _ApacPartnerOrRailsOAuth(ABaseProvider):
    """Base for MNO, wallet, government, or bank program APIs — not generic social OAuth."""

    _hint: str = "Use the vendor’s partner developer program or national-rail documentation."

    def __init__(self, client_id: str = "", client_secret: str = "", **kwargs: Any):
        super().__init__(
            client_id=client_id or "__optional__",
            client_secret=client_secret or "__optional__",
            authorization_url="https://invalid.invalid/oauth/authorize",
            token_url="https://invalid.invalid/oauth/token",
            userinfo_url=None,
            **kwargs,
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
                "Onboard through the official developer or regulator portal for your jurisdiction.",
                "India-dominant Google/Facebook SSO still uses GoogleProvider and FacebookProvider.",
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


class MixiProvider(_ApacPartnerOrRailsOAuth):
    """mixi — legacy Japanese social; new third-party login integrations are largely discontinued."""

    _hint = "Historical mixi OpenID/social APIs are not suitable for new Google-style OAuth integrations."

    @property
    def provider_name(self) -> str:
        return "mixi"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MIXI


class GarenaProvider(_ApacPartnerOrRailsOAuth):
    """Garena / Sea — gaming identity and partner SSO are program-specific."""

    _hint = "Garena and Sea group gaming auth use partner contracts and regional game SDKs, not a single public OAuth2 userinfo URL."

    @property
    def provider_name(self) -> str:
        return "garena"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GARENA


class GrabProvider(_ApacPartnerOrRailsOAuth):
    """Grab — super-app; GrabPay and Grab partner APIs use Grab developer onboarding."""

    _hint = "Integrate via Grab Developer / partner OAuth and API products (region and use-case specific)."

    @property
    def provider_name(self) -> str:
        return "grab"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GRAB


class GotoProvider(_ApacPartnerOrRailsOAuth):
    """GoTo (Gojek, Tokopedia, et al.) — Indonesia ecosystem; APIs are merchant/partner gated."""

    _hint = "Use GoTo developer or merchant documentation for OAuth and identity across Gojek/Tokopedia products."

    @property
    def provider_name(self) -> str:
        return "goto"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GOTO


class MomoProvider(_ApacPartnerOrRailsOAuth):
    """MoMo (Vietnam) — wallet and payment identity via MoMo partner APIs."""

    _hint = "MoMo open APIs and OAuth-style flows are for registered partners; not arbitrary social login."

    @property
    def provider_name(self) -> str:
        return "momo"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MOMO


class TouchNGoProvider(_ApacPartnerOrRailsOAuth):
    """Touch ’n Go eWallet (Malaysia) — TNG Digital partner integrations."""

    _hint = "Touch ’n Go wallet authentication uses TNG Digital’s partner and eWallet APIs."

    @property
    def provider_name(self) -> str:
        return "touch_n_go"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.TOUCH_N_GO


class GCashProvider(_ApacPartnerOrRailsOAuth):
    """GCash (Philippines) — financial super-app; GCash developer / MP integrations."""

    _hint = "GCash identity and payments require GCash-for-business or Globe partner onboarding."

    @property
    def provider_name(self) -> str:
        return "gcash"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GCASH


class PayMayaProvider(_ApacPartnerOrRailsOAuth):
    """PayMaya / Maya (Philippines) — wallet and acquiring partner APIs."""

    _hint = "Maya PayMongo-style partner APIs replace ad-hoc OAuth; follow Maya Business developer docs."

    @property
    def provider_name(self) -> str:
        return "paymaya"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PAYMAYA


class PhonePeProvider(_ApacPartnerOrRailsOAuth):
    """PhonePe — UPI and merchant OAuth are Flipkart/PhonePe partner programs."""

    _hint = "PhonePe login and payments integrate via PhonePe PG / developer partnership, not public social OAuth."

    @property
    def provider_name(self) -> str:
        return "phonepe"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PHONEPE


class PaytmProvider(_ApacPartnerOrRailsOAuth):
    """Paytm — wallet, PG, and mini-app identity via Paytm for Business APIs."""

    _hint = "Paytm authentication for merchants uses Paytm developer credentials and product-specific flows."

    @property
    def provider_name(self) -> str:
        return "paytm"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.PAYTM


class AadhaarProvider(_ApacPartnerOrRailsOAuth):
    """Aadhaar (UIDAI) — national ID; online auth is AUA/KUA, eKYC, and regulated aggregator rails."""

    _hint = "Aadhaar authentication uses UIDAI-compliant ASP/KUA stacks, not browser OAuth2 against a single authorize URL."

    @property
    def provider_name(self) -> str:
        return "aadhaar"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AADHAAR


class DigiLockerProvider(_ApacPartnerOrRailsOAuth):
    """DigiLocker — government-issued document vault; integrations via MeitY / platform onboarding."""

    _hint = "DigiLocker access for RPs follows government API registration and consent models, not consumer social OAuth."

    @property
    def provider_name(self) -> str:
        return "digilocker"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DIGILOCKER


class IndiaStackAaProvider(_ApacPartnerOrRailsOAuth):
    """India Stack — Account Aggregator (AA) financial data consent flows (FIP/FIU), not login SSO."""

    _hint = "Account Aggregator is consent-based financial data sharing (ReBIT Sahamati), not a generic identity provider."

    @property
    def provider_name(self) -> str:
        return "india_stack_aa"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.INDIA_STACK_AA


class JioProvider(_ApacPartnerOrRailsOAuth):
    """Jio (Reliance) — telecom and Jio digital suite; partner and Jio developer program APIs."""

    _hint = "Jio identity and services integrate through Reliance Jio platform and enterprise contracts."

    @property
    def provider_name(self) -> str:
        return "jio"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.JIO


class TrueIdProvider(_ApacPartnerOrRailsOAuth):
    """TrueID (Thailand) — CP/True digital identity and media; partner OAuth where offered."""

    _hint = "TrueID integrations are region- and product-specific; use True developer or True partner channels."

    @property
    def provider_name(self) -> str:
        return "trueid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.TRUEID


class LineBankProvider(_ApacPartnerOrRailsOAuth):
    """LINE Bank (Taiwan, Thailand, etc.) — banking entity separate from LINE Login consumer channels."""

    _hint = "LINE Bank Open Banking and auth follow local banking regulation and LINE Financial partner APIs."

    @property
    def provider_name(self) -> str:
        return "line_bank"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.LINE_BANK


class KakaoBankProvider(_ApacPartnerOrRailsOAuth):
    """KakaoBank — Korean neobank; APIs are for partners under financial regulation."""

    _hint = "KakaoBank identity and accounts integrate via official banking APIs, not KakaoTalk OAuth alone."

    @property
    def provider_name(self) -> str:
        return "kakaobank"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.KAKAOBANK


class TossProvider(_ApacPartnerOrRailsOAuth):
    """Toss (Viva Republica) — Korean fintech; Toss Login / financial APIs for registered developers."""

    _hint = "Toss authentication products are documented on Toss Developers for approved financial and service partners."

    @property
    def provider_name(self) -> str:
        return "toss"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.TOSS


class TinkoffProvider(_ApacPartnerOrRailsOAuth):
    """Tinkoff — Russian neobank / ecosystem; Tinkoff Invest OpenAPI and Tinkoff ID are product-specific."""

    _hint = "Use Tinkoff Developer (invest, banking, ID) documentation and issued client credentials per product."

    @property
    def provider_name(self) -> str:
        return "tinkoff"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.TINKOFF


class SberbankOnlineProvider(_ApacPartnerOrRailsOAuth):
    """Sberbank Online — Sber ID and Sber developer APIs (separate from GigaChat AI OAuth)."""

    _hint = "Sber ecosystem OAuth (Sber ID, Sber Developers) is contract- and scope-specific."

    @property
    def provider_name(self) -> str:
        return "sberbank_online"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SBERBANK_ONLINE


class AlfaBankRuProvider(_ApacPartnerOrRailsOAuth):
    """Alfa-Bank (Russia) — corporate and open-banking style APIs via Alfa developer programs."""

    _hint = "Alfa-Bank third-party login and APIs are partner programs with bank-issued credentials."

    @property
    def provider_name(self) -> str:
        return "alfa_bank_ru"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ALFA_BANK_RU


class RaiffeisenProvider(_ApacPartnerOrRailsOAuth):
    """Raiffeisen Bank International / regional Raiffeisen entities — API and PSD2 programs per country."""

    _hint = "Raiffeisen APIs vary by CEE subsidiary; integrate the specific country’s developer or open-banking portal."

    @property
    def provider_name(self) -> str:
        return "raiffeisen"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.RAIFFEISEN
