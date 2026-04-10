#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/eidas_europe_providers.py
EU eIDAS-aligned and national digital-identity integrations: OIDC where a stable
public endpoint set exists, plus stubs for bank-app, eID-card, SAML-broker, or
program-specific flows that are not generic OAuth2 userinfo clients.

NHS Login and GOV.UK One Login URLs follow published technical onboarding.
France Connect paths are environment-specific (integration vs production).
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 02-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any, Literal, Optional
class _EidasNonPortableOAuth(ABaseProvider):
    """National eID, bank mobile apps, SAML federations, or MNO SSO — not this OAuth2 base."""

    _hint: str = "Integrate via the scheme’s official SDK, broker, or contracted federation documentation."

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
                "Use the national or bank developer portal for test certificates and RP onboarding.",
                "Do not assume Google-style social OAuth without reading the local OIDC/SAML profile.",
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


# --- Stubs: app / card / broker flows -------------------------------------------------


class IdAustriaProvider(_EidasNonPortableOAuth):
    """Austrian national eID (e.g. card-based); browser OIDC is via official brokers, not a single static URL here."""

    _hint = (
        "ID Austria / national eID uses card and official identity middleware; use eIDAS connector docs and test PKI."
    )

    @property
    def provider_name(self) -> str:
        return "id_austria"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ID_AUSTRIA


class ItsmeProvider(_EidasNonPortableOAuth):
    """itsme — Belgium; app-centric Strong Customer Authentication, partner onboarding required."""

    _hint = "itsme integrates via contracted merchant/RP APIs and itsme’s documented OIDC profile; not a generic public social IdP."

    @property
    def provider_name(self) -> str:
        return "itsme"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ITSME


class BankIDNordicProvider(_EidasNonPortableOAuth):
    """Umbrella hint: Nordic BankID covers Swedish and Norwegian products with different endpoints and RP programs."""

    _hint = (
        "Use BankIDSwedenProvider or BankIDNorwayProvider / vendor docs; Swedish BankID and Norwegian BankID are distinct programs."
    )

    @property
    def provider_name(self) -> str:
        return "bankid_nordic"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.BANKID_NORDIC


class BankIDSwedenProvider(_EidasNonPortableOAuth):
    """Swedish BankID — Redirect/Mobile/API flows with bank-issued test environment."""

    _hint = "Swedish BankID uses bank-operated OIDC-style redirects and order/sign APIs; register as RP with BankID."

    @property
    def provider_name(self) -> str:
        return "bankid_sweden"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.BANKID_SWEDEN


class BankIDNorwayProvider(_EidasNonPortableOAuth):
    """Norwegian BankID — separate product from Swedish BankID (OIDC BankID Norway)."""

    _hint = "Norwegian BankID publishes OIDC for merchants; obtain client credentials from BankID Norway, not this placeholder."

    @property
    def provider_name(self) -> str:
        return "bankid_norway"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.BANKID_NORWAY


class MitIDProvider(_EidasNonPortableOAuth):
    """Denmark MitID — brokered authentication (MitID Erhverv / private mitid.dk integration)."""

    _hint = "MitID integrates via official brokers and Danish IdP contracts; browser flows are not a single global authorize URL."

    @property
    def provider_name(self) -> str:
        return "mitid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MITID


class DigiDProvider(_EidasNonPortableOAuth):
    """Netherlands DigiD — SAML/OIDC via government broker (not arbitrary third-party social login)."""

    _hint = "DigiD is offered through Logius / SAML and OIDC for government services; use the DigiD connection scheme."

    @property
    def provider_name(self) -> str:
        return "digid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DIGID


class FcBarcelonaDigitalIdProvider(_EidasNonPortableOAuth):
    """FC Barcelona municipal digital-ID pilot / program-specific (not a generic EU-wide IdP)."""

    _hint = "Participate via the pilot’s published technical onboarding; endpoints are not standardized like France Connect."

    @property
    def provider_name(self) -> str:
        return "fc_barcelona_digital_id"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FC_BARCELONA_DIGITAL_ID


class SpidProvider(_EidasNonPortableOAuth):
    """Italy SPID — SAML federation with many IdPs; OIDC is mediated through AGID-registered brokers."""

    _hint = "SPID is SAML-first; use a certified SPID service provider library and metadata exchange, not this OAuth base."

    @property
    def provider_name(self) -> str:
        return "spid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SPID


class PosteIdProvider(_EidasNonPortableOAuth):
    """Italy PosteID — SPID-qualified IdP with Poste Italiane integration rules."""

    _hint = "PosteID follows SPID rules; integrate as SPID RP toward Poste’s IdP metadata and certificates."

    @property
    def provider_name(self) -> str:
        return "posteid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.POSTEID


class SwissIdProvider(_EidasNonPortableOAuth):
    """SwissID — SwissSign/e-ID ecosystem; OIDC/SAML via SwissID registration."""

    _hint = "SwissID exposes federated login for registered RPs; obtain SwissID developer access and use their documented endpoints."

    @property
    def provider_name(self) -> str:
        return "swissid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SWISSID


class FtnProvider(_EidasNonPortableOAuth):
    """Finnish Trust Network — SAML/OIDC through Finnish trust brokers and IdPs."""

    _hint = "FTN uses Suomi.fi and Traficom-approved brokers; integrate via Finnish e-identification documentation."

    @property
    def provider_name(self) -> str:
        return "ftn"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FTN


class SmartIdProvider(_EidasNonPortableOAuth):
    """Smart-ID — Baltic/Nordic mobile app authentication; RP API, not generic browser OAuth here."""

    _hint = "Smart-ID uses session start and signature APIs; use SK ID Solutions developer documentation."

    @property
    def provider_name(self) -> str:
        return "smart_id"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SMART_ID


class GovUkVerifyProvider(_EidasNonPortableOAuth):
    """GOV.UK Verify (legacy) — closed to new RPs; retained for interoperability notes only."""

    _hint = "GOV.UK Verify is legacy; new services should use GOV.UK One Login (GovUkOneLoginProvider)."

    @property
    def provider_name(self) -> str:
        return "govuk_verify"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GOVUK_VERIFY


class GermanEidProvider(_EidasNonPortableOAuth):
    """German nPA / eID — AusweisApp2 and eID-Server; online-aufruf with smart card, not password OAuth."""

    _hint = "Use BSI / AusweisApp2 eID-Server integration; browser OAuth analogy does not apply."

    @property
    def provider_name(self) -> str:
        return "german_eid"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GERMAN_EID


class IdinProvider(_EidasNonPortableOAuth):
    """Netherlands iDIN — bank-based identity via Dutch banks’ iDIN scheme."""

    _hint = "iDIN is bank-federated; integrate through participating banks’ iDIN/OIDC documentation as RP."

    @property
    def provider_name(self) -> str:
        return "idin"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.IDIN


class VerifiedMeProvider(_EidasNonPortableOAuth):
    """Verified.Me (Canada) — bank/network identity; partner program similar in spirit to EU bank IdPs."""

    _hint = "Verified.Me uses bank-consent and network APIs; onboard via Interac / Verified.Me developer program."

    @property
    def provider_name(self) -> str:
        return "verified_me"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.VERIFIED_ME


class MobileConnectGsmaProvider(_EidasNonPortableOAuth):
    """GSMA Mobile Connect — operator OIDC profile; MNO Discovery, client_ids per operator hub."""

    _hint = (
        "Mobile Connect uses operator authorization servers and discovery; implement MC OIDC per GSMA spec and operator contracts."
    )

    @property
    def provider_name(self) -> str:
        return "mobile_connect_gsma"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.MOBILE_CONNECT_GSMA


class KeycloakEuProvider(ABaseProvider):
    """
    Keycloak realm OIDC — “EU” denotes deployment in EU regions; URLs are your sovereign host + realm.
    Use this when hosting Keycloak in EU for data-residency (ProviderType.KEYCLOAK_EU vs generic KEYCLOAK enum).
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        keycloak_base_url: str,
        realm: str,
        **kwargs: Any,
    ):
        base = keycloak_base_url.removesuffix("/")
        realm = realm.strip().strip("/")
        auth = f"{base}/realms/{realm}/protocol/openid-connect/auth"
        token = f"{base}/realms/{realm}/protocol/openid-connect/token"
        userinfo = f"{base}/realms/{realm}/protocol/openid-connect/userinfo"
        self._issuer = f"{base}/realms/{realm}"
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=auth,
            token_url=token,
            userinfo_url=userinfo,
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "keycloak_eu"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.KEYCLOAK_EU

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/protocol/openid-connect/certs"


class Auth0EuropeProvider(ABaseProvider):
    """
    Auth0 with EU data-residency: tenant hostname is ``{tenant}.eu.auth0.com``.
    GDPR posture is tenant/contract configuration; this class only encodes the regional domain.
    """

    def __init__(self, client_id: str, client_secret: str, *, tenant: str, **kwargs: Any):
        t = tenant.strip().removesuffix(".eu.auth0.com")
        host = f"{t}.eu.auth0.com"
        base = f"https://{host}"
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/authorize",
            token_url=f"{base}/oauth/token",
            userinfo_url=f"{base}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "auth0_europe"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AUTH0_EUROPE

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/.well-known/jwks.json"


# --- OIDC with published UK / FR public sector endpoints --------------------------------


class NhsLoginProvider(ABaseProvider):
    """NHS Login — OIDC for health and care (England); see NHS Digital integration guides."""

    _ISSUER = "https://auth.nhs.uk"

    def __init__(self, client_id: str, client_secret: str, **kwargs: Any):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{self._ISSUER}/authorize",
            token_url=f"{self._ISSUER}/token",
            userinfo_url=f"{self._ISSUER}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "nhs_login"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.NHS_LOGIN

    @property
    def oidc_issuer(self) -> str | None:
        return self._ISSUER

    @property
    def oidc_jwks_uri(self) -> str | None:
        # Prefer OIDC discovery (jwks_uri) in production; this follows common /.well-known layout.
        return f"{self._ISSUER}/.well-known/jwks.json"


class GovUkOneLoginProvider(ABaseProvider):
    """GOV.UK One Login (OIDC) — central government digital identity for the UK."""

    _ISSUER = "https://oidc.account.gov.uk"

    def __init__(self, client_id: str, client_secret: str, **kwargs: Any):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{self._ISSUER}/authorize",
            token_url=f"{self._ISSUER}/token",
            userinfo_url=f"{self._ISSUER}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "govuk_one_login"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GOVUK_ONE_LOGIN

    @property
    def oidc_issuer(self) -> str | None:
        return self._ISSUER

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._ISSUER}/.well-known/jwks.json"


class FranceConnectProvider(ABaseProvider):
    """
    FranceConnect OAuth2/OIDC — default **API v2** (``oidc.franceconnect.gouv.fr``).
    Legacy **v1** hosts remain configurable for transitional integrations.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        environment: Literal["integration", "production"] = "production",
        api_version: Literal["v2", "v1"] = "v2",
        **kwargs: Any,
    ):
        if api_version == "v2":
            if environment == "integration":
                base = "https://fcp-low.integ01.dev-franceconnect.fr/api/v2"
            else:
                base = "https://oidc.franceconnect.gouv.fr/api/v2"
        else:
            if environment == "integration":
                base = "https://fcp.integ01.dev-franceconnect.fr/api/v1"
            else:
                base = "https://app.franceconnect.gouv.fr/api/v1"
        self._issuer = base
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=f"{base}/authorize",
            token_url=f"{base}/token",
            userinfo_url=f"{base}/userinfo",
            **kwargs,
        )

    @property
    def provider_name(self) -> str:
        return "france_connect"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FRANCE_CONNECT

    @property
    def oidc_issuer(self) -> str | None:
        return self._issuer

    @property
    def oidc_jwks_uri(self) -> str | None:
        return f"{self._issuer}/jwks"
