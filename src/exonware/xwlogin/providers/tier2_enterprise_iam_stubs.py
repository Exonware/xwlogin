#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/tier2_enterprise_iam_stubs.py
Enterprise IAM products that are typically SAML-first, highly deployment-specific,
MFA brokers, identity governance, or legacy web access stacks — not a single fixed OIDC URL.

Prefer :class:`SAMLProvider`, vendor SDKs, or discovery documents for these integrations.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.2
Generation Date: 08-Apr-2026
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType, XWProviderError
from typing import Any, Optional
class _EnterpriseIamStub(ABaseProvider):
    _hint: str = "Configure SAML/OIDC metadata per tenant or use the vendor's SDK."

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
            error_code="enterprise_iam_stub",
            suggestions=["Use federation metadata URL or SAMLProvider for this product"],
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
            error_code="enterprise_iam_stub",
        )

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        raise XWProviderError(
            f"{self.provider_name}: {self._hint}",
            error_code="enterprise_iam_stub",
        )


class CyberArkIdaptiveStub(_EnterpriseIamStub):
    """CyberArk Identity (Idaptive) — tenant-specific OAuth paths and company segments."""

    _hint = "Use your Idaptive / CyberArk Identity tenant metadata; paths often include tenant and company segments."

    @property
    def provider_name(self) -> str:
        return "cyberark_idaptive"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.CYBERARK_IDAPTIVE


class IbmSecurityVerifyStub(_EnterpriseIamStub):
    """IBM Security Verify — SaaS hostname and realm vary per subscription."""

    @property
    def provider_name(self) -> str:
        return "ibm_security_verify"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.IBM_SECURITY_VERIFY


class SailPointIdentityGovernanceStub(_EnterpriseIamStub):
    """SailPoint — identity governance; SSO is not a single hosted OAuth authorize URL here."""

    _hint = "Use SailPoint APIs and link workforce SSO via your IdP (OIDC/SAML) separately."

    @property
    def provider_name(self) -> str:
        return "sailpoint"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SAILPOINT


class DuoSecurityStub(_EnterpriseIamStub):
    """Duo (Cisco) — MFA and policy; workforce login is usually via upstream IdP plus Duo step-up."""

    _hint = "Integrate Duo for MFA alongside your OIDC/SAML IdP; not a drop-in replace for IdP authorize URLs."

    @property
    def provider_name(self) -> str:
        return "duo_security"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.DUO_SECURITY


class RsaSecurIdAccessStub(_EnterpriseIamStub):
    """RSA SecurID / ID Plus — deployment-specific OAuth/OIDC endpoints."""

    @property
    def provider_name(self) -> str:
        return "rsa_securid_access"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.RSA_SECURID_ACCESS


class SecureAuthStub(_EnterpriseIamStub):
    """SecureAuth — adaptive authentication; realm-specific endpoints."""

    @property
    def provider_name(self) -> str:
        return "secureauth"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SECUREAUTH


class ShibbolethStub(_EnterpriseIamStub):
    """Shibboleth — SAML SP/IdP software; no fixed third-party OAuth host."""

    _hint = "Use SAML metadata from your academic or research IdP deployment."

    @property
    def provider_name(self) -> str:
        return "shibboleth"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SHIBBOLETH


class SimpleSamlPhpStub(_EnterpriseIamStub):
    """SimpleSAMLphp — self-hosted SAML/OIDC; endpoints are deployment-defined."""

    @property
    def provider_name(self) -> str:
        return "simple_saml_php"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SIMPLE_SAML_PHP


class GoogleWorkspaceSamlStub(_EnterpriseIamStub):
    """Google Workspace SAML apps — distinct from :class:`GoogleWorkspaceProvider` (OAuth/OpenID to Google APIs)."""

    _hint = "For Google Workspace as SAML IdP, use SAMLProvider with your Google IdP metadata."

    @property
    def provider_name(self) -> str:
        return "google_workspace_saml"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GOOGLE_WORKSPACE_SAML


class Connect2idServerStub(_EnterpriseIamStub):
    """Connect2id server — software deployment; OAuth/OIDC base URL is customer-specific."""

    @property
    def provider_name(self) -> str:
        return "connect2id_server"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.CONNECT2ID_SERVER


class VmwareWorkspaceOneStub(_EnterpriseIamStub):
    """VMware Workspace ONE / Access — tenant host and organization vary."""

    @property
    def provider_name(self) -> str:
        return "vmware_workspace_one"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.VMWARE_WORKSPACE_ONE


class CitrixCloudStub(_EnterpriseIamStub):
    """Citrix Cloud — organization-specific IdP and workspace auth."""

    @property
    def provider_name(self) -> str:
        return "citrix_cloud"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.CITRIX_CLOUD


class NetIqStub(_EnterpriseIamStub):
    """NetIQ (Micro Focus) Access Manager — on-prem endpoints per deployment."""

    @property
    def provider_name(self) -> str:
        return "netiq"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.NETIQ


class IbmTivoliAccessManagerStub(_EnterpriseIamStub):
    """IBM Tivoli Access Manager / legacy IBM SSO stacks — on-prem configuration."""

    @property
    def provider_name(self) -> str:
        return "ibm_tivoli_access"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.IBM_TIVOLI_ACCESS


class CaSiteMinderStub(_EnterpriseIamStub):
    """CA SiteMinder (Broadcom) — policy server URLs are enterprise-specific."""

    @property
    def provider_name(self) -> str:
        return "ca_siteminder"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.CA_SITEMINDER


class WorkOSStub(_EnterpriseIamStub):
    """WorkOS — organization SSO and directory sync; connection endpoints are per-environment."""

    _hint = "Use WorkOS SSO or Admin APIs; each connection uses its own IdP metadata."

    @property
    def provider_name(self) -> str:
        return "workos"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.WORKOS


class FronteggStub(_EnterpriseIamStub):
    """Frontegg B2B — tenant-aware auth; prefer vendor-hosted OIDC metadata for your environment."""

    @property
    def provider_name(self) -> str:
        return "frontegg"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.FRONTEGG


class SuperTokensStub(_EnterpriseIamStub):
    """SuperTokens — self-hosted/customer URLs; not a single global OAuth authorize endpoint."""

    @property
    def provider_name(self) -> str:
        return "super_tokens"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.SUPER_TOKENS
