#!/usr/bin/env python3
"""
Federation broker exports.
"""

from .types import FederatedIdentity
from exonware.xwauth.identity.federation.errors import FederationUpstreamCode, XWFederationError, federation_exception_to_oauth_response
from .mapping import apply_claim_mapping_v1
from .idp_registry import (
    TenantScopedIdpRegistry,
    TenantIdpRecord,
    IdpHealthSnapshot,
    idp_isolation_namespace,
    idp_record_to_discovery_response,
)
from .pkce import generate_pkce_pair
from .jwks_cache import JwksDocumentCache
from .idp_quirks import (
    GOOGLE_OIDC_ISSUER,
    normalize_oidc_issuer_url,
    okta_authorization_server_base,
    suggested_entra_multitenant_additional_issuers,
)
from .oidc_id_token import (
    OidcIdTokenValidationParams,
    decode_id_token_unverified,
    fetch_jwks,
    fetch_openid_configuration,
    validate_federated_id_token,
)

try:
    from .broker import FederationBroker
except ImportError:
    FederationBroker = None

__all__ = [
    "FederatedIdentity",
    "FederationBroker",
    "FederationUpstreamCode",
    "XWFederationError",
    "federation_exception_to_oauth_response",
    "apply_claim_mapping_v1",
    "TenantScopedIdpRegistry",
    "TenantIdpRecord",
    "IdpHealthSnapshot",
    "idp_isolation_namespace",
    "idp_record_to_discovery_response",
    "generate_pkce_pair",
    "JwksDocumentCache",
    "GOOGLE_OIDC_ISSUER",
    "normalize_oidc_issuer_url",
    "okta_authorization_server_base",
    "suggested_entra_multitenant_additional_issuers",
    "OidcIdTokenValidationParams",
    "decode_id_token_unverified",
    "fetch_jwks",
    "fetch_openid_configuration",
    "validate_federated_id_token",
]

