"""Re-export of :mod:`exonware.xwlogin.handlers_common_connector` (stable ``handlers`` path)."""

from __future__ import annotations

from exonware.xwlogin.handlers_common_connector import (
    AUTH_TAGS,
    MFA_TAGS,
    PROVIDERS_TAGS,
    SSO_TAGS,
    USER_TAGS,
    get_auth,
    get_bearer_token,
    get_current_user_id,
    get_saml_manager,
    get_user_lifecycle,
    merge_token_endpoint_client_auth,
    require_client_auth,
)

__all__ = [
    "AUTH_TAGS",
    "MFA_TAGS",
    "PROVIDERS_TAGS",
    "SSO_TAGS",
    "USER_TAGS",
    "get_auth",
    "get_bearer_token",
    "get_current_user_id",
    "get_saml_manager",
    "get_user_lifecycle",
    "merge_token_endpoint_client_auth",
    "require_client_auth",
]
