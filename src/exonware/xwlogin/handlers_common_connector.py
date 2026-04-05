# exonware/xwlogin/handlers_common_connector.py
"""FastAPI/OpenAPI glue from the connector (`xwauth.handlers._common`).

Package-level façade: OpenAPI tag lists and request-scoped getters live in **xwauth** so connector
and login mixins stay aligned. ``handlers.connector_common`` re-exports this module for the
historical import path (GUIDE_32).

Route code should still prefer ``exonware.xwlogin.handlers.connector_http``, which includes these
symbols alongside auth, security, and transport façades.
"""

from __future__ import annotations

from exonware.xwauth.handlers._common import (
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
