"""Connector façade for login-provider HTTP handlers.

Centralizes imports: **xwlogin.api_connector**, **xwlogin.auth_connector**, **xwlogin.security**,
**xwlogin.handlers.connector_common** (tags + HTTP getters from ``xwauth.handlers._common``),
**xwlogin.handlers.connector_transport** (OAuth→HTTP + ops hooks via **oauth_errors_connector** / **ops_connector**),
**xwlogin.form_post_connector** (OIDC ``form_post`` HTML),
**xwlogin.handlers.connector_auth_factories** (first-party authenticator factories).
"""

from __future__ import annotations

from exonware.xwlogin.api_connector import API_VERSION, AUTH_PREFIX
from exonware.xwlogin.auth_connector import (
    UserLifecycle,
    XWAuthError,
    XWInvalidRequestError,
    XWUserAlreadyExistsError,
)
from exonware.xwlogin.handlers.connector_auth_factories import (
    get_email_password_authenticator,
    get_magic_link_authenticator,
    get_phone_otp_authenticator,
)
from exonware.xwlogin.handlers.connector_common import (
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
from exonware.xwlogin.handlers.connector_transport import (
    oauth_error_to_http,
    track_critical_handler,
)
from exonware.xwlogin.form_post_connector import render_oidc_form_post_html
from exonware.xwlogin.security.backup_codes import (
    generate_backup_codes,
    hash_backup_code,
    verify_backup_code,
)
from exonware.xwlogin.security.mfa_policy import (
    attestation_for_profile,
    merge_amr_claims,
    require_backup_codes,
)
from exonware.xwlogin.security.mfa_secrets import decrypt_totp_secret, encrypt_totp_secret

__all__ = [
    "API_VERSION",
    "AUTH_PREFIX",
    "AUTH_TAGS",
    "MFA_TAGS",
    "PROVIDERS_TAGS",
    "SSO_TAGS",
    "USER_TAGS",
    "UserLifecycle",
    "attestation_for_profile",
    "XWAuthError",
    "XWInvalidRequestError",
    "XWUserAlreadyExistsError",
    "decrypt_totp_secret",
    "encrypt_totp_secret",
    "generate_backup_codes",
    "get_auth",
    "get_bearer_token",
    "get_current_user_id",
    "get_email_password_authenticator",
    "get_magic_link_authenticator",
    "get_phone_otp_authenticator",
    "get_saml_manager",
    "get_user_lifecycle",
    "hash_backup_code",
    "merge_token_endpoint_client_auth",
    "merge_amr_claims",
    "oauth_error_to_http",
    "render_oidc_form_post_html",
    "require_backup_codes",
    "require_client_auth",
    "track_critical_handler",
    "verify_backup_code",
]
