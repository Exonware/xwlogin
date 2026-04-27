# exonware/xwauth/handlers/_common.py
"""
Shared helpers, tags, and security for xwauth HTTP handler mixins (connector + default API).

Shared HTTP handler helpers for the authorization-server surface in ``exonware-xwauth``.

First-party authenticator factories are loaded **only if** a compatible login connector package
is present on ``PYTHONPATH`` (optional runtime). ``exonware-xwauth`` does **not** declare that
package as a pip dependency; integrate login/IdP behavior primarily via OAuth 2.0 / OIDC HTTP APIs.
"""

from __future__ import annotations
import base64
import secrets
from typing import Any
from fastapi import Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwauth.identity.api_paths import (
    ADMIN_PREFIX,
    API_VERSION,
    AUTH_PREFIX,
    OAUTH1_PREFIX,
    OAUTH2_PREFIX,
    OIDC_PREFIX,
    ORGANIZATIONS_PREFIX,
    PATH_HEALTH,
    PATH_METRICS,
    SCIM_PREFIX,
    SYSTEM_PREFIX,
    USERS_PREFIX,
    WEBHOOKS_PREFIX,
)

_LOGIN_FACTORY_ERR = (
    "First-party authenticator factories are unavailable: the canonical "
    "``exonware.xwauth.identity.handlers.authenticators`` module could not be "
    "imported. Use OAuth 2.0 / OIDC HTTP integration with your login/IdP "
    "deployment, or reinstall exonware-xwauth-identity."
)


def _load_login_auth_factories() -> Any:
    """Return the canonical authenticator-factory module owned by identity.

    Identity is fully independent and ships its own first-party authenticators
    (email/password, magic link, phone OTP) in
    ``exonware.xwauth.identity.handlers.authenticators``. There is **no**
    compat shim and no optional xwlogin connector — per the repo-wide zero-
    shims rule; callers that want legacy xwlogin factories should install
    xwlogin and invoke its factories directly.
    """
    try:
        from exonware.xwauth.identity.handlers import authenticators as _m

        return _m
    except ImportError as e:  # pragma: no cover - packaging regression only
        raise ImportError(_LOGIN_FACTORY_ERR) from e


def get_email_password_authenticator(auth: Any) -> Any:
    return _load_login_auth_factories().get_email_password_authenticator(auth)


def get_magic_link_authenticator(auth: Any) -> Any:
    return _load_login_auth_factories().get_magic_link_authenticator(auth)


def get_phone_otp_authenticator(auth: Any) -> Any:
    return _load_login_auth_factories().get_phone_otp_authenticator(auth)

AUTH_TAGS = ["Auth"]
USER_TAGS = ["Users"]
MFA_TAGS = ["MFA"]
ADMIN_TAGS = ["Admin"]
SYSTEM_TAGS = ["System"]
ORG_TAGS = ["Organizations"]
SSO_TAGS = ["SSO"]
PROVIDERS_TAGS = ["Providers"]
AUTHZ_TAGS = ["Authorization"]
WEBHOOK_TAGS = ["Webhooks"]
SCIM_TAGS = ["SCIM"]
_security = HTTPBearer(auto_error=False)

# Documented optional cookie for ``GET …/auth/sessions/view`` only (same-origin HTML).
# Integrators set this from a BFF after token issuance; use HttpOnly + Secure + SameSite
# in production-shaped deployments. JSON session APIs still require ``Authorization: Bearer``.
XWAUTH_REFERENCE_ACCESS_TOKEN_COOKIE = "xwauth_reference_access_token"

def get_auth(request: Request):
    """Get XWAuth instance from app state."""
    return request.app.state.xwauth

def get_user_lifecycle(auth):
    """Get UserLifecycle instance from XWAuth."""
    from exonware.xwauth.identity.users.lifecycle import UserLifecycle
    return UserLifecycle(auth)

def get_organization_lifecycle(auth):
    """Get OrganizationLifecycle instance from XWAuth."""
    from exonware.xwauth.identity.organizations.lifecycle import OrganizationLifecycle
    return OrganizationLifecycle(auth)

def get_organization_manager(auth):
    """Get OrganizationManager instance from XWAuth."""
    from exonware.xwauth.identity.organizations.manager import OrganizationManager
    return OrganizationManager(auth)

def get_saml_manager(auth):
    """Get SAMLManager instance from XWAuth."""
    from exonware.xwauth.identity.core.saml import SAMLManager
    return SAMLManager(auth)

def get_fga_manager(auth):
    """Get FGAManager instance from XWAuth."""
    from exonware.xwauth.identity.authorization.fga import FGAManager
    return FGAManager(auth)

def get_webhook_manager(auth):
    """Get WebhookManager instance from XWAuth."""
    from exonware.xwauth.identity.webhooks.manager import WebhookManager
    return WebhookManager(auth)

def get_scim_user_service(auth):
    """Get SCIM User service from XWAuth."""
    return auth.scim_users

def get_scim_group_service(auth):
    """Get SCIM Group service from XWAuth."""
    return auth.scim_groups

def get_audit_log_manager(auth):
    """Get AuditLogManager instance from XWAuth."""
    from exonware.xwauth.identity.audit.manager import AuditLogManager
    return AuditLogManager(auth)
async def get_current_user_id(request: Request) -> str | None:
    """Extract user ID from Bearer token."""
    uid, _ = await get_bearer_user_and_introspection(request)
    return uid


async def get_current_user_id_for_sessions_reference_html(request: Request) -> str | None:
    """
    User id for the HTML session list only: Bearer first, else optional reference cookie.

    See :data:`XWAUTH_REFERENCE_ACCESS_TOKEN_COOKIE`.
    """
    uid = await get_current_user_id(request)
    if uid:
        return uid
    raw = request.cookies.get(XWAUTH_REFERENCE_ACCESS_TOKEN_COOKIE)
    if not raw or not str(raw).strip():
        return None
    auth = get_auth(request)
    try:
        ir = await auth.introspect_token(str(raw).strip())
        if ir.get("active"):
            sub = ir.get("sub") or ir.get("user_id")
            return str(sub) if sub else None
    except Exception:
        pass
    return None


async def get_bearer_user_and_introspection(request: Request) -> tuple[str | None, dict | None]:
    """
    Single introspection round-trip: active subject id and full RFC 7662-style dict.

    Used by org-scoped routes to enforce token org_id vs path org alignment without a second introspect.
    """
    creds: HTTPAuthorizationCredentials | None = await _security(request)
    if not creds:
        return None, None
    auth = get_auth(request)
    try:
        introspect_result = await auth.introspect_token(creds.credentials)
        if introspect_result.get("active"):
            uid = introspect_result.get("sub") or introspect_result.get("user_id")
            return (str(uid) if uid else None), introspect_result
    except Exception:
        pass
    return None, None


def json_response_for_token_org_path_mismatch() -> dict[str, Any]:
    """OAuth-shaped error body for org-bound token vs URL org mismatch."""
    return {
        "error": "access_denied",
        "error_description": "Token organization context does not match the requested organization resource",
        "error_code": "tenant_context_mismatch",
    }

def get_bearer_token(request: Request) -> str | None:
    """Extract Bearer token from Authorization header."""
    h = request.headers.get("authorization") or ""
    if not h.lower().startswith("bearer "):
        return None
    return h[7:].strip()


def merge_token_endpoint_client_auth(request: Request, req: dict[str, Any]) -> None:
    """
    RFC 6749 §2.3.1 (client_secret_basic): merge HTTP Basic user/password into the token
    request dict when client_id or client_secret are absent from the form body.
    """
    h = request.headers.get("authorization") or ""
    if not h.lower().startswith("basic "):
        return
    try:
        raw = base64.b64decode(h[6:].strip()).decode("utf-8")
        if ":" not in raw:
            return
        basic_id, basic_secret = raw.split(":", 1)
    except Exception:
        return

    def _missing(v: Any) -> bool:
        return v is None or (isinstance(v, str) and not v.strip())

    if _missing(req.get("client_id")):
        req["client_id"] = basic_id
    if _missing(req.get("client_secret")):
        req["client_secret"] = basic_secret


def require_client_auth(
    request: Request,
    form: Any,
    auth: Any,
) -> tuple[dict[str, Any], int] | None:
    """
    Require client authentication (RFC 7662, RFC 7009).
    Supports form client_id+client_secret or Basic Auth.
    Returns None on success; (body, status) on failure.
    """
    client_id: str | None = None
    client_secret: str | None = None
    h = request.headers.get("authorization") or ""
    if h.lower().startswith("basic "):
        try:
            raw = base64.b64decode(h[6:].strip()).decode("utf-8")
            if ":" in raw:
                client_id, client_secret = raw.split(":", 1)
        except Exception:
            pass
    if not client_id:
        client_id = form.get("client_id") if form else None
    if client_secret is None and form:
        client_secret = form.get("client_secret")
    if not client_id:
        return oauth_error_response("invalid_client", "client_id required")
    client = auth.config.get_registered_client(client_id)
    if not client:
        return oauth_error_response("invalid_client", "Client not registered")
    secret = client.get("client_secret") or ""
    # Constant-time compare avoids leaking secret prefix matches in HTTP timing.
    if secret and (
        not client_secret
        or not secrets.compare_digest(str(client_secret), str(secret))
    ):
        return oauth_error_response("invalid_client", "client_secret invalid")
    return None
async def introspect_and_check_admin(request: Request) -> tuple[str | None, dict | None, bool]:
    """
    Introspect Bearer token and check admin scope.
    Returns (user_id, introspect_result, has_admin).
    """
    token = get_bearer_token(request)
    if not token:
        return None, None, False
    auth = get_auth(request)
    try:
        ir = await auth.introspect_token(token)
        if not ir.get("active"):
            return None, ir, False
        user_id = ir.get("sub") or ir.get("user_id")
        scope_str = ir.get("scope") or ""
        scopes = scope_str.split() if isinstance(scope_str, str) else list(scope_str)
        has_admin = "admin" in scopes
        return user_id, ir, has_admin
    except Exception:
        return None, None, False

def security_scheme():
    """Return the HTTPBearer security scheme (for optional use in Depends)."""
    return _security
