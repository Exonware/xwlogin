# exonware/xwauth/api_paths.py
"""
HTTP API path prefix constants (shared by handlers, xwauth-api, discovery).

These are **URL namespaces** for connector-oriented stacks. ``AUTH_PREFIX`` names a route
segment (``/v1/auth/...``); it is only a path prefix, not a claim about which Python package owns
end-user login UX. A composed host may re-export the same constants so connector AS routes and
login-connector routes stay aligned without path drift.
"""

API_VERSION = "v1"
# Protocol sub-namespaces. OAuth 1.0 (RFC 5849) is conventionally just "oauth";
# OAuth 2.0 (RFC 6749) is "oauth2"; OIDC is "oidc".
OAUTH2_PREFIX = f"/{API_VERSION}/oauth2"
OIDC_PREFIX = f"/{API_VERSION}/oidc"
OAUTH1_PREFIX = f"/{API_VERSION}/oauth"
# Temporary back-compat alias for clients still hitting the old /v1/oauth1 path.
OAUTH1_LEGACY_PREFIX = f"/{API_VERSION}/oauth1"
AUTH_PREFIX = f"/{API_VERSION}/auth"
USERS_PREFIX = f"/{API_VERSION}/users"
ADMIN_PREFIX = f"/{API_VERSION}/admin"
ORGANIZATIONS_PREFIX = f"/{API_VERSION}/organizations"
WEBHOOKS_PREFIX = f"/{API_VERSION}/webhooks"
# RFC 7644 SCIM base path: canonical ``/scim/v2`` (issuer-relative, IdP-friendly).
SCIM_PREFIX = "/scim/v2"
# Deprecated: nested under API version; retained so existing IdP base URLs keep working.
SCIM_LEGACY_PREFIX = f"/{API_VERSION}/scim/v2"
SYSTEM_PREFIX = f"/{API_VERSION}/system"
PATH_HEALTH = "/health"
PATH_METRICS = "/metrics"

__all__ = [
    "API_VERSION",
    "OAUTH2_PREFIX",
    "OIDC_PREFIX",
    "OAUTH1_PREFIX",
    "OAUTH1_LEGACY_PREFIX",
    "AUTH_PREFIX",
    "USERS_PREFIX",
    "ADMIN_PREFIX",
    "ORGANIZATIONS_PREFIX",
    "WEBHOOKS_PREFIX",
    "SCIM_PREFIX",
    "SCIM_LEGACY_PREFIX",
    "SYSTEM_PREFIX",
    "PATH_HEALTH",
    "PATH_METRICS",
]
