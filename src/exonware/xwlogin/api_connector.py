"""Versioned HTTP path constants from the connector (`exonware.xwauth.api_paths`).

Login routes, **xwauth-api**, and OpenAPI wiring should import prefixes here instead of
``exonware.xwauth.api_paths`` directly, so the AS surface stays a single documented boundary
alongside ``auth_connector`` / ``provider_connector``.
"""

from __future__ import annotations

from exonware.xwauth.api_paths import (
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

__all__ = [
    "API_VERSION",
    "OAUTH2_PREFIX",
    "OIDC_PREFIX",
    "OAUTH1_PREFIX",
    "AUTH_PREFIX",
    "USERS_PREFIX",
    "ADMIN_PREFIX",
    "ORGANIZATIONS_PREFIX",
    "WEBHOOKS_PREFIX",
    "SCIM_PREFIX",
    "SYSTEM_PREFIX",
    "PATH_HEALTH",
    "PATH_METRICS",
]
