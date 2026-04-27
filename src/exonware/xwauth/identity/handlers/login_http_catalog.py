# exonware/xwauth/identity/src/exonware/xwauth/identity/handlers/login_http_catalog.py
"""Stable catalog of first-party **login** HTTP capabilities (GUIDE_32 façade boundary).

This tree is the standalone login product; ``exonware.xwauth`` is the connector to external
authorization systems. Concrete paths are registered by the host (e.g. ``exonware.xwauth_api``)
from ``handlers.mixins``; this module only describes what this package *can* expose so OpenAPI and
product docs stay honest.
"""

from __future__ import annotations

from typing import Any

_MIXIN_MODULES = (
    "magic_link",
    "mfa",
    "otp",
    "passkeys",
    "password",
    "saml",
    "sso_providers",
    "user",
)


def get_login_http_route_catalog() -> dict[str, Any]:
    """Return a versioned map of mixin modules and lifecycle areas hosts typically wire up."""
    return {
        "version": 1,
        "mixin_modules": list(_MIXIN_MODULES),
        "lifecycle_areas": [
            "password",
            "otp",
            "magic_link",
            "mfa",
            "passkeys",
            "saml",
            "sso_oauth_callbacks",
            "user_profile",
        ],
        "notes": (
            "Split: this catalog covers first-party **login** mixins; ``exonware.xwauth`` covers connector "
            "integration with external AS/OIDC/SCIM stacks (see ``exonware.xwauth_api`` ``AUTH_SERVICES``). "
            "Full OAuth2/OIDC AS routes (authorize, token, revoke, introspect, PAR, device flow) are "
            "published by the connector host: versioned under /v1/oauth2 and /v1/oidc; SCIM canonical base "
            "/scim/v2 with legacy /v1/scim/v2 mirrored for IdP compatibility. Root /.well-known/* is issuer "
            "metadata. First-party login supplies ``api_services_connector`` + ``get_provider_callback_routes``; "
            "connector AS mixins live in ``connector_route_mixins``. Capability hints: "
            "``exonware.xwauth.identity_api.facade.describe_bundle()['capabilities']`` on hosts that ship ``exonware-xwauth-identity-api``."
        ),
    }
