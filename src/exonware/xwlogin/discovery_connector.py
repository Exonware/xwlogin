# exonware/xwlogin/discovery_connector.py
"""OAuth 2.0 / OIDC discovery metadata builders (connector logic in ``xwauth.oauth_http.discovery``).

Reference AS hosts (e.g. xwauth-api) should import from this module so discovery wiring stays on the
**xwlogin** façade surface alongside ``api_connector`` and ``handlers.connector_http`` (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwauth.oauth_http.discovery import (
    oauth_authorization_server_metadata,
    oauth_protected_resource_metadata,
    openid_configuration,
)

__all__ = [
    "oauth_authorization_server_metadata",
    "oauth_protected_resource_metadata",
    "openid_configuration",
]
