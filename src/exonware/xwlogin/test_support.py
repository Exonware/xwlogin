"""Connector symbols for **xwlogin tests** (AS facade, config, mocks, HTTP/ops façades).

Re-exports connector façades used together in unit tests so suites avoid scattered
``exonware.xwauth.*`` imports. Production code should use ``auth_connector``,
``provider_connector``, ``config_connector``, ``facade_connector``, and
``handlers.connector_http`` as appropriate instead of this barrel (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwlogin.config_connector import DEFAULT_TEST_CLIENTS, XWAuthConfig, XWConfigError
from exonware.xwlogin.facade_connector import XWAuth, create_webauthn_credential_index_redis
from exonware.xwlogin.form_post_connector import render_oidc_form_post_html
from exonware.xwlogin.handlers_common_connector import get_auth
from exonware.xwlogin.mock_connector import MockStorageProvider, MockUser
from exonware.xwlogin.oauth_errors_connector import oauth_error_to_http
from exonware.xwlogin.ops_connector import track_critical_handler

__all__ = [
    "DEFAULT_TEST_CLIENTS",
    "MockStorageProvider",
    "MockUser",
    "XWAuth",
    "XWAuthConfig",
    "XWConfigError",
    "create_webauthn_credential_index_redis",
    "get_auth",
    "render_oidc_form_post_html",
    "oauth_error_to_http",
    "track_critical_handler",
]
