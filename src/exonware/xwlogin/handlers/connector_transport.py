"""Connector-side HTTP transport helpers used by login routes.

Maps OAuth/token exceptions to HTTP responses and forwards critical-path tracing to connector ops
hooks. Prefer importing through ``exonware.xwlogin.handlers.connector_http`` from route mixins.
Implementation is delegated to **xwlogin** package façades (``oauth_errors_connector``,
``ops_connector``) — no direct ``exonware.xwauth`` imports here.
"""

from __future__ import annotations

from exonware.xwlogin.oauth_errors_connector import oauth_error_to_http
from exonware.xwlogin.ops_connector import track_critical_handler

__all__ = ["oauth_error_to_http", "track_critical_handler"]
