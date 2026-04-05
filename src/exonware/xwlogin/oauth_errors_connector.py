# exonware/xwlogin/oauth_errors_connector.py
"""Map OAuth/token exceptions to HTTP responses (``xwauth.oauth_http.errors``).

Login HTTP layers should use ``handlers.connector_http`` or ``handlers.connector_transport``; this
module is the **package-level** re-export so dependency on ``oauth_http.errors`` is explicit
(GUIDE_32).
"""

from __future__ import annotations

from exonware.xwauth.oauth_http.errors import oauth_error_to_http

__all__ = ["oauth_error_to_http"]
