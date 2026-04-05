# exonware/xwlogin/ops_connector.py
"""Critical-path handler tracing hooks from the connector (``xwauth.ops_hooks``).

Package-level façade for observability hooks used by login routes; ``handlers.connector_transport``
re-exports this alongside ``oauth_errors_connector`` (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwauth.ops_hooks import track_critical_handler

__all__ = ["track_critical_handler"]
