# exonware/xwlogin/handlers/api_services_connector.py
"""Single import surface for reference AS hosts (e.g. xwauth-api) wiring login-provider routes.

Use this instead of importing ``handlers.mixins`` and ``handlers.mixins.sso_providers`` separately
(GUIDE_32 façade boundary).
"""

from __future__ import annotations

from exonware.xwlogin.handlers import mixins as login_route_mixins
from exonware.xwlogin.handlers.mixins.sso_providers import get_provider_callback_routes

__all__ = [
    "get_provider_callback_routes",
    "login_route_mixins",
]
