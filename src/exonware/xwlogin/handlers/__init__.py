"""First-party HTTP surface: ``mixins`` (xwapi HTTP types + XWAction routes), ``authenticators`` (factories),
``connector_http`` (full façade for route code), ``connector_common`` (re-export of package
``handlers_common_connector`` / ``xwauth.handlers._common``), ``connector_transport`` (OAuth→HTTP + ops hooks via ``oauth_errors_connector`` / ``ops_connector``), and
``oauth_form_post`` (OIDC ``form_post`` HTML implementation; façade ``form_post_connector``), ``connector_auth_factories`` (email/magic-link/OTP
authenticator factories). Prefer ``connector_http`` for imports.

Submodules load on first access (PEP 562) so ``import exonware.xwlogin.handlers`` stays light until
you use ``handlers.mixins``, ``handlers.authenticators``, ``handlers.connector_http``,
``handlers.connector_common``, or ``handlers.connector_transport``. Route mixins need optional extra
``exonware-xwlogin[full]`` (exonware-xwapi + xwaction) at runtime.
``api_services_connector`` bundles login mixins + ``get_provider_callback_routes`` for xwauth-api-style hosts.
``connector_route_mixins`` re-exports **xwauth** OAuth/OIDC/SCIM handler mixins for AS route registration.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "api_services_connector",
    "authenticators",
    "connector_common",
    "connector_http",
    "connector_route_mixins",
    "connector_transport",
    "mixins",
]


def __getattr__(name: str) -> Any:
    if name == "api_services_connector":
        mod = importlib.import_module("exonware.xwlogin.handlers.api_services_connector")
        globals()["api_services_connector"] = mod
        return mod
    if name == "mixins":
        mod = importlib.import_module("exonware.xwlogin.handlers.mixins")
        globals()["mixins"] = mod
        return mod
    if name == "authenticators":
        mod = importlib.import_module("exonware.xwlogin.handlers.authenticators")
        globals()["authenticators"] = mod
        return mod
    if name == "connector_http":
        mod = importlib.import_module("exonware.xwlogin.handlers.connector_http")
        globals()["connector_http"] = mod
        return mod
    if name == "connector_common":
        mod = importlib.import_module("exonware.xwlogin.handlers.connector_common")
        globals()["connector_common"] = mod
        return mod
    if name == "connector_transport":
        mod = importlib.import_module("exonware.xwlogin.handlers.connector_transport")
        globals()["connector_transport"] = mod
        return mod
    if name == "connector_route_mixins":
        mod = importlib.import_module("exonware.xwlogin.handlers.connector_route_mixins")
        globals()["connector_route_mixins"] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({n for n in globals() if not n.startswith("_")} | set(__all__))
