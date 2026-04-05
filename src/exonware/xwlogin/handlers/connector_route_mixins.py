# exonware/xwlogin/handlers/connector_route_mixins.py
"""OAuth/OIDC/SCIM **connector** route mixins (``exonware.xwauth.handlers.mixins``).

Reference AS apps (e.g. xwauth-api) should import ``connector_route_mixins`` from this module
instead of ``xwauth.handlers.mixins`` so route registration stays behind the **xwlogin** boundary
alongside ``api_services_connector`` (GUIDE_32).
"""

from __future__ import annotations

from exonware.xwauth.handlers import mixins as connector_route_mixins

__all__ = ["connector_route_mixins"]
