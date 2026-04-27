# exonware/xwauth/oauth_http/__init__.py
"""OAuth/OIDC HTTP helpers (discovery metadata, error mapping) for transport layers."""

from .resource_owner_session import ensure_resource_owner_session

__all__ = ["ensure_resource_owner_session"]
