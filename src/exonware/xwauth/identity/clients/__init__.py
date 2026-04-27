# exonware/xwauth-identity/src/exonware/xwauth/identity/clients/__init__.py
"""OAuth 2.0 / OIDC **client** helpers (RP, agents, multi-entity configs).

Implemented in this distribution; they talk to **any** standards-compliant authorization
server over HTTP and do not require ``exonware-xwauth-connect``.
"""

from __future__ import annotations

from .async_client import AsyncOAuth2Session
from .entity_session_manager import EntitySessionManager
from .oauth_client import OAuth2ClientManager
from .oauth2_client import OAuth2Session

__all__ = [
    "AsyncOAuth2Session",
    "EntitySessionManager",
    "OAuth2ClientManager",
    "OAuth2Session",
]
