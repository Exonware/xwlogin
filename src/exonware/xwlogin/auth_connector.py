"""Connector primitives for first-party authenticators (base types, contracts, users, tokens).

Implementation remains in **xwauth**. ``exonware.xwlogin.authentication`` should import from here
instead of scattered ``exonware.xwauth.*`` modules so the connector boundary stays visible.
``exonware.xwlogin.handlers.connector_http`` also imports shared types from here (``UserLifecycle``,
common ``XWAuth*`` errors) so login HTTP mixins do not reach into ``xwauth.errors`` / ``users`` directly.
"""

from __future__ import annotations

from exonware.xwauth.base import ABaseAuth, ABaseAuthenticator
from exonware.xwauth.contracts import IAuthenticator
from exonware.xwauth.defs import UserStatus
from exonware.xwauth.errors import (
    XWAuthenticationError,
    XWAuthError,
    XWInvalidCredentialsError,
    XWInvalidRequestError,
    XWUserAlreadyExistsError,
    XWUserError,
)
from exonware.xwauth.storage.interface import IStorageProvider
from exonware.xwauth.tokens.manager import TokenManager
from exonware.xwauth.users.lifecycle import UserLifecycle
from exonware.xwauth.users.user import User

__all__ = [
    "ABaseAuth",
    "ABaseAuthenticator",
    "IAuthenticator",
    "IStorageProvider",
    "TokenManager",
    "User",
    "UserLifecycle",
    "UserStatus",
    "XWAuthenticationError",
    "XWAuthError",
    "XWInvalidCredentialsError",
    "XWInvalidRequestError",
    "XWUserAlreadyExistsError",
    "XWUserError",
]
