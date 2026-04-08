"""Connector primitives for first-party authenticators (base types, contracts, users, tokens).

**Target (REF_41):** foundation types belong in **xwlogin**; **xwauth** will depend on **xwlogin** once moved. Until then, this module re-exports **xwauth** to avoid a pip dependency cycle.

Implementation remains in **xwauth**. ``exonware.xwlogin.authentication`` should import from here
instead of scattered ``exonware.xwauth.*`` modules so the connector boundary stays visible.
``exonware.xwlogin.handlers.connector_http`` also imports shared types from here (``UserLifecycle``,
common ``XWAuth*`` errors) so login HTTP mixins do not reach into ``xwauth.errors`` / ``users`` directly.
"""

from __future__ import annotations

from exonware.xwlogin.foundation.contracts import IAuthenticator
from exonware.xwlogin.foundation.defs import UserStatus
from exonware.xwauth.base import ABaseAuth, ABaseAuthenticator
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
