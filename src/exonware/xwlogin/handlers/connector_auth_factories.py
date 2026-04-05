# exonware/xwlogin/handlers/connector_auth_factories.py
"""First-party authenticator factories — stable import path for the connector layer.

``exonware.xwauth.handlers._common`` must not import ``handlers.authenticators`` directly; it
delegates here. Login route code should prefer ``exonware.xwlogin.handlers.connector_http``,
which re-exports the same callables.
"""

from __future__ import annotations

from exonware.xwlogin.handlers.authenticators import (
    get_email_password_authenticator,
    get_magic_link_authenticator,
    get_phone_otp_authenticator,
)

__all__ = [
    "get_email_password_authenticator",
    "get_magic_link_authenticator",
    "get_phone_otp_authenticator",
]
