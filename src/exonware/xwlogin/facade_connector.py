"""Authorization server façade and related factory helpers from the connector.

``XWAuth`` is the main AS entrypoint in **xwauth**. Login integration tests and apps that assemble
the full stack should import it here instead of ``from exonware.xwauth import XWAuth`` so façade
access stays a single boundary (with ``config_connector``, ``auth_connector``, ``webauthn_connector``, etc.).
"""

from __future__ import annotations

from exonware.xwauth import XWAuth
from exonware.xwlogin.webauthn_connector import (
    create_webauthn_challenge_store,
    create_webauthn_credential_index_redis,
    rebuild_webauthn_credential_index,
)

__all__ = [
    "XWAuth",
    "create_webauthn_challenge_store",
    "create_webauthn_credential_index_redis",
    "rebuild_webauthn_credential_index",
]
