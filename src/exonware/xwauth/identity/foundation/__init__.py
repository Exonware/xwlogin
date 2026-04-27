# exonware/xwauth.identity/src/exonware/xwauth.identity/foundation/__init__.py
"""
Login-layer foundation types with **no** dependency on ``exonware.xwauth.connect`` (REF_41 §7).

New symbols should stay import-light (stdlib + ``exonware-xwsystem`` only) until the
packaging flip completes. Protocols live in ``foundation.contracts``; enums in ``foundation.defs``.
"""

from __future__ import annotations

from exonware.xwauth.identity.contracts import IAuthenticator
from exonware.xwauth.identity.defs import MFAMethod, UserStatus

__all__ = ["IAuthenticator", "MFAMethod", "UserStatus"]
