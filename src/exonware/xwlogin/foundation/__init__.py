# exonware/xwlogin/src/exonware/xwlogin/foundation/__init__.py
"""
Login-layer foundation types with **no** dependency on ``exonware.xwauth`` (REF_41 §7).

New symbols should stay import-light (stdlib + ``exonware-xwsystem`` only) until the
packaging flip completes. Protocols live in ``foundation.contracts``; enums in ``foundation.defs``.
"""

from __future__ import annotations

from .contracts import IAuthenticator
from .defs import MFAMethod, UserStatus

__all__ = ["IAuthenticator", "MFAMethod", "UserStatus"]
