"""Login-focused FastAPI route mixins (password, OTP, passkeys, SAML, SSO callbacks, etc.).

Submodules load on first attribute access (PEP 562) so ``import …handlers.mixins`` stays cheap until
a concrete route module is needed.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "magic_link",
    "mfa",
    "otp",
    "passkeys",
    "password",
    "saml",
    "sso_providers",
    "user",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        mod = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({k for k in globals() if not k.startswith("_")} | set(__all__))
