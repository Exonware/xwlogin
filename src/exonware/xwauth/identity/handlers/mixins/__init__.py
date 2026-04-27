# exonware/xwauth-identity/src/exonware/xwauth/identity/handlers/mixins/__init__.py

"""Service-grouped mixins for xwauth API.



Submodules load on first attribute access (PEP 562) so ``import …handlers.mixins`` does not

eagerly import every mixin (connector cold start + optional login shims).

"""



from __future__ import annotations



import importlib

from typing import Any



__all__ = [

    "auth_core",

    "oauth2_extended",

    "client_registration",

    "user",

    "password",

    "otp",

    "magic_link",

    "mfa",

    "passkeys",

    "sessions",

    "organizations",

    "sso_providers",

    "saml",

    "fga",

    "webhooks",

    "admin",

    "system",

    "oauth1",

    "scim",

]





def __getattr__(name: str) -> Any:

    if name in __all__:

        mod = importlib.import_module(f"{__name__}.{name}")

        globals()[name] = mod

        return mod

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")





def __dir__() -> list[str]:

    return sorted({k for k in globals() if not k.startswith("_")} | set(__all__))

