"""Connector primitives for the login-provider layer (OAuth IdP base, registry, enums, errors).

**Target (REF_41):** provider bases/registry move into **xwlogin**; **xwauth** will import them. Until migration completes, definitions remain under **xwauth** and are re-exported here.

Implementation stays in **xwauth**. IdP modules and ``callback_providers`` should import from here
instead of ``exonware.xwauth.defs`` / ``providers.base`` / ``errors`` directly. Registry lookup errors use
``XWProviderNotFoundError`` / ``XWProviderConfigurationError`` from this module.

- ``ABaseProvider``: OAuth-oriented base from ``xwauth.providers.base``.
- ``CoreABaseProvider``: abstract provider base from ``xwauth.base`` (e.g. LDAP-style providers).
"""

from __future__ import annotations

from exonware.xwauth.base import ABaseProvider as CoreABaseProvider
from exonware.xwauth.contracts import IProvider
from exonware.xwauth.defs import ProviderType
from exonware.xwauth.errors import (
    XWProviderConfigurationError,
    XWProviderConnectionError,
    XWProviderError,
    XWProviderNotFoundError,
)
from exonware.xwauth.providers.base import ABaseProvider
from exonware.xwauth.providers.registry import ProviderRegistry

__all__ = [
    "ABaseProvider",
    "CoreABaseProvider",
    "IProvider",
    "ProviderRegistry",
    "ProviderType",
    "XWProviderConfigurationError",
    "XWProviderConnectionError",
    "XWProviderError",
    "XWProviderNotFoundError",
]
