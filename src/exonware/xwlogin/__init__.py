#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/__init__.py
XWLogin — **login provider** surface: IdP catalog, OAuth RP clients, WebAuthn/MFA,
and first-party authenticators (email/password, magic link, OTP).

Depends on **exonware-xwauth** (the **connector**) for ``ABaseAuth``, storage contracts, and shared
errors/defs. Use ``exonware.xwlogin.provider_connector`` for IdP-facing connector types (``ABaseProvider``,
``ProviderType``, ``ProviderRegistry``, ``XWProvider*``, ``CoreABaseProvider``, ``IProvider``)
without scattering ``exonware.xwauth.*`` across provider modules, ``exonware.xwlogin.auth_connector`` for authenticator base types,
``UserLifecycle``, ``TokenManager``, and related errors, ``exonware.xwlogin.config_connector`` for ``XWAuthConfig`` / ``XWConfigError`` / harness ``DEFAULT_TEST_CLIENTS``, ``exonware.xwlogin.facade_connector`` for ``XWAuth`` and WebAuthn index factories, ``exonware.xwlogin.mock_connector`` for in-memory test doubles, ``exonware.xwlogin.api_connector`` for versioned HTTP path prefixes (same surface as ``xwauth.api_paths``), and ``exonware.xwlogin.discovery_connector`` for RFC 8414 / OIDC ``/.well-known`` metadata builders (implementation in ``xwauth.oauth_http.discovery``), ``tokens_connector`` for OIDC ID-token signing discovery helpers, ``audit_connector`` for request audit correlation, ``storage_connector`` for ``XWStorageProvider``, ``oauth_errors_connector`` for ``oauth_error_to_http``, ``ops_connector`` for ``track_critical_handler``, ``handlers_common_connector`` for ``xwauth.handlers._common`` (tags/getters), and ``form_post_connector`` for OIDC ``form_post`` HTML. Import from
``exonware.xwlogin.providers``, ``exonware.xwlogin.authentication``, ``exonware.xwlogin.clients``,
and (with optional extra ``[full]``) ``exonware.xwlogin.handlers`` — use ``from exonware.xwlogin.handlers import mixins`` (lazy) or ``handlers.mixins`` / ``handlers.authenticators`` for routes and authenticator factories.
``handlers_common_connector`` is the package-level import site for ``xwauth.handlers._common`` (tags/getters); ``handlers.connector_common`` re-exports it. ``handlers.connector_http`` composes path/auth/MFA façades plus ``connector_common`` and ``connector_transport`` and does **not** import ``exonware.xwauth`` directly.
``handlers.api_services_connector`` bundles ``login_route_mixins`` + ``get_provider_callback_routes`` for reference AS apps (e.g. xwauth-api).
``exonware.xwlogin.security`` holds MFA backup-code hashing, TOTP envelope encryption, and MFA/WebAuthn policy helpers (``exonware.xwauth.security.*`` shims delegate here when xwlogin is installed).

``from exonware.xwlogin import provider_connector`` / ``auth_connector`` / ``config_connector`` / ``facade_connector`` / ``api_connector`` / ``api_services_connector`` / ``handlers_common_connector`` / ``form_post_connector`` / ``audit_connector`` / ``tokens_connector`` / ``storage_connector`` / ``oauth_errors_connector`` / ``ops_connector`` / ``security`` / ``webauthn_connector`` is supported
(PEP 562): those names load on first access, not on ``import exonware.xwlogin``. ``mock_connector`` is available as a submodule (not re-exported on the root) for test doubles. Unit tests may import
``exonware.xwlogin.test_support`` for a single test barrel (config/facade/mock + ``oauth_error_to_http``, ``track_critical_handler``, ``get_auth``, ``render_oidc_form_post_html``).

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
"""

from __future__ import annotations

import importlib
from typing import Any

from .version import __author__, __email__, __version__

__all__ = [
    "__author__",
    "__email__",
    "__version__",
    "api_connector",
    "api_services_connector",
    "audit_connector",
    "auth_connector",
    "config_connector",
    "discovery_connector",
    "facade_connector",
    "form_post_connector",
    "handlers_common_connector",
    "oauth_errors_connector",
    "ops_connector",
    "provider_connector",
    "security",
    "storage_connector",
    "tokens_connector",
    "webauthn_connector",
]


def __getattr__(name: str) -> Any:
    if name == "provider_connector":
        mod = importlib.import_module("exonware.xwlogin.provider_connector")
        globals()["provider_connector"] = mod
        return mod
    if name == "auth_connector":
        mod = importlib.import_module("exonware.xwlogin.auth_connector")
        globals()["auth_connector"] = mod
        return mod
    if name == "api_connector":
        mod = importlib.import_module("exonware.xwlogin.api_connector")
        globals()["api_connector"] = mod
        return mod
    if name == "api_services_connector":
        mod = importlib.import_module("exonware.xwlogin.handlers.api_services_connector")
        globals()["api_services_connector"] = mod
        return mod
    if name == "config_connector":
        mod = importlib.import_module("exonware.xwlogin.config_connector")
        globals()["config_connector"] = mod
        return mod
    if name == "discovery_connector":
        mod = importlib.import_module("exonware.xwlogin.discovery_connector")
        globals()["discovery_connector"] = mod
        return mod
    if name == "facade_connector":
        mod = importlib.import_module("exonware.xwlogin.facade_connector")
        globals()["facade_connector"] = mod
        return mod
    if name == "handlers_common_connector":
        mod = importlib.import_module("exonware.xwlogin.handlers_common_connector")
        globals()["handlers_common_connector"] = mod
        return mod
    if name == "form_post_connector":
        mod = importlib.import_module("exonware.xwlogin.form_post_connector")
        globals()["form_post_connector"] = mod
        return mod
    if name == "security":
        mod = importlib.import_module("exonware.xwlogin.security")
        globals()["security"] = mod
        return mod
    if name == "webauthn_connector":
        mod = importlib.import_module("exonware.xwlogin.webauthn_connector")
        globals()["webauthn_connector"] = mod
        return mod
    if name == "audit_connector":
        mod = importlib.import_module("exonware.xwlogin.audit_connector")
        globals()["audit_connector"] = mod
        return mod
    if name == "tokens_connector":
        mod = importlib.import_module("exonware.xwlogin.tokens_connector")
        globals()["tokens_connector"] = mod
        return mod
    if name == "storage_connector":
        mod = importlib.import_module("exonware.xwlogin.storage_connector")
        globals()["storage_connector"] = mod
        return mod
    if name == "oauth_errors_connector":
        mod = importlib.import_module("exonware.xwlogin.oauth_errors_connector")
        globals()["oauth_errors_connector"] = mod
        return mod
    if name == "ops_connector":
        mod = importlib.import_module("exonware.xwlogin.ops_connector")
        globals()["ops_connector"] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({n for n in globals() if not n.startswith("_")} | set(__all__))
