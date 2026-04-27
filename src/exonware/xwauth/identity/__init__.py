#!/usr/bin/env python3
"""
``exonware.xwauth.identity`` — standalone first-party identity provider.

**Role.** Complete login + authorization surface: OAuth 2.0 / OIDC AS
(authorize, token, introspect, revoke, JWKS, discovery, device flow, PAR,
back-channel logout, RP-initiated logout), first-party ceremonies
(password, OTP, magic link, MFA, passkeys, SAML SP), SCIM 2.0,
organizations, webhooks, FGA, audit, sessions, user management.

**Independence rule.** ``exonware.xwauth.identity`` **never imports**
``exonware.xwauth.connect`` (and vice versa). The sibling ``xwauth-connect``
distribution is the multi-provider connector/broker for *external* auth
systems (Google, Apple, Microsoft, SAML IdPs, Keycloak, Auth0, …).

Both distributions share the ``exonware.xwauth`` namespace via
:mod:`pkgutil`-extend namespace packages (see ``exonware/__init__.py`` and
``exonware/xwauth/__init__.py``) and can coexist in one process.

**Mutual discovery.** Hosts that compose both sides (e.g. ``xwbase-api``)
use :func:`discover_connect_package` / :func:`connect_is_available` below
to detect whether the connect distribution is installed — *without*
importing it at module load. The helpers return ``None`` / ``False`` when
connect is absent; callers fall back to HTTP-upstream mode or connect-less
operation.

**Canonical import paths** (no re-export barrels):

- types & errors: ``exonware.xwauth.identity.{base,contracts,defs,errors}``
- config: ``exonware.xwauth.identity.config.config``
- storage: ``exonware.xwauth.identity.storage.{interface,mock,xwstorage_provider}``
- users / tokens / sessions / audit: ``exonware.xwauth.identity.{users,tokens,sessions,audit}``
- facade: ``exonware.xwauth.identity.facade`` (``XWAuth``)
- HTTP: ``exonware.xwauth.identity.handlers.{_common,connector_http,oauth_form_post,mixins}``
- WebAuthn factories: ``exonware.xwauth.identity.authentication.webauthn_factory``

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
"""

from __future__ import annotations

import importlib
import os
from types import ModuleType
from typing import Any

from .version import __author__, __email__, __version__

# =============================================================================
# XWLAZY — optional lazy-install hook (parity with every exonware package).
# =============================================================================
if os.environ.get("XWSTACK_SKIP_XWLAZY_INIT", "").lower() not in ("1", "true", "yes"):
    try:
        from exonware.xwlazy import config_package_lazy_install_enabled

        config_package_lazy_install_enabled(
            __package__ or "exonware.xwauth.identity",
            enabled=True,
            mode="smart",
        )
    except ImportError:
        # xwlazy not installed — omit [lazy] extra or install exonware-xwlazy.
        pass

# =============================================================================
# Mutual discovery — symmetric with ``exonware.xwauth.connect``.
# Identity never imports connect at module load. Hosts that want to compose
# both sides call :func:`discover_connect_package` to detect presence safely.
# =============================================================================
_DISCOVERY_UNSET: Any = object()
_connect_module_cache: Any = _DISCOVERY_UNSET
_CONNECT_DISABLED_ENV = "XWAUTH_IDENTITY_DISABLE_CONNECT_DISCOVERY"


def discover_connect_package() -> ModuleType | None:
    """Return the ``exonware.xwauth.connect`` module if installed, else ``None``.

    Performs a one-time import attempt and caches the result. Safe when the
    connect distribution is not installed — returns ``None`` instead of
    raising ``ImportError``. Symmetric counterpart of
    :func:`exonware.xwauth.connect.discover_identity_package`. Use in hosts
    that optionally mount connector routes when available.

    A real failure inside the ``exonware.xwauth.connect`` package (e.g. a
    transitive dep missing) is propagated as an ``ImportError`` rather than
    masked as "not installed" — so integrators can distinguish the two.

    Set ``XWAUTH_IDENTITY_DISABLE_CONNECT_DISCOVERY=1`` to force-return
    ``None`` (useful for identity-only test harnesses).
    """
    global _connect_module_cache
    if _connect_module_cache is not _DISCOVERY_UNSET:
        return _connect_module_cache
    if os.environ.get(_CONNECT_DISABLED_ENV, "").lower() in ("1", "true", "yes"):
        _connect_module_cache = None
        return None
    try:
        mod = importlib.import_module("exonware.xwauth.connect")
    except ModuleNotFoundError as exc:
        # Only treat "connect itself is not installed" as None; let
        # transitive-import failures bubble up so real defects aren't hidden.
        if exc.name != "exonware.xwauth.connect":
            raise
        _connect_module_cache = None
        return None
    except ImportError:
        _connect_module_cache = None
        return None
    _connect_module_cache = mod
    return mod


def connect_is_available() -> bool:
    """Return ``True`` if ``exonware.xwauth.connect`` can be imported."""
    return discover_connect_package() is not None


def _reset_discovery_cache_for_tests() -> None:
    """Clear the discovery cache. Intended for unit tests only."""
    global _connect_module_cache
    _connect_module_cache = _DISCOVERY_UNSET


__all__ = [
    "__author__",
    "__email__",
    "__version__",
    # Mutual discovery
    "discover_connect_package",
    "connect_is_available",
]


def __getattr__(name: str) -> Any:
    # Intentionally minimal. Identity's public surface is its subpackages
    # (``facade``, ``config.config``, ``users``, ``tokens``, ``sessions``,
    # ``storage``, ``handlers``, ``authentication``, ``oauth_http``, …).
    # Import them directly by their canonical paths.
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({n for n in globals() if not n.startswith("_")} | set(__all__))
