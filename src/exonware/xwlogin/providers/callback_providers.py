# exonware/xwlogin/providers/callback_providers.py
"""
Dynamic OAuth2 callback provider registry.
Provider names are discovered from the providers package: any module that defines
an ABaseProvider subclass gets GET /v1/auth/{name}/callback. The **provider name**
used for the route is each provider's actual `provider_name` (from the provider
instance), so it matches registry lookup. config.providers can extend the list
at runtime.
"""

from __future__ import annotations
import importlib
import pkgutil
from typing import Optional, Sequence
from exonware.xwsystem import get_logger
from exonware.xwlogin.provider_connector import ABaseProvider

logger = get_logger(__name__)
# Modules to skip when discovering callback-capable providers.
_SKIP_MODULES = frozenset({
    "base",
    "registry",
    "callback_providers",
    "xwsystem_providers",
    # Multi-provider / regional barrels: not one module ↔ one callback name.
    "tier1_global_essential_providers",
    "tier2_enterprise_iam_stubs",
    "tier6_non_oauth_stubs",
    "tier7_api_flow_providers",
    "apac_india_sea_cis_stubs",
    "china_wecom_unionpay_stubs",
    "latam_fintech_retail_stubs",
    "mea_emea_fintech_stubs",
    "eidas_europe_providers",
})
# Registry id differs from the Python module name (documented aliases).
_ALLOWED_MODULE_PROVIDER_MISMATCHES: frozenset[tuple[str, str]] = frozenset({
    ("xiaomi_account", "xiaomi"),
})
# Custom __init__ args (module_name -> args) for providers that don't use
# (client_id, client_secret, authorization_url, token_url). Used only to
# read provider_name during discovery.
_CUSTOM_INIT_ARGS: dict[str, tuple] = {
    "adfs": ("", "", "https://adfs.example.com/adfs"),
    "active_directory": ("", "", "https://authority.example.com"),
    "ping_federate": ("", "", "https://pingfederate.example.com"),
}
_DUMMY_AUTH = "https://example.com/auth"
_DUMMY_TOKEN = "https://example.com/token"


def _get_provider_class(module_name: str) -> type | None:
    """Return the ABaseProvider subclass from a provider module, or None."""
    if module_name in _SKIP_MODULES:
        return None
    try:
        mod = importlib.import_module(f"exonware.xwlogin.providers.{module_name}")
    except Exception:
        return None
    mod_fqn = mod.__name__
    candidates: list[type] = []
    for attr in dir(mod):
        if attr.startswith("_"):
            continue
        try:
            obj = getattr(mod, attr)
        except Exception:
            continue
        if not isinstance(obj, type) or obj is ABaseProvider:
            continue
        try:
            if issubclass(obj, ABaseProvider):
                candidates.append(obj)
        except TypeError:
            pass
    if not candidates:
        return None
    defined_here = [c for c in candidates if getattr(c, "__module__", None) == mod_fqn]
    pool = defined_here if defined_here else candidates
    if len(pool) > 1:
        roots = [
            c
            for c in pool
            if not any(c is not d and issubclass(c, d) for d in pool)
        ]
        if roots:
            pool = roots
    pool.sort(key=lambda c: c.__name__)
    return pool[0]


def _try_provider_name(module_name: str, cls: type) -> str | None:
    """
    Instantiate the provider (with dummy args) and return provider_name, or None.
    Uses _CUSTOM_INIT_ARGS for known custom __init__; otherwise tries (client_id,
    client_secret) then (client_id, client_secret, auth_url, token_url).
    """
    if module_name in _CUSTOM_INIT_ARGS:
        arg_sets = [_CUSTOM_INIT_ARGS[module_name]]
    else:
        arg_sets = [
            ("", ""),
            ("", "", _DUMMY_AUTH, _DUMMY_TOKEN),
        ]
    for args in arg_sets:
        try:
            inst = cls(*args)
            return inst.provider_name
        except Exception:
            continue
    return None


def _is_oauth2_callback_provider_module(module_name: str) -> bool:
    """Return True if the providers submodule has an ABaseProvider subclass."""
    return _get_provider_class(module_name) is not None


def discover_oauth2_callback_provider_names() -> list[str]:
    """
    Discover provider names from the providers package.
    Scans top-level provider modules. Any module that defines a subclass of
    ABaseProvider (from providers.base) is considered callback-capable. The
    **provider name** used for routes is each provider's actual `provider_name`
    (so it matches registry lookup). When instantiation fails, the module name
    is used as fallback.
    Returns:
        Sorted list of unique provider names.
    """
    try:
        import exonware.xwlogin.providers as _login_pkg
    except Exception as e:
        logger.warning("could not import xwlogin.providers package: %s", e)
        return []
    names: set[str] = set()
    for _importer, modname, ispkg in pkgutil.iter_modules(_login_pkg.__path__):
        if ispkg:
            continue
        cls = _get_provider_class(modname)
        if cls is None:
            continue
        pname = _try_provider_name(modname, cls)
        if pname is not None:
            names.add(pname)
        else:
            names.add(modname)
            logger.debug(
                "provider name fallback: could not instantiate %s, using module name",
                modname,
            )
    return sorted(names)


def get_oauth2_callback_provider_names(
    extra: Optional[Sequence[str]] = None,
) -> list[str]:
    """
    Return sorted, unique provider names that get callback endpoints.
    Uses discover_oauth2_callback_provider_names() (from the providers
    codebase). extra (e.g. config.providers) is merged in.
    Args:
        extra: Additional names (e.g. from config.providers). Merged with
               discovered names.
    Returns:
        Sorted list of provider names.
    """
    names = set(discover_oauth2_callback_provider_names())
    if extra:
        for n in extra:
            if isinstance(n, str) and n.strip():
                names.add(n.strip().lower())
    return sorted(names)


def verify_provider_names_match_modules() -> tuple[list[tuple[str, str]], list[str]]:
    """
    Check that each provider's ``provider_name`` matches its module name.
    Used to ensure callback route names match registry lookup. When we cannot
    instantiate a provider, we use the module name as fallback.
    Returns:
        (mismatches, fallbacks): mismatches are (module_name, provider_name)
        where they differ; fallbacks are modules we could not instantiate.
    """
    try:
        import exonware.xwlogin.providers as _login_pkg
    except Exception:
        return [], []
    mismatches: list[tuple[str, str]] = []
    fallbacks: list[str] = []
    for _importer, modname, ispkg in pkgutil.iter_modules(_login_pkg.__path__):
        if ispkg or modname in _SKIP_MODULES:
            continue
        cls = _get_provider_class(modname)
        if cls is None:
            continue
        pname = _try_provider_name(modname, cls)
        if pname is None:
            fallbacks.append(modname)
            continue
        if pname != modname and (modname, pname) not in _ALLOWED_MODULE_PROVIDER_MISMATCHES:
            mismatches.append((modname, pname))
    return mismatches, fallbacks
