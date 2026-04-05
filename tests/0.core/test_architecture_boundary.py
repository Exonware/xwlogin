#!/usr/bin/env python3
# exonware/xwlogin/tests/0.core/test_architecture_boundary.py
"""Login-provider code must not import ``exonware.xwauth`` outside façade modules (GUIDE_32)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.xwlogin_core

# Only these paths (relative to ``exonware/xwlogin/``) may contain AST imports of ``exonware.xwauth``.
# Add a new ``*_connector.py`` (or ``handlers/connector_route_mixins.py``) when introducing a new bridge.
_XWLOGIN_XWAUTH_IMPORT_ALLOWLIST: frozenset[str] = frozenset(
    {
        "api_connector.py",
        "audit_connector.py",
        "auth_connector.py",
        "config_connector.py",
        "discovery_connector.py",
        "facade_connector.py",
        "handlers_common_connector.py",
        "mock_connector.py",
        "oauth_errors_connector.py",
        "ops_connector.py",
        "provider_connector.py",
        "storage_connector.py",
        "tokens_connector.py",
        "handlers/connector_route_mixins.py",
    }
)


def _xwlogin_package_src() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "exonware" / "xwlogin"


def _rel_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _xwauth_import_offenders(root: Path) -> list[tuple[str, int, str]]:
    bad: list[tuple[str, int, str]] = []
    for path in sorted(root.rglob("*.py")):
        rel = _rel_posix(path, root)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                mod = node.module
                if mod == "exonware.xwauth" or mod.startswith("exonware.xwauth."):
                    if rel not in _XWLOGIN_XWAUTH_IMPORT_ALLOWLIST:
                        bad.append((rel, node.lineno, mod))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if name == "exonware.xwauth" or name.startswith("exonware.xwauth."):
                        if rel not in _XWLOGIN_XWAUTH_IMPORT_ALLOWLIST:
                            bad.append((rel, node.lineno, name))
    return bad


def test_xwlogin_src_imports_xwauth_only_via_façade_modules() -> None:
    root = _xwlogin_package_src()
    assert root.is_dir(), f"missing package src: {root}"
    offenders = _xwauth_import_offenders(root)
    assert not offenders, (
        "exonware.xwauth may only be imported from designated *_connector / "
        "handlers/connector_route_mixins façade modules (GUIDE_32). Offenders:\n"
        + "\n".join(f"  {rel}:{ln} {mod}" for rel, ln, mod in offenders)
        + "\nUpdate _XWLOGIN_XWAUTH_IMPORT_ALLOWLIST if you added a new façade module."
    )
