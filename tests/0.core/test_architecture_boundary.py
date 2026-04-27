#!/usr/bin/env python3
# exonware/xwauth-identity/tests/0.core/test_architecture_boundary.py
"""Independence guard: xwauth-identity src must not import xwauth-connect at module level.

The two packages are independent peers -- each owns its own errors, storage,
and handler primitives. Runtime discovery (``discover_connect_package``) goes
through ``importlib`` inside a function body, not a top-level import.

The reverse guard (connect src must not import identity at module level) is
enforced by the mirror test in xwauth-connect.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.xwlogin_core


def _identity_package_src() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "exonware" / "xwauth" / "identity"


def _module_level_connect_imports(py_path: Path) -> list[tuple[int, str]]:
    text = py_path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(py_path))
    bad: list[tuple[int, str]] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            mod = node.module
            if mod == "exonware.xwauth.connect" or mod.startswith("exonware.xwauth.connect."):
                bad.append((node.lineno, mod))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name == "exonware.xwauth.connect" or name.startswith("exonware.xwauth.connect."):
                    bad.append((node.lineno, name))
    return bad


def test_identity_src_has_no_module_level_connect_import() -> None:
    """Identity package must not bind connect at import time (GUIDE_32, zero-shims rule)."""
    root = _identity_package_src()
    assert root.is_dir(), f"missing package src: {root}"
    failures: list[str] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        for ln, mod in _module_level_connect_imports(path):
            failures.append(f"  {rel}:{ln} {mod}")
    assert not failures, (
        "exonware.xwauth.identity src must not import exonware.xwauth.connect at module "
        "level (use lazy imports inside functions via discover_connect_package()). "
        "Offenders:\n" + "\n".join(failures)
    )
