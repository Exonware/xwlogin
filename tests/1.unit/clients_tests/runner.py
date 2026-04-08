#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/clients_tests/runner.py
OAuth Client Tests Module Runner
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 25-Jan-2026
"""

import sys
import os
from pathlib import Path
# ⚠️ CRITICAL: Configure UTF-8 encoding for Windows console (GUIDE_TEST.md compliance)
from exonware.xwsystem.console.cli import ensure_utf8_console
ensure_utf8_console()
# Import reusable utilities

def _package_root() -> Path:
    """Folder with pyproject.toml + src/ (any tests/**/runner.py depth)."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").is_file() and (p / "src").is_dir():
            return p
        p = p.parent
    raise RuntimeError("Could not locate package root from " + str(Path(__file__)))


_PKG_ROOT = _package_root()

from exonware.xwsystem.utils.test_runner import TestRunner


def main():
    """Run OAuth client unit tests."""
    os.chdir(_PKG_ROOT)
    test_dir = Path(__file__).parent
    runner = TestRunner(
        library_name="xwlogin",
        layer_name="1.unit.clients_tests",
        description="OAuth Client Library Unit Tests",
        test_dir=test_dir,
        pytest_cwd=_PKG_ROOT,
        markers=["xwlogin_unit"]
    )
    return runner.run()
if __name__ == "__main__":
    sys.exit(main())
