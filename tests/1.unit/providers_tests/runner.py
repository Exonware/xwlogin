#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/providers_tests/runner.py
Provider Tests Module Runner
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 20-Dec-2025
"""

import sys
from pathlib import Path
# ⚠️ CRITICAL: Configure UTF-8 encoding for Windows console (GUIDE_TEST.md compliance)
from exonware.xwsystem.console.cli import ensure_utf8_console
ensure_utf8_console()
# Add src to Python path
src_path = Path(__file__).parent.parent.parent.parent / "src"
sys.path.insert(0, str(src_path))
# Import reusable utilities
from exonware.xwsystem.utils.test_runner import TestRunner


def main():
    """Run provider integration unit tests."""
    test_dir = Path(__file__).parent
    runner = TestRunner(
        library_name="xwlogin",
        layer_name="1.unit.providers_tests",
        description="Provider Integration Unit Tests",
        test_dir=test_dir,
        markers=["xwlogin_unit"]
    )
    return runner.run()
if __name__ == "__main__":
    sys.exit(main())
