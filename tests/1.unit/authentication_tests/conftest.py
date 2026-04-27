#!/usr/bin/env python3
"""
#exonware/xwauth.connector/tests/1.unit/authentication_tests/conftest.py
Authentication Tests Fixtures
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 20-Dec-2025
"""

import sys
from pathlib import Path
# Add src to path for testing
src_path = Path(__file__).parent.parent.parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))
import pytest
