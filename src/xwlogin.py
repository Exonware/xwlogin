# exonware/xwlogin/src/xwlogin.py
"""
Top-level ``xwlogin`` import alias: same module object as ``exonware.xwlogin``.

Supports ``import xwlogin`` / ``from xwlogin import ...`` with no duplicated exports.
"""

from __future__ import annotations

import sys

import exonware.xwlogin as _pkg

sys.modules[__name__] = _pkg
