#!/usr/bin/env python3
"""
#exonware/xwauth-identity/tests/_vendor/fastapi/__init__.py
Minimal FastAPI shims for unit tests that only need import-time symbols.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Request:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    state: Any = None
