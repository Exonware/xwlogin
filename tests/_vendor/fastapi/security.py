#!/usr/bin/env python3
"""
#exonware/xwauth-identity/tests/_vendor/fastapi/security.py
Minimal FastAPI security shims for offline unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class HTTPAuthorizationCredentials:
    scheme: str
    credentials: str


class HTTPBearer:
    def __init__(self, auto_error: bool = True) -> None:
        self.auto_error = auto_error

    async def __call__(self, request: Any) -> HTTPAuthorizationCredentials | None:
        auth_header = None
        if hasattr(request, "headers") and request.headers:
            auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
        scheme, _, token = auth_header.partition(" ")
        if not token:
            return None
        return HTTPAuthorizationCredentials(scheme=scheme, credentials=token)
