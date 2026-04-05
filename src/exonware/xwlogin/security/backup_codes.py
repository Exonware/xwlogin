# exonware/xwlogin/src/exonware/xwlogin/security/backup_codes.py
"""One-time backup codes (hashed at rest)."""

from __future__ import annotations

import hashlib
import secrets
from typing import Iterable


def generate_backup_codes(count: int = 10) -> list[str]:
    """Return human-readable one-time codes (store only hashes)."""
    out: list[str] = []
    for _ in range(max(1, count)):
        chunk = secrets.token_hex(4)
        out.append(f"{chunk[:4]}-{chunk[4:]}".upper())
    return out


def hash_backup_code(code: str) -> str:
    normalized = "".join(code.split()).upper().replace("-", "")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_backup_code(code: str, hashes: Iterable[str]) -> str | None:
    """Return matched hash if any digest matches, else None."""
    target = hash_backup_code(code)
    for h in hashes:
        if secrets.compare_digest(target, h):
            return h
    return None
