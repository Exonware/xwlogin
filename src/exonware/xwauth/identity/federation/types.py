#!/usr/bin/env python3
"""
Federation broker contracts and normalized identity DTOs.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FederatedIdentity:
    """Normalized identity payload returned by federation adapters."""

    provider: str
    subject_id: str
    email: str | None = None
    tenant_id: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)
    mapping_trace: dict[str, Any] | None = None

