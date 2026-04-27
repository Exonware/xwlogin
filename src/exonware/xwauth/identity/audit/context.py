#!/usr/bin/env python3
"""Request-scoped audit context (correlation id) via contextvars for ASGI stacks."""

from __future__ import annotations

from contextvars import ContextVar, Token

_audit_correlation_id: ContextVar[str | None] = ContextVar("xwauth_audit_correlation_id", default=None)


def attach_audit_correlation(correlation_id: str | None) -> Token:
    """Bind correlation id for the current async context; returns token for reset."""
    return _audit_correlation_id.set((correlation_id or "").strip() or None)


def reset_audit_correlation(token: Token) -> None:
    _audit_correlation_id.reset(token)


def get_audit_correlation_id() -> str | None:
    return _audit_correlation_id.get()
