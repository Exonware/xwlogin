"""Optional hooks into xwauth-api ops runtime (no hard dependency on xwauth-api)."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any


def notify_critical_handler(request: Any, operation_id: str, latency_ms: float, success: bool) -> None:
    app = getattr(request, "app", None)
    if app is None:
        return
    state = getattr(app, "state", None)
    if state is None:
        return
    runtime = getattr(state, "xwauth_ops_runtime", None)
    if runtime is None:
        return
    record = getattr(runtime, "record_critical_handler", None)
    if callable(record):
        record(operation_id, latency_ms, success)


@asynccontextmanager
async def track_critical_handler(request: Any, operation_id: str) -> AsyncIterator[None]:
    """Time a handler body and emit ops critical_handler metrics (success unless an exception escapes)."""
    t0 = time.perf_counter()
    ok = True
    try:
        yield
    except BaseException:
        ok = False
        raise
    finally:
        notify_critical_handler(request, operation_id, (time.perf_counter() - t0) * 1000.0, ok)
