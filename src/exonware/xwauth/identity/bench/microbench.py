#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/bench/microbench.py
Deterministic micro-benchmarks for JWT and OIDC-adjacent hot paths.

Used for reproducible methodology (REF_25 #6); not a substitute for HTTP/load tests.
"""

from __future__ import annotations

import time
from typing import Any

from exonware.xwauth.identity.tokens.jwt import JWTTokenManager, oidc_left_half_sha256_b64url

_BENCH_SECRET = "b" * 32  # fixed synthetic secret; never use in production


def run_microbench_suite(iterations: int = 500) -> dict[str, Any]:
    """
    Run fixed workloads and return wall-clock timings.

    Args:
        iterations: Repeat count per case (>= 1). Keep small in CI; raise locally for publishing.

    Returns:
        Dict with ``iterations``, per-phase total seconds, and ``cases`` detail map.
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    mgr = JWTTokenManager(
        secret=_BENCH_SECRET,
        algorithm="HS256",
        issuer="xwauth-bench",
        audience="xwauth-bench-audience",
    )

    # Warmup (stabilize JIT / imports if any)
    _w = mgr.generate_token("warmup", "warmup-client", ["openid"], expires_in=600)
    mgr.validate_token(_w)

    t0 = time.perf_counter()
    for _ in range(iterations):
        mgr.generate_token("bench-user", "bench-client", ["openid", "profile"], expires_in=600)
    gen_elapsed = time.perf_counter() - t0

    sample = mgr.generate_token("bench-user", "bench-client", ["openid"], expires_in=3600)
    t0 = time.perf_counter()
    for _ in range(iterations):
        mgr.validate_token(sample)
    val_elapsed = time.perf_counter() - t0

    sample_access = "x" * 48
    t0 = time.perf_counter()
    for _ in range(iterations):
        oidc_left_half_sha256_b64url(sample_access)
    hash_elapsed = time.perf_counter() - t0

    def _case(total: float) -> dict[str, float]:
        return {"total_seconds": total, "per_op_seconds": total / iterations}

    return {
        "iterations": iterations,
        "jwt_generate_seconds": gen_elapsed,
        "jwt_validate_seconds": val_elapsed,
        "oidc_at_hash_seconds": hash_elapsed,
        "cases": {
            "jwt_generate": _case(gen_elapsed),
            "jwt_validate": _case(val_elapsed),
            "oidc_at_hash": _case(hash_elapsed),
        },
    }
