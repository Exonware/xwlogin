#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/ops/tco_evidence.py
Publishing workflow for **benchmark JSON** used in TCO / competitive evidence (REF_25 #19).

Validates output shape from ``exonware.xwauth.bench.run_microbench_suite``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

TCO_EVIDENCE_SCHEMA_VERSION = 1

_MICROBENCH_TOP_KEYS = frozenset(
    {
        "iterations",
        "jwt_generate_seconds",
        "jwt_validate_seconds",
        "oidc_at_hash_seconds",
        "cases",
    }
)
_CASE_KEYS = frozenset({"jwt_generate", "jwt_validate", "oidc_at_hash"})


def validate_microbench_output(doc: Mapping[str, Any]) -> None:
    """
    Ensure *doc* matches ``run_microbench_suite`` output shape.

    Raises:
        ValueError: missing keys or malformed ``cases``.
    """
    missing = _MICROBENCH_TOP_KEYS - doc.keys()
    if missing:
        raise ValueError(f"microbench output missing keys: {sorted(missing)}")
    cases = doc.get("cases")
    if not isinstance(cases, dict):
        raise ValueError("microbench output 'cases' must be a dict")
    case_missing = _CASE_KEYS - cases.keys()
    if case_missing:
        raise ValueError(f"microbench cases missing: {sorted(case_missing)}")
    for name in _CASE_KEYS:
        entry = cases[name]
        if not isinstance(entry, dict):
            raise ValueError(f"cases[{name!r}] must be a dict")
        if "total_seconds" not in entry or "per_op_seconds" not in entry:
            raise ValueError(f"cases[{name!r}] must include total_seconds and per_op_seconds")


def tco_benchmark_publish_checklist() -> dict[str, Any]:
    """Steps to capture reproducible numbers for REF_25 Appendix A / sales engineering."""
    return {
        "schema_version": TCO_EVIDENCE_SCHEMA_VERSION,
        "kind": "tco_benchmark_publish",
        "sections": [
            {
                "id": "environment",
                "title": "Record environment",
                "items": [
                    "OS, CPU model, RAM, Python version, ``PYTHONHASHSEED`` if relevant.",
                    "Commit SHA and package versions for exonware-xwauth / xwauth-api.",
                ],
            },
            {
                "id": "xwauth_microbench",
                "title": "Library microbench",
                "items": [
                    "Run ``python -m exonware.xwauth.bench --iterations <N> --json``; validate with ``validate_microbench_output``.",
                    "Store JSON under ``docs/logs/benchmarks/MICROBENCH_<date>.json`` (git-track only intentional releases).",
                ],
            },
            {
                "id": "xwauth_connector_api_http",
                "title": "HTTP token bench (TestClient or oha)",
                "items": [
                    "Run ``xwauth-api/scripts/http_bench.py`` or socket load per benchmarks README.",
                    "Attach methodology notes (workers, storage backend, warm-up).",
                ],
            },
            {
                "id": "tco_narrative",
                "title": "TCO narrative",
                "items": [
                    "Update REF_25 **Appendix A** table with measured ops/sec or latency bullets plus staffing comparison.",
                ],
            },
        ],
    }
