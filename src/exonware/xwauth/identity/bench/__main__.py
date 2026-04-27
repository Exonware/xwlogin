#!/usr/bin/env python3
"""CLI: python -m exonware.xwauth.bench --iterations 2000 [--json]"""

from __future__ import annotations

import argparse
import sys

from exonware.xwsystem.io.serialization.formats.text import json as xw_json
from exonware.xwauth.identity.bench import run_microbench_suite


def main() -> int:
    p = argparse.ArgumentParser(description="xwauth micro-benchmark suite (REF_25 #6).")
    p.add_argument(
        "--iterations",
        type=int,
        default=2000,
        help="Repeats per benchmark case (default: 2000).",
    )
    p.add_argument("--json", action="store_true", help="Print JSON only (machine-readable).")
    args = p.parse_args()
    try:
        result = run_microbench_suite(iterations=args.iterations)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    if args.json:
        print(xw_json.dumps(result, indent=2))
        return 0
    it = result["iterations"]
    print(f"xwauth microbench iterations={it}")
    for key in ("jwt_generate_seconds", "jwt_validate_seconds", "oidc_at_hash_seconds"):
        print(f"  {key}: {result[key]:.6f}s")
    for name, c in result["cases"].items():
        print(f"  {name} per_op: {c['per_op_seconds']:.9f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
