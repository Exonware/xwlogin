#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/bench/__init__.py
Micro-benchmark entry points for competitive ops evidence (REF_25 #6).
"""

from __future__ import annotations

from .microbench import run_microbench_suite

__all__ = ["run_microbench_suite"]
