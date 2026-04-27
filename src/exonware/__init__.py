"""
exonware package - Enterprise-grade Python framework ecosystem.

Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com

This is a namespace package allowing multiple exonware subpackages to coexist
(xwsystem, xwnode, xwdata, xwauth, etc.). Each distribution ships its own
leaf subpackage(s) under the shared ``exonware`` namespace; ``pkgutil.extend_path``
merges all matching on-disk locations at import time.

**Hard rule:** this file must NOT contain package-specific logic (version
loading, side effects, conditional imports). Multiple distributions all
provide this file; only one wins at import time, so any distribution-specific
code here is non-deterministic. Per-distribution version metadata lives in
the leaf subpackage's own ``version.py``.
"""
# Make this a namespace package FIRST
__path__ = __import__('pkgutil').extend_path(__path__, __name__)
