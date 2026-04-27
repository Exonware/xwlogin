# exonware/xwauth-identity/src/exonware/xwauth/identity/stack.py
"""
Opt-in extended XW stack imports (REF_41 §8).

**xwauth** already requires **xwsystem**, **xwaction**, and **xwschema**. After
``pip install exonware-xwauth-identity[stack]``, import this module to eagerly load the
optional chain: **xwjson**, **xwnode**, **xwdata**, **xwentity**, **xwmodels**,
**xwquery**.

Default **xwauth** does **not** import this module.
"""

from __future__ import annotations

import exonware.xwdata as xwdata  # noqa: F401
import exonware.xwentity as xwentity  # noqa: F401
import exonware.xwjson as xwjson  # noqa: F401
import exonware.xwmodels as xwmodels  # noqa: F401
import exonware.xwnode as xwnode  # noqa: F401
import exonware.xwquery as xwquery  # noqa: F401

__all__ = ["xwdata", "xwentity", "xwjson", "xwmodels", "xwnode", "xwquery"]
