# exonware/xwlogin/src/exonware/xwlogin/stack.py
"""
Opt-in first-party XW stack imports (REF_41 §8).

Install ``pip install exonware-xwlogin[full]``, then import this module during host
bootstrap to eagerly load **xwnode**, **xwdata**, **xwentity**, **xwmodels**,
**xwquery**, and **xwaction** (same pins as the **full** extra).

- **xwjson** / **xwapi** — use ``pip install exonware-xwlogin[full]`` and import
  handler modules as needed.
- **xwschema** — provided by the **exonware-xwauth** dependency on **xwlogin**.

Default **xwlogin** does **not** import this module.
"""

from __future__ import annotations

import exonware.xwaction as xwaction  # noqa: F401
import exonware.xwdata as xwdata  # noqa: F401
import exonware.xwentity as xwentity  # noqa: F401
import exonware.xwmodels as xwmodels  # noqa: F401
import exonware.xwnode as xwnode  # noqa: F401
import exonware.xwquery as xwquery  # noqa: F401

__all__ = ["xwaction", "xwdata", "xwentity", "xwmodels", "xwnode", "xwquery"]
