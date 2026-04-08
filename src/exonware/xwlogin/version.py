#!/usr/bin/env python3
"""Version for exonware-xwlogin (aligned with xwauth pre-1.0)."""

from datetime import datetime


def _today_release_date() -> str:
    return datetime.now().strftime("%d-%b-%Y")


__version__ = "0.0.1.2"
__author__ = "eXonware Backend Team"
__email__ = "connect@exonware.com"
__date__ = _today_release_date()

__all__ = ["__version__", "__author__", "__email__", "__date__"]
