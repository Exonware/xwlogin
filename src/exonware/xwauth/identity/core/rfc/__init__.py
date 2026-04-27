#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/rfc/__init__.py
Advanced RFC Support Module
Implements advanced OAuth 2.0 RFCs for enhanced security and functionality.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from .rfc9101 import RFC9101BrowserBasedApps
from .rfc9207 import RFC9207IssuerIdentification
from .rfc9068 import RFC9068JWTProfile
from .rfc7521 import RFC7521JWTBearerToken
__all__ = [
    "RFC9101BrowserBasedApps",
    "RFC9207IssuerIdentification",
    "RFC9068JWTProfile",
    "RFC7521JWTBearerToken",
]
