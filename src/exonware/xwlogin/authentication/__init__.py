#!/usr/bin/env python3
"""
#exonware/xwlogin/src/exonware/xwlogin/authentication/__init__.py
Authentication Methods Module
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.1
Generation Date: 20-Dec-2025
"""

from .email_password import EmailPasswordAuthenticator
from .magic_link import MagicLinkAuthenticator
from .phone_otp import PhoneOTPAuthenticator
from .anonymous import AnonymousAuthenticator
from .account_linking import AccountLinking
from .webauthn import WebAuthnManager
__all__ = [
    "EmailPasswordAuthenticator",
    "MagicLinkAuthenticator",
    "PhoneOTPAuthenticator",
    "AnonymousAuthenticator",
    "AccountLinking",
    "WebAuthnManager",
]
