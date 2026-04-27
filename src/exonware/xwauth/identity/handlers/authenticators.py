"""Factory helpers for first-party authenticators (email/password, magic link, phone OTP)."""

from __future__ import annotations

from typing import Any


def get_email_password_authenticator(auth: Any):
    from exonware.xwauth.identity.authentication.email_password import EmailPasswordAuthenticator

    return EmailPasswordAuthenticator(auth)


def get_magic_link_authenticator(auth: Any):
    from exonware.xwauth.identity.authentication.magic_link import MagicLinkAuthenticator

    return MagicLinkAuthenticator(auth)


def get_phone_otp_authenticator(auth: Any):
    from exonware.xwauth.identity.authentication.phone_otp import PhoneOTPAuthenticator

    return PhoneOTPAuthenticator(auth)
