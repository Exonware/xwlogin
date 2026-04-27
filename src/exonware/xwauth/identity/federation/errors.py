#!/usr/bin/env python3
"""
Federation upstream error taxonomy and safe OAuth-style client responses.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from exonware.xwsystem.security.oauth_errors import oauth_error_body, oauth_error_status

from exonware.xwauth.identity.errors import XWAuthError


class FederationUpstreamCode(str, Enum):
    """Stable internal codes for IdP / directory failures (logs, metrics, support)."""

    UPSTREAM_TIMEOUT = "upstream_timeout"
    INVALID_STATE = "invalid_upstream_state"
    INVALID_NONCE = "invalid_upstream_nonce"
    INVALID_SIGNATURE = "invalid_upstream_signature"
    TOKEN_VALIDATION_FAILED = "upstream_token_invalid"
    MISCONFIGURED_IDP = "misconfigured_idp"
    ACCOUNT_LINK_CONFLICT = "account_link_conflict"
    RATE_LIMITED = "upstream_rate_limited"


class XWFederationError(XWAuthError):
    """
    Federation failure with an upstream classification.
    HTTP mapping is performed via federation_exception_to_oauth_response.
    """

    __slots__ = ("upstream_code", "oauth_error", "safe_description")

    def __init__(
        self,
        message: str,
        *,
        upstream_code: FederationUpstreamCode | str,
        oauth_error: str = "invalid_grant",
        safe_description: str | None = None,
        **kwargs: Any,
    ) -> None:
        code = upstream_code.value if isinstance(upstream_code, FederationUpstreamCode) else str(upstream_code)
        super().__init__(message, error_code=code, **kwargs)
        self.upstream_code = code
        self.oauth_error = oauth_error
        self.safe_description = safe_description or "Authentication with the external identity provider failed."


_UPSTREAM_TO_OAUTH: dict[str, tuple[str, str]] = {
    FederationUpstreamCode.UPSTREAM_TIMEOUT.value: (
        "temporarily_unavailable",
        "The identity provider did not respond in time. Try again shortly.",
    ),
    FederationUpstreamCode.INVALID_STATE.value: (
        "invalid_grant",
        "The login session is invalid or expired. Restart sign-in.",
    ),
    FederationUpstreamCode.INVALID_NONCE.value: (
        "invalid_grant",
        "The OpenID Connect nonce did not match. Restart sign-in.",
    ),
    FederationUpstreamCode.INVALID_SIGNATURE.value: (
        "invalid_grant",
        "The identity provider response could not be verified.",
    ),
    FederationUpstreamCode.TOKEN_VALIDATION_FAILED.value: (
        "invalid_grant",
        "Token validation with the identity provider failed.",
    ),
    FederationUpstreamCode.MISCONFIGURED_IDP.value: (
        "invalid_request",
        "Single sign-on is misconfigured for this organization.",
    ),
    FederationUpstreamCode.ACCOUNT_LINK_CONFLICT.value: (
        "access_denied",
        "This account cannot be linked automatically. Contact an administrator.",
    ),
    FederationUpstreamCode.RATE_LIMITED.value: (
        "temporarily_unavailable",
        "The identity provider is busy. Try again shortly.",
    ),
}


def federation_exception_to_oauth_response(exc: Exception) -> tuple[dict[str, Any], int] | None:
    """
    If exc is a federation-classified error, return a safe (body, status) for HTTP handlers.
    """
    if isinstance(exc, XWFederationError):
        oauth_err = exc.oauth_error
        desc = exc.safe_description
        body = oauth_error_body(oauth_err, desc)
        status = oauth_error_status(oauth_err)
        body["federation_upstream"] = exc.upstream_code
        return body, status
    upstream = getattr(exc, "federation_upstream", None)
    if isinstance(upstream, str) and upstream in _UPSTREAM_TO_OAUTH:
        oauth_err, desc = _UPSTREAM_TO_OAUTH[upstream]
        body = oauth_error_body(oauth_err, desc)
        body["federation_upstream"] = upstream
        return body, oauth_error_status(oauth_err)
    return None
