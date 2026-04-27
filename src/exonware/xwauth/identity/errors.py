#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/errors.py
XWAuth Error Classes
This module defines all error classes for the xwauth library,
providing rich error context and actionable error messages.
Following xwnode/xwquery error patterns.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from __future__ import annotations
import time
from typing import Any, Optional
from exonware.xwsystem import get_logger
logger = get_logger(__name__)
# ==============================================================================
# BASE ERROR
# ==============================================================================


class XWAuthError(Exception):
    """
    Base exception with rich context and zero overhead in success path.
    This error system follows modern Python best practices:
    - Zero overhead when no errors occur
    - Rich context only created on failure path
    - Chainable methods for fluent error building
    - Performance-optimized with __slots__
    Following xwnode/xwquery error patterns.
    """
    __slots__ = ('message', 'error_code', 'context', 'suggestions', 'timestamp', 'cause')

    def __init__(self, message: str, *, 
                 error_code: str = None,
                 context: dict[str, Any] = None,
                 suggestions: list[str] = None,
                 cause: Exception = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.suggestions = suggestions or []
        self.timestamp = time.time()
        self.cause = cause

    def add_context(self, **kwargs) -> XWAuthError:
        """Add context information (chainable)."""
        self.context.update(kwargs)
        return self

    def suggest(self, suggestion: str) -> XWAuthError:
        """Add actionable suggestion (chainable)."""
        self.suggestions.append(suggestion)
        return self

    def __str__(self) -> str:
        """Rich string representation with context and suggestions."""
        result = [self.message]
        if self.context:
            context_str = ', '.join(f"{k}={v}" for k, v in self.context.items())
            result.append(f"Context: {context_str}")
        if self.suggestions:
            suggestions_str = '; '.join(self.suggestions)
            result.append(f"Suggestions: {suggestions_str}")
        return " | ".join(result)
# ==============================================================================
# OAUTH 2.0 ERRORS
# ==============================================================================


class XWOAuthError(XWAuthError):
    """OAuth 2.0 specific errors following RFC 6749."""
    __slots__ = ('error_description', 'error_uri', 'state')

    def __init__(self, message: str, error_code: str, error_description: str = None, 
                 error_uri: Optional[str] = None, state: Optional[str] = None, **kwargs):
        super().__init__(message, error_code=error_code, **kwargs)
        self.error_description = error_description
        self.error_uri = error_uri
        self.state = state


class XWInvalidRequestError(XWOAuthError):
    """Invalid request error (OAuth 2.0)."""

    def __init__(self, message: str, error_code: str = "invalid_request", **kwargs):
        super().__init__(message, error_code=error_code, **kwargs)


class XWUnauthorizedClientError(XWOAuthError):
    """Unauthorized client error (OAuth 2.0)."""

    def __init__(self, message: str, error_code: str = "unauthorized_client", **kwargs):
        super().__init__(message, error_code=error_code, **kwargs)


class XWAccessDeniedError(XWOAuthError):
    """Access denied error (OAuth 2.0)."""
    pass


class XWUnsupportedResponseTypeError(XWOAuthError):
    """Unsupported response type error (OAuth 2.0)."""

    def __init__(self, message: str, error_code: str = "unsupported_response_type", **kwargs):
        super().__init__(message, error_code=error_code, **kwargs)


class XWInvalidScopeError(XWOAuthError):
    """Invalid scope error (OAuth 2.0)."""
    pass


class XWServerError(XWOAuthError):
    """Server error (OAuth 2.0)."""
    pass


class XWTemporarilyUnavailableError(XWOAuthError):
    """Temporarily unavailable error (OAuth 2.0)."""
    pass
# ==============================================================================
# TOKEN ERRORS
# ==============================================================================


class XWTokenError(XWAuthError):
    """Token-related errors."""
    pass


class XWInvalidTokenError(XWTokenError):
    """Invalid token error (RFC 6749 / introspection; OAuth token endpoint uses invalid_grant)."""

    __slots__ = ("error_description",)

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        error_description: str | None = None,
        context: dict[str, Any] | None = None,
        suggestions: list[str] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            error_code=error_code or "invalid_token",
            context=context,
            suggestions=suggestions,
            cause=cause,
        )
        self.error_description = (
            error_description if error_description is not None else message
        )


class XWExpiredTokenError(XWTokenError):
    """Expired token error."""

    __slots__ = ("error_description",)

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        error_description: str | None = None,
        context: dict[str, Any] | None = None,
        suggestions: list[str] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
            error_code=error_code or "invalid_token",
            context=context,
            suggestions=suggestions,
            cause=cause,
        )
        self.error_description = (
            error_description if error_description is not None else message
        )


class XWTokenRevokedError(XWTokenError):
    """Token revoked error."""
    pass


class XWTokenNotFoundError(XWTokenError):
    """Token not found error."""
    pass
# ==============================================================================
# PROVIDER ERRORS
# ==============================================================================


class XWProviderError(XWAuthError):
    """Provider integration errors."""
    pass


class XWProviderNotFoundError(XWProviderError):
    """Provider not found error."""

    def __init__(self, message: str, provider_name: str = None, **kwargs):
        context = kwargs.get('context', {})
        if provider_name:
            context['provider_name'] = provider_name
        super().__init__(message, context=context, **{k: v for k, v in kwargs.items() if k != 'context'})


class XWProviderConfigurationError(XWProviderError):
    """Provider configuration error."""
    pass


class XWProviderConnectionError(XWProviderError):
    """Provider connection error."""
    pass
# ==============================================================================
# AUTHENTICATION ERRORS
# ==============================================================================


class XWAuthenticationError(XWAuthError):
    """Authentication errors."""
    pass


class XWInvalidCredentialsError(XWAuthenticationError):
    """Invalid credentials error."""
    pass


class XWAccountLockedError(XWAuthenticationError):
    """Account locked error."""
    pass


class XWAccountDisabledError(XWAuthenticationError):
    """Account disabled error."""
    pass
# ==============================================================================
# AUTHORIZATION ERRORS
# ==============================================================================


class XWAuthorizationError(XWAuthError):
    """Authorization errors."""
    pass


class XWPermissionDeniedError(XWAuthorizationError):
    """Permission denied error."""
    pass


class XWInsufficientScopeError(XWAuthorizationError):
    """Insufficient scope error."""
    pass
# ==============================================================================
# USER ERRORS
# ==============================================================================


class XWUserError(XWAuthError):
    """User-related errors."""
    pass


class XWUserNotFoundError(XWUserError):
    """User not found error."""

    def __init__(self, message: str, user_id: str = None, **kwargs):
        context = kwargs.get('context', {})
        if user_id:
            context['user_id'] = user_id
        super().__init__(message, context=context, **{k: v for k, v in kwargs.items() if k != 'context'})


class XWUserAlreadyExistsError(XWUserError):
    """User already exists error."""

    def __init__(self, message: str, email: str = None, **kwargs):
        context = kwargs.get('context', {})
        if email:
            context['email'] = email
        super().__init__(message, context=context, **{k: v for k, v in kwargs.items() if k != 'context'})


class XWInvalidUserDataError(XWUserError):
    """Invalid user data error."""
    pass
# ==============================================================================
# SESSION ERRORS
# ==============================================================================


class XWSessionError(XWAuthError):
    """Session-related errors."""
    pass


class XWSessionExpiredError(XWSessionError):
    """Session expired error."""
    pass


class XWSessionNotFoundError(XWSessionError):
    """Session not found error."""
    pass
# ==============================================================================
# STORAGE ERRORS
# ==============================================================================


class XWStorageError(XWAuthError):
    """Storage provider errors."""
    pass


class XWStorageConnectionError(XWStorageError):
    """Storage connection error."""
    pass


class XWStorageOperationError(XWStorageError):
    """Storage operation error."""
    pass
# ==============================================================================
# CONFIG & VALIDATION ERRORS (parity with xlib_OLD/xauth)
# ==============================================================================


class XWConfigError(XWAuthError, ValueError):
    """Configuration error or invalid settings."""
    pass


class XWValidationError(XWAuthError, ValueError):
    """Data or input validation failure."""
    pass
# ==============================================================================
# MFA ERRORS
# ==============================================================================


class XWMFAError(XWAuthError):
    """Multi-factor authentication errors."""
    pass


class XWMFAInvalidCodeError(XWMFAError):
    """MFA code invalid or expired."""
    pass


class XWMFARequiredError(XWMFAError):
    """MFA required but not provided or not verified."""
    pass
# ==============================================================================
# WEBAUTHN / PASSKEYS ERRORS
# ==============================================================================


class XWWebAuthnError(XWAuthError):
    """WebAuthn / passkeys errors."""
    pass


class XWWebAuthnChallengeError(XWWebAuthnError):
    """WebAuthn challenge validation failed."""
    pass


class XWWebAuthnCredentialError(XWWebAuthnError):
    """WebAuthn credential registration or verification failed."""
    pass
# ==============================================================================
# SECURITY ERRORS (CSRF, RATE LIMIT)
# ==============================================================================


class XWCSRFError(XWAuthError):
    """CSRF validation failed."""
    pass


class XWRateLimitError(XWAuthError):
    """Rate limit exceeded for the given action."""
    pass
