# exonware/xwauth/oauth_http/errors.py
"""OAuth error → HTTP (body, status). Used by HTTP handlers."""

from __future__ import annotations
from typing import Any
from exonware.xwsystem.security.oauth_errors import oauth_error_to_http_parts

from ..federation.errors import federation_exception_to_oauth_response


def oauth_error_to_http(exc: Exception) -> tuple[dict[str, Any], int]:
    """
    Map xwauth OAuth/Token errors to (body, status_code).
    Args:
        exc: xwauth exception (XWOAuthError, XWTokenError, etc.)
    Returns:
        (dict for JSON body, HTTP status code)
    """
    mapped = federation_exception_to_oauth_response(exc)
    if mapped is not None:
        return mapped
    return oauth_error_to_http_parts(exc)
