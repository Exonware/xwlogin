#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/rfc/rfc9101.py
RFC 9101: OAuth 2.0 for Browser-Based Apps
Implements OAuth 2.0 security best practices for browser-based applications.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from typing import Any, Optional
from urllib.parse import urlparse
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.errors import XWInvalidRequestError
logger = get_logger(__name__)


class RFC9101BrowserBasedApps:
    """
    RFC 9101: OAuth 2.0 for Browser-Based Apps implementation.
    Provides security enhancements for browser-based OAuth 2.0 applications:
    - PKCE mandatory for public clients
    - Redirect URI validation
    - State parameter requirements
    - Token storage security recommendations
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize RFC 9101 support.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        logger.debug("RFC9101BrowserBasedApps initialized")

    def validate_browser_based_client(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None
    ) -> None:
        """
        Validate browser-based client according to RFC 9101.
        Requirements:
        - PKCE is mandatory for public clients
        - Redirect URI must be registered
        - Redirect URI must use HTTPS (except localhost)
        Args:
            client_id: Client identifier
            redirect_uri: Redirect URI
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE code challenge method
        Raises:
            XWInvalidRequestError: If validation fails
        """
        # Get client
        client = self._config.get_registered_client(client_id)
        if not client:
            raise XWInvalidRequestError(
                "Client not found",
                error_code="invalid_client"
            )
        # Check if public client
        is_public = self._is_public_client(client)
        # RFC 9101: PKCE mandatory for public clients
        if is_public:
            if not code_challenge:
                raise XWInvalidRequestError(
                    "PKCE code_challenge is required for public clients (RFC 9101)",
                    error_code="invalid_request",
                    error_description="Public clients must use PKCE (RFC 9101)"
                )
            if code_challenge_method not in ("S256", "plain"):
                raise XWInvalidRequestError(
                    "Invalid code_challenge_method. Must be 'S256' or 'plain'",
                    error_code="invalid_request"
                )
        # Validate redirect URI
        parsed_uri = urlparse(redirect_uri)
        # RFC 9101: Redirect URI must use HTTPS (except localhost)
        if parsed_uri.scheme != "https":
            if parsed_uri.hostname not in ("localhost", "127.0.0.1", "::1"):
                raise XWInvalidRequestError(
                    "Redirect URI must use HTTPS (RFC 9101)",
                    error_code="invalid_request",
                    error_description="Browser-based apps must use HTTPS redirect URIs"
                )
        # Validate redirect URI is registered
        registered_uris = client.get("redirect_uris", [])
        if redirect_uri not in registered_uris:
            raise XWInvalidRequestError(
                "Invalid redirect_uri",
                error_code="invalid_request",
                error_description="Redirect URI not registered for client"
            )

    def _is_public_client(self, client: dict[str, Any]) -> bool:
        """Check if client is public (no client_secret)."""
        return not client.get("client_secret")

    def get_browser_based_recommendations(self) -> dict[str, Any]:
        """
        Get security recommendations for browser-based apps (RFC 9101).
        Returns:
            Dictionary with security recommendations
        """
        return {
            "pkce_required": True,
            "token_storage": "httpOnly cookies or secure storage",
            "redirect_uri_https": True,
            "state_parameter": True,
            "token_lifetime": "Short-lived access tokens recommended",
            "refresh_token_rotation": True,
        }
