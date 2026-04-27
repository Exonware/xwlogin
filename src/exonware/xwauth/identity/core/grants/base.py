#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/grants/base.py
Base Grant Class
Abstract base class for OAuth 2.0 grant types.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from abc import ABC, abstractmethod
from typing import Any, Optional
from datetime import datetime, timedelta
import secrets
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError, XWUnauthorizedClientError
from exonware.xwauth.identity.base import ABaseAuth
logger = get_logger(__name__)


class ABaseGrant(ABC):
    """
    Abstract base class for OAuth 2.0 grant types.
    Provides common functionality for all grant type implementations.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize grant handler.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        self._storage = auth.storage
        logger.debug(f"ABaseGrant initialized: {self.grant_type}")
    @property
    @abstractmethod

    def grant_type(self) -> GrantType:
        """Get grant type."""
        pass
    @abstractmethod

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Validate grant request.
        Args:
            request: Request parameters
        Returns:
            Validated request data
        Raises:
            XWOAuthError: If validation fails
        """
        pass
    @abstractmethod

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Process grant request and return token response.
        Args:
            request: Validated request parameters
        Returns:
            Token response dictionary
        """
        pass

    def _validate_client(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        *,
        require_secret: bool = True,
    ) -> dict[str, Any]:
        """
        Validate OAuth client against registered_clients.
        Args:
            client_id: Client identifier
            client_secret: Optional client secret (required for confidential clients when require_secret)
            require_secret: If True, verify client_secret for confidential clients (token exchange, introspect, revoke).
                If False, only check client is registered (e.g. authorize redirect).
        Returns:
            Registered client dict (client_id, client_secret, redirect_uris)
        Raises:
            XWUnauthorizedClientError: If client is invalid or secret mismatch
        """
        if not client_id:
            raise XWUnauthorizedClientError(
                "Client ID is required",
                error_code="invalid_client",
                error_description="client_id parameter is required"
            )
        client = self._config.get_registered_client(client_id)
        if not client:
            raise XWUnauthorizedClientError(
                "Unknown client",
                error_code="invalid_client",
                error_description="Client not registered"
            )
        if not require_secret:
            return client
        secret = client.get("client_secret") or ""
        if secret:
            if not client_secret:
                raise XWUnauthorizedClientError(
                    "client_secret is required for this client",
                    error_code="invalid_client",
                    error_description="client_secret parameter is required"
                )
            # Constant-time compare prevents timing side-channels on client credentials.
            if not secrets.compare_digest(str(client_secret), str(secret)):
                raise XWUnauthorizedClientError(
                    "Invalid client credentials",
                    error_code="invalid_client",
                    error_description="client_secret mismatch"
                )
        return client

    def _is_public_client(self, client: dict[str, Any]) -> bool:
        """
        Check if client is public (no client_secret).
        Args:
            client: Client dict from get_registered_client
        Returns:
            True if client is public (no client_secret), False if confidential
        """
        secret = client.get("client_secret") or ""
        return not secret

    def _validate_redirect_uri(
        self, redirect_uri: str, registered_uris: Optional[list[str]] = None
    ) -> bool:
        """
        Validate redirect URI (OAuth 2.1: exact matching against per-client allowlist).
        Args:
            redirect_uri: Redirect URI from request
            registered_uris: Registered redirect URIs for client (exact match)
        Returns:
            True if redirect URI is valid
        Raises:
            XWInvalidRequestError: If redirect URI is invalid
        """
        if not redirect_uri:
            raise XWInvalidRequestError(
                "redirect_uri is required",
                error_code="invalid_request",
                error_description="redirect_uri parameter is required"
            )
        if registered_uris is not None:
            if not registered_uris:
                raise XWInvalidRequestError(
                    "No redirect_uris registered for client",
                    error_code="invalid_request",
                    error_description="Client has no registered redirect URIs",
                )
            if redirect_uri not in registered_uris:
                raise XWInvalidRequestError(
                    "redirect_uri does not match any registered URI",
                    error_code="invalid_request",
                    error_description="redirect_uri does not match registered URI",
                )
        return True

    def _validate_scope(self, requested_scopes: Optional[str], allowed_scopes: Optional[list[str]] = None) -> list[str]:
        """
        Validate and normalize scopes.
        Args:
            requested_scopes: Space-separated scope string
            allowed_scopes: Optional list of allowed scopes
        Returns:
            List of validated scopes
        """
        if not requested_scopes:
            return []
        scopes = requested_scopes.split()
        if allowed_scopes:
            # Filter to only allowed scopes
            scopes = [s for s in scopes if s in allowed_scopes]
        return scopes

    def _generate_state(self) -> str:
        """
        Generate cryptographically random state parameter for CSRF protection.
        Returns:
            Random state string
        """
        from exonware.xwsystem.security.hazmat import secure_random
        import base64
        # Generate 32 random bytes, encode as URL-safe base64
        random_bytes = secure_random(32)
        state = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return state
