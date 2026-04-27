#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/par.py
Pushed Authorization Requests (PAR) Implementation (RFC 9126)
Implements PAR for OAuth 2.0 to push authorization request parameters
to the authorization server before redirecting the user.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 25-Jan-2026
"""

from __future__ import annotations
import secrets
import base64
from typing import Any, Optional
from datetime import datetime, timedelta
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.errors import XWInvalidRequestError, XWOAuthError
from exonware.xwauth.identity.base import ABaseAuth
logger = get_logger(__name__)

# Query parameters allowed on the authorization endpoint alongside ``request_uri``
# (RFC 9126: pushed request carries the bulk; browser redirect adds CSRF / tenant context).
PAR_AUTHORIZE_QUERY_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "request_uri",
        "client_id",
        "state",
        "nonce",
        "response_mode",
        "org_id",
        "organization_id",
        "project_id",
        "tenant_id",
        "tid",
    }
)


class PARManager:
    """
    Manager for Pushed Authorization Requests (RFC 9126).
    Stores authorization request parameters server-side and generates
    request_uri that can be used in the authorize endpoint.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize PAR manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        self._storage = auth.storage
        self._par_lifetime = int(self._config.par_request_lifetime)
        logger.debug("PARManager initialized")

    async def push_request(self, request_params: dict[str, Any], client_id: str) -> dict[str, Any]:
        """
        Push authorization request parameters (RFC 9126 Section 2.1).
        Stores request parameters server-side and returns request_uri.
        Args:
            request_params: Authorization request parameters
            client_id: Client identifier (must be authenticated)
        Returns:
            Dictionary with request_uri and expires_in
        Raises:
            XWInvalidRequestError: If request is invalid
        """
        # Validate client
        client = self._config.get_registered_client(client_id)
        if not client:
            raise XWInvalidRequestError(
                "Invalid client_id",
                error_code="invalid_client",
                error_description="Client not registered"
            )
        # Validate required parameters
        response_type = request_params.get("response_type")
        if not response_type:
            raise XWInvalidRequestError(
                "response_type is required",
                error_code="invalid_request",
                error_description="response_type parameter is required"
            )
        # Generate request_uri
        request_uri = self._generate_request_uri()
        # Calculate expiration
        expires_at = datetime.now() + timedelta(seconds=self._par_lifetime)
        # Store request parameters
        par_data = {
            "request_uri": request_uri,
            "client_id": client_id,
            "request_params": request_params.copy(),
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.now().isoformat(),
        }
        # Store in storage (using storage interface pattern)
        # For now, use a simple key-value pattern
        # In production, this should use proper storage entities
        storage_key = f"par:{request_uri}"
        # Use storage if it has a generic write method, otherwise use mock pattern
        if hasattr(self._storage, 'write'):
            await self._storage.write(storage_key, par_data)
        else:
            # Fallback: Store in a temporary dict (for mock storage)
            if not hasattr(self._storage, '_par_requests'):
                self._storage._par_requests = {}
            self._storage._par_requests[request_uri] = par_data
        logger.debug(f"Pushed PAR request: {request_uri} for client: {client_id}")
        return {
            "request_uri": request_uri,
            "expires_in": self._par_lifetime,
        }

    async def get_request(self, request_uri: str) -> Optional[dict[str, Any]]:
        """
        Retrieve pushed authorization request by request_uri.
        Args:
            request_uri: Request URI to retrieve
        Returns:
            Request parameters if found and not expired, None otherwise
        """
        storage_key = f"par:{request_uri}"
        # Retrieve from storage
        if hasattr(self._storage, 'read'):
            par_data = await self._storage.read(storage_key)
        else:
            # Fallback: Retrieve from temporary dict
            if not hasattr(self._storage, '_par_requests'):
                return None
            par_data = self._storage._par_requests.get(request_uri)
        if not par_data:
            return None
        # Check expiration
        expires_at_str = par_data.get("expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if datetime.now() > expires_at:
                    logger.debug(f"PAR request expired: {request_uri}")
                    # Clean up expired request
                    await self._delete_request(request_uri)
                    return None
            except (ValueError, TypeError):
                # Invalid date format, treat as expired
                await self._delete_request(request_uri)
                return None
        return par_data.get("request_params")

    async def consume_request(
        self, request_uri: str
    ) -> tuple[dict[str, Any], str] | None:
        """
        Atomically load and remove a pushed request (single-use ``request_uri``).

        Returns ``(request_params, client_id)`` or ``None`` if missing / expired.
        Matches common AS behavior (Hydra / FAPI deployments) to prevent authorize replay.
        """
        if not request_uri or not isinstance(request_uri, str):
            return None
        uri = request_uri.strip()
        storage_key = f"par:{uri}"
        par_data: dict[str, Any] | None
        if hasattr(self._storage, "read"):
            par_data = await self._storage.read(storage_key)
        else:
            if not hasattr(self._storage, "_par_requests"):
                return None
            par_data = self._storage._par_requests.get(uri)
        if not par_data:
            return None
        expires_at_str = par_data.get("expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if datetime.now() > expires_at:
                    logger.debug("PAR request expired: %s", uri)
                    await self._delete_request(uri)
                    return None
            except (ValueError, TypeError):
                await self._delete_request(uri)
                return None
        params = par_data.get("request_params")
        client_id = par_data.get("client_id")
        if not isinstance(params, dict) or not client_id:
            await self._delete_request(uri)
            return None
        await self._delete_request(uri)
        return (params, str(client_id))

    async def _delete_request(self, request_uri: str) -> None:
        """
        Delete PAR request from storage.
        Args:
            request_uri: Request URI to delete
        """
        storage_key = f"par:{request_uri}"
        if hasattr(self._storage, 'delete'):
            await self._storage.delete(storage_key)
        else:
            # Fallback: Delete from temporary dict
            if hasattr(self._storage, '_par_requests'):
                self._storage._par_requests.pop(request_uri, None)

    def _generate_request_uri(self) -> str:
        """
        Generate unique request_uri.
        Returns:
            Unique request URI (format: urn:ietf:params:oauth:request_uri:<token>)
        """
        # Generate random token (32 bytes = 256 bits)
        random_bytes = secrets.token_bytes(32)
        token = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        # RFC 9126 format: urn:ietf:params:oauth:request_uri:<token>
        return f"urn:ietf:params:oauth:request_uri:{token}"
