#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/dcr.py
Dynamic Client Registration (DCR) Implementation (RFC 7591, RFC 7592)
Implements OAuth 2.0 Dynamic Client Registration for programmatic
client registration and management.
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
from datetime import datetime
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.errors import XWInvalidRequestError, XWOAuthError
from exonware.xwauth.identity.base import ABaseAuth
logger = get_logger(__name__)


class DCRManager:
    """
    Manager for Dynamic Client Registration (RFC 7591, RFC 7592).
    Handles client registration, retrieval, update, and deletion.
    """

    def __init__(self, auth: ABaseAuth, registration_endpoint_base: Optional[str] = None):
        """
        Initialize DCR manager.
        Args:
            auth: XWAuth instance
            registration_endpoint_base: Base URL for registration_client_uri
                                      (e.g., "https://as.example.com/v1/auth/register")
        """
        self._auth = auth
        self._config = auth.config
        self._storage = auth.storage
        self._registration_endpoint_base = registration_endpoint_base or ""
        logger.debug("DCRManager initialized")

    async def register_client(self, client_metadata: dict[str, Any]) -> dict[str, Any]:
        """
        Register a new OAuth client (RFC 7591 Section 2).
        Args:
            client_metadata: Client metadata (redirect_uris, grant_types, etc.)
        Returns:
            Client registration response with client_id, client_secret, registration_client_uri
        """
        # Validate required fields
        redirect_uris = client_metadata.get("redirect_uris", [])
        if not redirect_uris or not isinstance(redirect_uris, list):
            raise XWInvalidRequestError(
                "redirect_uris is required and must be a list",
                error_code="invalid_client_metadata",
                error_description="redirect_uris parameter is required"
            )
        # Generate client_id
        client_id = self._generate_client_id()
        # Generate client_secret (for confidential clients)
        # If client_type is not specified, assume confidential if client_secret not provided
        client_type = client_metadata.get("token_endpoint_auth_method", "client_secret_basic")
        client_secret = None
        if client_type in ("client_secret_basic", "client_secret_post", "client_secret_jwt"):
            client_secret = self._generate_client_secret()
        # Generate registration_client_uri
        registration_client_uri = self._generate_registration_client_uri(client_id)
        # Build client data
        client_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "registration_client_uri": registration_client_uri,
            "registration_access_token": self._generate_registration_access_token(),
            "client_id_issued_at": int(datetime.now().timestamp()),
            "client_secret_expires_at": 0,  # 0 means never expires
            **client_metadata,
        }
        # Store client in storage
        storage_key = f"oauth_client:{client_id}"
        # Use storage if it has a generic write method
        if hasattr(self._storage, 'write'):
            await self._storage.write(storage_key, client_data)
        else:
            # Fallback: Store in a temporary dict (for mock storage)
            if not hasattr(self._storage, '_oauth_clients'):
                self._storage._oauth_clients = {}
            self._storage._oauth_clients[client_id] = client_data
        # Update config's dynamic clients registry
        if not hasattr(self._config, '_dynamic_clients'):
            self._config._dynamic_clients = {}
        self._config._dynamic_clients[client_id] = client_data
        # Add to registered_clients list if not already there
        existing = self._config.get_registered_client(client_id)
        if not existing:
            self._config.registered_clients.append({
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uris": redirect_uris,
            })
        logger.debug(f"Registered new OAuth client: {client_id}")
        # Return registration response (RFC 7591 Section 2)
        response = {
            "client_id": client_id,
            "client_id_issued_at": client_data["client_id_issued_at"],
            "client_secret": client_secret,
            "client_secret_expires_at": 0,
            "registration_access_token": client_data["registration_access_token"],
            "registration_client_uri": registration_client_uri,
            **{k: v for k, v in client_metadata.items() if k not in ("client_id", "client_secret")},
        }
        return response

    async def validate_registration_access_token(
        self,
        client_id: str,
        registration_access_token: str
    ) -> bool:
        """
        Validate registration access token for client.
        Args:
            client_id: Client identifier
            registration_access_token: Registration access token to validate
        Returns:
            True if token is valid, False otherwise
        Raises:
            XWInvalidRequestError: If token is invalid
        """
        # Get client data
        client_data = await self._get_client_data(client_id)
        if not client_data:
            raise XWInvalidRequestError(
                "Client not found",
                error_code="invalid_client_id",
                error_description=f"Client {client_id} not found"
            )
        # Get stored registration access token
        stored_token = client_data.get("registration_access_token")
        if not stored_token:
            # Client doesn't have registration access token (pre-registered client)
            raise XWInvalidRequestError(
                "Registration access token not available",
                error_code="invalid_token",
                error_description="Client does not support registration access token"
            )
        # Validate token (constant-time comparison)
        if not secrets.compare_digest(registration_access_token, stored_token):
            raise XWInvalidRequestError(
                "Invalid registration access token",
                error_code="invalid_token",
                error_description="Registration access token does not match"
            )
        return True

    async def _get_client_data(self, client_id: str) -> Optional[dict[str, Any]]:
        """
        Get raw client data from storage.
        Args:
            client_id: Client identifier
        Returns:
            Client data dictionary or None
        """
        # Try storage first
        storage_key = f"oauth_client:{client_id}"
        if hasattr(self._storage, 'read'):
            client_data = await self._storage.read(storage_key)
        else:
            # Fallback: Retrieve from temporary dict
            if not hasattr(self._storage, '_oauth_clients'):
                return None
            client_data = self._storage._oauth_clients.get(client_id)
        # If not in storage, check config
        if not client_data:
            client_data = self._config.get_registered_client(client_id)
            if client_data:
                # Convert config format to DCR format
                client_data = {
                    "client_id": client_data.get("client_id"),
                    "client_secret": client_data.get("client_secret"),
                    "redirect_uris": client_data.get("redirect_uris", []),
                }
        return client_data

    async def get_client(self, client_id: str, registration_access_token: Optional[str] = None) -> Optional[dict[str, Any]]:
        """
        Get client metadata by client_id (RFC 7592 Section 2.1).
        Args:
            client_id: Client identifier
            registration_access_token: Registration access token (required for DCR clients)
        Returns:
            Client metadata if found, None otherwise
        """
        # Validate registration access token if provided
        if registration_access_token:
            await self.validate_registration_access_token(client_id, registration_access_token)
        # Get client data
        client_data = await self._get_client_data(client_id)
        # Remove sensitive fields for response
        if client_data:
            response = client_data.copy()
            # Don't return client_secret in GET response (RFC 7592)
            # Only return it during initial registration
            if "client_secret" in response:
                del response["client_secret"]
            if "registration_access_token" in response:
                del response["registration_access_token"]
            return response
        return None

    async def update_client(
        self, 
        client_id: str, 
        client_metadata: dict[str, Any],
        registration_access_token: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Update client metadata (RFC 7592 Section 2.2).
        Args:
            client_id: Client identifier
            client_metadata: Updated client metadata
            registration_access_token: Registration access token (required for DCR clients)
        Returns:
            Updated client metadata
        """
        # Validate registration access token if provided
        if registration_access_token:
            await self.validate_registration_access_token(client_id, registration_access_token)
        # Get existing client
        existing = await self._get_client_data(client_id)
        if not existing:
            raise XWInvalidRequestError(
                "Client not found",
                error_code="invalid_client_id",
                error_description=f"Client {client_id} not found"
            )
        # Merge updates (don't allow changing client_id or registration_client_uri)
        updated = existing.copy()
        for key, value in client_metadata.items():
            if key not in ("client_id", "registration_client_uri", "client_id_issued_at"):
                updated[key] = value
        # Store updated client
        storage_key = f"oauth_client:{client_id}"
        if hasattr(self._storage, 'write'):
            await self._storage.write(storage_key, updated)
        else:
            # Fallback: Update in temporary dict
            if not hasattr(self._storage, '_oauth_clients'):
                self._storage._oauth_clients = {}
            self._storage._oauth_clients[client_id] = updated
        # Update config
        if hasattr(self._config, '_dynamic_clients'):
            self._config._dynamic_clients[client_id] = updated
        logger.debug(f"Updated OAuth client: {client_id}")
        # Return updated metadata (without sensitive fields)
        response = updated.copy()
        if "client_secret" in response:
            del response["client_secret"]
        if "registration_access_token" in response:
            del response["registration_access_token"]
        return response

    async def delete_client(
        self, 
        client_id: str,
        registration_access_token: Optional[str] = None
    ) -> None:
        """
        Delete client (RFC 7592 Section 2.3).
        Args:
            client_id: Client identifier
            registration_access_token: Registration access token (required for DCR clients)
        """
        # Validate registration access token if provided
        if registration_access_token:
            await self.validate_registration_access_token(client_id, registration_access_token)
        # Check if client exists
        existing = await self._get_client_data(client_id)
        if not existing:
            raise XWInvalidRequestError(
                "Client not found",
                error_code="invalid_client_id",
                error_description=f"Client {client_id} not found"
            )
        # Delete from storage
        storage_key = f"oauth_client:{client_id}"
        if hasattr(self._storage, 'delete'):
            await self._storage.delete(storage_key)
        else:
            # Fallback: Delete from temporary dict
            if hasattr(self._storage, '_oauth_clients'):
                self._storage._oauth_clients.pop(client_id, None)
        # Remove from config
        if hasattr(self._config, '_dynamic_clients'):
            self._config._dynamic_clients.pop(client_id, None)
        # Remove from registered_clients list
        self._config.registered_clients = [
            c for c in self._config.registered_clients 
            if c.get("client_id") != client_id
        ]
        logger.debug(f"Deleted OAuth client: {client_id}")

    def _generate_client_id(self) -> str:
        """Generate unique client_id."""
        # Generate random bytes (16 bytes = 128 bits)
        random_bytes = secrets.token_bytes(16)
        client_id = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return client_id

    def _generate_client_secret(self) -> str:
        """Generate client_secret."""
        # Generate random bytes (32 bytes = 256 bits)
        random_bytes = secrets.token_bytes(32)
        client_secret = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return client_secret

    def _generate_registration_access_token(self) -> str:
        """Generate registration access token."""
        # Generate random token (32 bytes = 256 bits)
        random_bytes = secrets.token_bytes(32)
        token = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return token

    def _generate_registration_client_uri(self, client_id: str) -> str:
        """
        Generate registration_client_uri for client.
        Args:
            client_id: Client identifier
        Returns:
            Registration client URI
        """
        if self._registration_endpoint_base:
            base = self._registration_endpoint_base.rstrip("/")
            return f"{base}/{client_id}"
        else:
            # Fallback: Use client_id as URI
            return f"urn:ietf:params:oauth:client_id:{client_id}"
