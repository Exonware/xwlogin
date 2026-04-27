#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/grants/device_code.py
Device Code Grant Implementation
OAuth 2.0 Device Authorization Grant (RFC 8628).
Used for devices without browsers or input capabilities.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from exonware.xwsystem import get_logger
from exonware.xwsystem.security.hazmat import secure_random
import base64
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError
from exonware.xwauth.identity.core.grants.base import ABaseGrant
logger = get_logger(__name__)


class DeviceCodeGrant(ABaseGrant):
    """
    Device Code grant type implementation.
    Used for devices without browsers or input capabilities (TVs, IoT devices, etc.).
    """
    @property

    def grant_type(self) -> GrantType:
        """Get grant type."""
        return GrantType.DEVICE_CODE

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Validate device code grant request.
        Args:
            request: Request parameters
        Returns:
            Validated request data
        Raises:
            XWOAuthError: If validation fails
        """
        grant_type = str(request.get("grant_type") or "")
        if grant_type == GrantType.DEVICE_CODE.value:
            return await self._validate_token_device_poll(request)
        client_id = request.get('client_id')
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request",
                error_description="client_id parameter is required"
            )
        self._validate_client(client_id, request.get('client_secret'))
        scopes = self._validate_scope(request.get('scope'))
        return {
            'client_id': client_id,
            'scopes': scopes,
        }

    async def _validate_token_device_poll(self, request: dict[str, Any]) -> dict[str, Any]:
        """RFC 8628 token request: grant_type=device_code + device_code (+ client auth)."""
        raw_code = request.get("device_code")
        if raw_code is None or not str(raw_code).strip():
            raise XWInvalidRequestError(
                "device_code is required",
                error_code="invalid_request",
                error_description="device_code parameter is required",
            )
        device_code_value = str(raw_code).strip()
        client_id = request.get("client_id")
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request",
                error_description="client_id parameter is required",
            )
        self._validate_client(client_id, request.get("client_secret"))
        stored = await self._storage.get_device_code(device_code_value)
        if not stored:
            raise XWOAuthError(
                "Invalid device code",
                error_code="invalid_grant",
                error_description="Unknown or expired device code",
            )
        if getattr(stored, "client_id", None) != client_id:
            raise XWOAuthError(
                "client_id does not match device flow",
                error_code="invalid_grant",
                error_description="client_id does not match the device authorization request",
            )
        return {
            "_device_token_poll": True,
            "_device_record": stored,
            "client_id": client_id,
        }

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Process device code grant request.
        Issues device code and user code for device authorization flow.
        Args:
            request: Validated request parameters
        Returns:
            Device authorization response
        """
        if request.get("_device_token_poll"):
            return await self._process_device_token_poll(request)
        # Generate device code and user code
        device_code = self._generate_device_code()
        user_code = self._generate_user_code()
        # Device verification URI
        verification_uri = request.get('verification_uri', '/oauth/device')
        verification_uri_complete = f"{verification_uri}?user_code={user_code}"
        # Create device code object
        now = datetime.now()
        expires_at = now + timedelta(minutes=15)
        # Create DeviceCode object that matches the protocol (format-agnostic)
        device_code_obj = SimpleNamespace(
            device_code=device_code,
            user_code=user_code,
            client_id=request['client_id'],
            scopes=request['scopes'],
            expires_at=expires_at,
            created_at=now,
            status='pending',
            user_id=None,
            attributes={}
        )
        # Store device code in storage (format-agnostic)
        await self._storage.save_device_code(device_code_obj)
        logger.debug(f"Generated and stored device code for client: {request['client_id']}")
        return {
            'device_code': device_code,
            'user_code': user_code,
            'verification_uri': verification_uri,
            'verification_uri_complete': verification_uri_complete,
            'expires_in': 900,  # 15 minutes
            'interval': 5,  # Polling interval in seconds
        }

    def _generate_device_code(self) -> str:
        """Generate device code."""
        random_bytes = secure_random(32)
        code = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return code

    def _generate_user_code(self) -> str:
        """
        Generate user code (8-character, case-insensitive, easy to type).
        Returns:
            User code string (e.g., "ABCD-EFGH")
        """
        import string
        import random
        # Generate 8 characters (A-Z, 0-9)
        chars = string.ascii_uppercase + string.digits
        code = ''.join(random.choice(chars) for _ in range(8))
        # Format as "XXXX-XXXX"
        return f"{code[:4]}-{code[4:]}"

    async def _process_device_token_poll(self, request: dict[str, Any]) -> dict[str, Any]:
        stored = request["_device_record"]
        expires_at = getattr(stored, "expires_at", None)
        now = datetime.now(timezone.utc)
        if expires_at is not None:
            exp = expires_at
            if getattr(exp, "tzinfo", None) is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now.timestamp() > exp.timestamp():
                raise XWOAuthError(
                    "Device code expired",
                    error_code="expired_token",
                    error_description="The device code has expired",
                )
        status = getattr(stored, "status", None) or "pending"
        if status == "pending":
            raise XWOAuthError(
                "Authorization pending",
                error_code="authorization_pending",
                error_description="The authorization request is still pending",
            )
        if status != "approved":
            raise XWOAuthError(
                "Invalid device code",
                error_code="invalid_grant",
                error_description="The device authorization is not in a valid state",
            )
        scopes = getattr(stored, "scopes", None) or []
        if isinstance(scopes, str):
            scopes = [s for s in scopes.split() if s]
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager:
            raise XWOAuthError(
                "Token service unavailable",
                error_code="server_error",
                error_description="Cannot complete device authorization without token service",
            )
        user_id = getattr(stored, "user_id", None)
        access_token = await token_manager.generate_access_token(
            user_id=user_id,
            client_id=request["client_id"],
            scopes=list(scopes) if scopes else [],
            session_id=None,
            additional_claims=None,
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self._config.access_token_lifetime,
            "scope": " ".join(scopes) if scopes else None,
        }
