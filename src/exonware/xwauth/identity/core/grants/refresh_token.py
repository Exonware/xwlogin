#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/grants/refresh_token.py
Refresh Token Grant Implementation
OAuth 2.0 Refresh Token grant type (RFC 6749 Section 6).
Used to obtain new access tokens using refresh tokens.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import XWOAuthError, XWInvalidRequestError, XWInvalidTokenError
from exonware.xwauth.identity.core.grants.base import ABaseGrant
logger = get_logger(__name__)


def _pick_refresh_field(token_data: dict[str, Any], *names: str) -> Any:
    """Read a field from refresh token row or nested attributes (B2B metadata round-trip)."""
    attrs = token_data.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}
    for name in names:
        for src in (token_data, attrs):
            v = src.get(name)
            if v is not None and v not in ("", []):
                return v
    return None


def _refresh_metadata_for_issue(token_data: dict[str, Any]) -> dict[str, Any] | None:
    keys = (
        "tenant_id",
        "tid",
        "org_id",
        "organization_id",
        "project_id",
        "application_id",
        "session_id",
        "roles",
        "aal",
        "amr",
    )
    out: dict[str, Any] = {}
    for k in keys:
        v = _pick_refresh_field(token_data, k)
        if v is not None and v not in ("", []):
            out[k] = v
    return out or None


class RefreshTokenGrant(ABaseGrant):
    """
    Refresh Token grant type implementation.
    Used to obtain new access tokens using refresh tokens.
    """
    @property

    def grant_type(self) -> GrantType:
        """Get grant type."""
        return GrantType.REFRESH_TOKEN

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Validate refresh token grant request.
        Args:
            request: Request parameters
        Returns:
            Validated request data
        Raises:
            XWOAuthError: If validation fails
        """
        # Required parameters
        client_id = request.get('client_id')
        refresh_token = request.get('refresh_token')
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request",
                error_description="client_id parameter is required"
            )
        if not refresh_token:
            raise XWInvalidRequestError(
                "refresh_token is required",
                error_code="invalid_request",
                error_description="refresh_token parameter is required"
            )
        # Validate client
        client_secret = request.get('client_secret')
        self._validate_client(client_id, client_secret)
        # Validate refresh token from storage
        token_data = await self._get_refresh_token(refresh_token)
        if not token_data:
            raise XWInvalidTokenError(
                "Invalid refresh token",
                error_code="invalid_grant",
                error_description="The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI used in the authorization request"
            )
        # Validate token belongs to client
        if token_data.get('client_id') != client_id:
            raise XWInvalidTokenError(
                "Refresh token does not belong to client",
                error_code="invalid_grant",
                error_description="Refresh token client mismatch"
            )
        # Validate scopes (optional - can request subset of original scopes)
        requested_scopes = request.get('scope')
        original_scopes = token_data.get('scopes', [])
        scopes = self._validate_scope(requested_scopes, original_scopes) if requested_scopes else original_scopes
        return {
            'client_id': client_id,
            'refresh_token': refresh_token,
            'scopes': scopes,
            'token_data': token_data,
        }

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Process refresh token grant request.
        Issues new access token (and optionally new refresh token) using refresh token.
        Args:
            request: Validated request parameters
        Returns:
            Token response dictionary
        """
        logger.debug(f"Processing refresh token grant for client: {request['client_id']}")
        # Get token manager from auth instance
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager:
            raise XWOAuthError(
                "Token manager not available",
                error_code="server_error",
                error_description="Token manager is not initialized"
            )
        # Get refresh token data (already validated in validate_request)
        token_data = request['token_data']
        user_id = token_data.get('user_id')
        client_id = request['client_id']
        scopes = request['scopes']
        refresh_token = request['refresh_token']
        session_id = token_data.get("session_id")
        token_claims = {
            "tenant_id": token_data.get("tenant_id") or token_data.get("tid"),
            "tid": token_data.get("tid") or token_data.get("tenant_id"),
            "org_id": token_data.get("org_id") or token_data.get("organization_id"),
            "organization_id": token_data.get("organization_id") or token_data.get("org_id"),
            "project_id": token_data.get("project_id") or token_data.get("application_id"),
            "roles": token_data.get("roles", []),
            "aal": token_data.get("aal"),
            "amr": token_data.get("amr", []),
        }
        token_claims = {k: v for k, v in token_claims.items() if v not in (None, [], "")}
        # Check if token rotation is enabled
        enable_rotation = getattr(self._config, 'refresh_token_rotation', True)
        # Revoke old refresh token if rotation is enabled
        if enable_rotation:
            # Get refresh token manager from token manager
            refresh_manager = getattr(token_manager, '_refresh_manager', None)
            if refresh_manager:
                # Rotate refresh token (revokes old, generates new)
                try:
                    new_refresh_token = await refresh_manager.rotate_refresh_token(refresh_token)
                except Exception as e:
                    logger.warning(f"Failed to rotate refresh token: {e}")
                    # If rotation fails, revoke old token anyway
                    await refresh_manager.revoke_refresh_token(refresh_token)
                    new_refresh_token = await token_manager.generate_refresh_token(
                        user_id=user_id,
                        client_id=client_id,
                        refresh_metadata=_refresh_metadata_for_issue(token_data),
                    )
            else:
                # Fallback: revoke old token and generate new one
                await token_manager.revoke_token(refresh_token, token_type_hint='refresh_token')
                new_refresh_token = await token_manager.generate_refresh_token(
                    user_id=user_id,
                    client_id=client_id,
                    refresh_metadata=_refresh_metadata_for_issue(token_data),
                )
        else:
            # No rotation: keep same refresh token
            new_refresh_token = None
        # Generate new access token
        access_token = await token_manager.generate_access_token(
            user_id=user_id,
            client_id=client_id,
            scopes=scopes,
            session_id=session_id,
            additional_claims=token_claims or None,
        )
        audit_logger = getattr(self._auth, "_safe_audit_log", None)
        if callable(audit_logger):
            await audit_logger(
                event_type="token.issued",
                user_id=user_id,
                attributes={"grant_type": "refresh_token", "client_id": client_id},
                tenant_id=token_claims.get("tenant_id") or token_claims.get("tid"),
                org_id=token_claims.get("org_id") or token_claims.get("organization_id"),
                project_id=token_claims.get("project_id"),
            )
        response = {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': self._config.access_token_lifetime,
            'scope': ' '.join(scopes) if scopes else None,
        }
        # Include new refresh token if rotation is enabled
        if enable_rotation and new_refresh_token:
            response['refresh_token'] = new_refresh_token
        return response

    async def _get_refresh_token(self, refresh_token: str) -> dict[str, Any] | None:
        """
        Get refresh token data from storage.
        Args:
            refresh_token: Refresh token string
        Returns:
            Token data dictionary or None
        """
        # Get token manager from auth instance
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager:
            return None
        # Get refresh token manager
        refresh_manager = getattr(token_manager, '_refresh_manager', None)
        if not refresh_manager:
            return None
        # Get refresh token data
        try:
            token_data = await refresh_manager.get_refresh_token(refresh_token)
            return token_data
        except Exception as e:
            logger.debug(f"Failed to get refresh token: {e}")
            return None
