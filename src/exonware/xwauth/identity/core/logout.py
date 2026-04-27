#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/logout.py
OIDC Logout Implementation (OpenID Connect Session Management)
Implements RP-initiated logout with front-channel and back-channel logout support.
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


class LogoutManager:
    """
    Manager for OIDC logout (RP-initiated logout).
    Handles logout token generation and session termination.
    """

    def __init__(self, auth: ABaseAuth):
        """
        Initialize logout manager.
        Args:
            auth: XWAuth instance
        """
        self._auth = auth
        self._config = auth.config
        self._storage = auth.storage
        logger.debug("LogoutManager initialized")

    async def logout(
        self,
        id_token_hint: Optional[str] = None,
        post_logout_redirect_uri: Optional[str] = None,
        state: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Process RP-initiated logout (OIDC Session Management).
        Args:
            id_token_hint: ID token hint (optional, helps identify session)
            post_logout_redirect_uri: URI to redirect after logout
            state: State parameter for CSRF protection
            client_id: Client identifier (optional)
        Returns:
            Logout response with redirect URI or confirmation
        """
        # Extract user info from id_token_hint if provided
        user_id = None
        session_id = None
        if id_token_hint:
            try:
                # Decode ID token using JWT token manager
                token_manager = getattr(self._auth, "_token_manager", None)
                if token_manager and hasattr(token_manager, '_jwt_manager') and token_manager._jwt_manager:
                    # Decode JWT token
                    payload = token_manager._jwt_manager.validate_token(id_token_hint)
                    user_id = payload.get("sub") or payload.get("user_id")
                    session_id = payload.get("sid")  # Session ID from token
                else:
                    # Fallback to introspection
                    introspect_result = await self._auth.introspect_token(id_token_hint)
                    if introspect_result.get("active"):
                        user_id = introspect_result.get("sub") or introspect_result.get("user_id")
                        session_id = introspect_result.get("sid")
            except Exception as e:
                logger.debug(f"Could not extract user from id_token_hint: {e}")
        # Revoke all tokens and sessions for the user
        if user_id:
            # Revoke all user sessions
            session_manager = getattr(self._auth, "_session_manager", None)
            if session_manager:
                # Get all user sessions
                user_sessions = await session_manager.list_user_sessions(user_id)
                for session_data in user_sessions:
                    await session_manager.revoke_session(session_data['id'])
                logger.debug(f"Revoked all sessions for user: {user_id}")
            # Revoke all user tokens (access and refresh tokens)
            # Note: For JWT tokens, we can't revoke them directly, but we can:
            # 1. Add them to a revocation list (if using token introspection)
            # 2. Revoke refresh tokens (which are stored)
            token_manager = getattr(self._auth, "_token_manager", None)
            if token_manager:
                # Revoke refresh tokens for user
                refresh_manager = getattr(token_manager, '_refresh_manager', None)
                if refresh_manager:
                    # List and revoke all refresh tokens for user
                    # This would require storage method to list tokens by user_id
                    # For now, we'll rely on token expiration and session revocation
                    logger.debug(f"Token revocation for user {user_id} - tokens will expire naturally")
            logger.debug(f"Logged out user: {user_id}")
        # Generate logout token for back-channel logout (if needed)
        logout_token = None
        if client_id:
            # Check if client has back-channel logout URI
            client = self._config.get_registered_client(client_id)
            if client and client.get("backchannel_logout_uri"):
                logout_token = await self._generate_logout_token(user_id, client_id)
                # Send back-channel logout notification
                await self._send_backchannel_logout(
                    client.get("backchannel_logout_uri"),
                    logout_token
                )
        # Prepare response
        response: dict[str, Any] = {
            "logged_out": True,
        }
        # Redirect if post_logout_redirect_uri provided
        if post_logout_redirect_uri:
            # Validate redirect URI
            if client_id:
                client = self._config.get_registered_client(client_id)
                if client:
                    registered_uris = client.get("post_logout_redirect_uris", [])
                    if registered_uris and post_logout_redirect_uri not in registered_uris:
                        raise XWInvalidRequestError(
                            "Invalid post_logout_redirect_uri",
                            error_code="invalid_request",
                            error_description="post_logout_redirect_uri not registered for client"
                        )
            redirect_url = post_logout_redirect_uri
            if state:
                separator = "&" if "?" in redirect_url else "?"
                redirect_url = f"{redirect_url}{separator}state={state}"
            response["redirect_uri"] = redirect_url
        return response

    async def _generate_logout_token(self, user_id: Optional[str], client_id: str) -> str:
        """
        Generate logout token (JWT) for back-channel logout.
        Args:
            user_id: User identifier
            client_id: Client identifier
        Returns:
            Logout token (JWT)
        """
        # Generate logout token using JWT
        # Logout token is a JWT with specific claims (OIDC Session Management)
        from exonware.xwauth.identity.tokens.jwt import JWTTokenManager
        jwt_manager = JWTTokenManager(
            secret=self._config.jwt_secret,
            algorithm=self._config.jwt_algorithm
        )
        now = int(datetime.now().timestamp())
        claims = {
            "iss": getattr(self._config, "issuer", "xwauth"),
            "aud": client_id,
            "iat": now,
            "jti": self._generate_jti(),
            "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
            }
        }
        if user_id:
            claims["sub"] = user_id
        logout_token = jwt_manager.generate_token(claims, expires_in=60)  # 60 second expiry
        return logout_token

    def _generate_jti(self) -> str:
        """Generate JWT ID (jti)."""
        random_bytes = secrets.token_bytes(16)
        jti = base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        return jti

    async def _send_backchannel_logout(self, logout_uri: str, logout_token: str) -> None:
        """
        Send back-channel logout notification to client.
        Args:
            logout_uri: Client's back-channel logout URI
            logout_token: Logout token (JWT)
        """
        try:
            import httpx
            # Send POST request with logout_token
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    logout_uri,
                    data={"logout_token": logout_token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                response.raise_for_status()
                logger.debug(f"Sent back-channel logout to {logout_uri}")
        except ImportError:
            logger.warning("httpx not installed. Back-channel logout unavailable. Install with: pip install httpx")
        except Exception as e:
            logger.error(f"Failed to send back-channel logout: {e}")
            # Don't fail logout if back-channel notification fails
