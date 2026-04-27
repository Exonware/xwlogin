#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/tokens/manager.py
Token Manager Orchestrator
Orchestrates JWT, opaque, and refresh token management.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from datetime import datetime, timedelta, timezone
import uuid
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.base import ABaseAuth
from exonware.xwauth.identity.defs import TokenType
from exonware.xwauth.identity.errors import XWTokenError
from exonware.xwauth.identity.contracts import ITokenManager
from exonware.xwauth.identity.base import ABaseTokenManager
from ..federation.oidc_access_token_hash import compute_at_hash, compute_c_hash
from .jwt import JWTTokenManager
from .oidc_id_token_signing import resolve_id_token_signing, sign_id_token_jwt
from .opaque import OpaqueTokenManager
from .refresh import RefreshTokenManager
from .introspection import TokenIntrospection
from .revocation import TokenRevocation
logger = get_logger(__name__)


class TokenManager(ABaseTokenManager, ITokenManager):
    """
    Token manager orchestrator.
    Manages JWT, opaque, and refresh tokens.
    """

    def __init__(self, auth: ABaseAuth, use_jwt: bool = True):
        """
        Initialize token manager.
        Args:
            auth: XWAuth instance
            use_jwt: Use JWT tokens (True) or opaque tokens (False)
        """
        super().__init__(auth.storage if hasattr(auth, 'storage') else None)
        self._auth = auth
        self._config = auth.config
        self._use_jwt = use_jwt
        # Initialize token managers
        if use_jwt:
            self._jwt_manager = JWTTokenManager(
                secret=self._config.jwt_secret,
                algorithm=self._config.jwt_algorithm
            )
        else:
            self._jwt_manager = None
        self._opaque_manager = OpaqueTokenManager(self._storage)
        self._refresh_manager = RefreshTokenManager(self._storage)
        # Initialize introspection and revocation
        self._introspection = TokenIntrospection(
            jwt_manager=self._jwt_manager,
            opaque_manager=self._opaque_manager
        )
        self._revocation = TokenRevocation(
            opaque_manager=self._opaque_manager,
            refresh_manager=self._refresh_manager,
            jwt_manager=self._jwt_manager
        )
        logger.info("TokenManager initialized")

    async def generate_access_token(
        self,
        user_id: str | None,
        client_id: str,
        scopes: list[str],
        session_id: str | None = None,
        additional_claims: dict[str, Any] | None = None
    ) -> str:
        """
        Generate access token.
        Args:
            user_id: User identifier (None for client credentials)
            client_id: Client identifier
            scopes: List of scopes
            session_id: Optional session identifier to include in token claims
            additional_claims: Optional additional claims (e.g. tenant_id, aal, roles)
        Returns:
            Access token string
        """
        if self._use_jwt and self._jwt_manager:
            # Generate JWT token with optional session_id claim
            token_claims = dict(additional_claims or {})
            if session_id:
                token_claims['session_id'] = session_id
            token = self._jwt_manager.generate_token(
                user_id=user_id,
                client_id=client_id,
                scopes=scopes,
                expires_in=self._config.access_token_lifetime,
                additional_claims=token_claims if token_claims else None
            )
        else:
            # Generate opaque token with optional session_id in attributes
            token = self._opaque_manager.generate_token()
            additional_data = dict(additional_claims or {})
            if session_id:
                additional_data['session_id'] = session_id
            await self._opaque_manager.save_token(
                token=token,
                user_id=user_id,
                client_id=client_id,
                scopes=scopes,
                expires_in=self._config.access_token_lifetime,
                additional_data=additional_data if additional_data else None
            )
        logger.debug(f"Generated access token for client: {client_id}")
        return token

    async def generate_id_token(
        self,
        *,
        sub: str,
        client_id: str,
        issuer: str,
        nonce: str,
        expires_in: int | None = None,
        authorization_code: str | None = None,
        access_token_for_hash: str | None = None,
    ) -> str:
        """
        Issue an OIDC ID Token (signed JWT). Used for hybrid authorize responses.

        ``c_hash`` / ``at_hash`` are derived from *authorization_code* / *access_token_for_hash*
        using the digest family implied by the id_token JWS algorithm (OIDC Core).
        """
        id_ttl = getattr(self._config, "oidc_id_token_lifetime_seconds", None)
        exp_sec = (
            int(expires_in)
            if expires_in is not None
            else (
                int(id_ttl)
                if id_ttl is not None
                else int(self._config.access_token_lifetime)
            )
        )
        material = resolve_id_token_signing(self._config)
        alg = material.algorithm
        c_hash_val = (
            compute_c_hash(authorization_code, signing_alg=alg)
            if authorization_code
            else None
        )
        at_hash_val = (
            compute_at_hash(access_token_for_hash, signing_alg=alg)
            if access_token_for_hash
            else None
        )
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=exp_sec)
        payload: dict[str, Any] = {
            "sub": sub,
            "aud": client_id,
            "nonce": nonce,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(uuid.uuid4()),
        }
        if issuer:
            payload["iss"] = issuer
        if c_hash_val:
            payload["c_hash"] = c_hash_val
        if at_hash_val:
            payload["at_hash"] = at_hash_val
        return sign_id_token_jwt(payload, material)

    async def generate_refresh_token(
        self,
        user_id: str | None,
        client_id: str,
        access_token: str | None = None,
        *,
        refresh_metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate refresh token.
        Args:
            user_id: User identifier
            client_id: Client identifier
            access_token: Optional access token to link with (for opaque tokens)
            refresh_metadata: Tenancy/session fields stored on the refresh token (org_id, tenant_id, etc.)
        Returns:
            Refresh token string
        """
        refresh_token = self._refresh_manager.generate_refresh_token()
        # Get access token ID (for opaque tokens) if access_token provided
        access_token_id = None
        if access_token and not self._use_jwt:
            # For opaque tokens, get the token ID from storage
            try:
                token_data = await self._opaque_manager.get_token(access_token)
                if token_data:
                    access_token_id = token_data.get('token_id')
            except Exception as e:
                logger.debug(f"Could not get access token ID: {e}")
                # Continue without linking - refresh token can work independently
        meta = {k: v for k, v in (refresh_metadata or {}).items() if v not in (None, "", [])}
        await self._refresh_manager.save_refresh_token(
            refresh_token=refresh_token,
            access_token_id=access_token_id,
            user_id=user_id,
            client_id=client_id,
            expires_in=self._config.refresh_token_lifetime,
            additional_data=meta if meta else None,
        )
        logger.debug(f"Generated refresh token for client: {client_id}")
        return refresh_token

    async def validate_token(self, token: str) -> bool:
        """
        Validate token.
        Args:
            token: Token string
        Returns:
            True if valid, False otherwise
        """
        try:
            if self._use_jwt and self._jwt_manager:
                self._jwt_manager.validate_token(token)
            else:
                await self._opaque_manager.validate_token(token)
            return True
        except Exception:
            return False

    async def revoke_token(
        self, token: str, token_type_hint: str | None = None
    ) -> None:
        """
        Revoke token (RFC 7009).
        Args:
            token: Token string to revoke
            token_type_hint: Optional "access_token" or "refresh_token"
        """
        await self._revocation.revoke(token, token_type_hint=token_type_hint)

    async def introspect_token(self, token: str) -> dict[str, Any]:
        """
        Introspect token (RFC 7662).
        Args:
            token: Token to introspect
        Returns:
            Introspection response
        """
        return await self._introspection.introspect(token)
