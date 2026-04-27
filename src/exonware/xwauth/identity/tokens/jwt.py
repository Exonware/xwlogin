#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/tokens/jwt.py
JWT Token Management
JWT token generation and validation using xwsystem SecureHash.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from typing import Any
from datetime import datetime, timedelta, timezone
import time
import uuid
import jwt
from exonware.xwsystem import get_logger
from exonware.xwauth.identity.errors import XWTokenError, XWInvalidTokenError, XWExpiredTokenError
from exonware.xwauth.identity.defs import TokenType
from .revoked_jti_store import IRevokedJtiStore, InMemoryRevokedJtiStore
logger = get_logger(__name__)


def oidc_left_half_sha256_b64url(value: str) -> str:
    """
    OIDC ``at_hash`` / ``c_hash`` for JWS alg HS256 / RS256 (SHA-256 family).
    Delegates to federation helper so digest choice stays aligned with ``oidc_access_token_hash``.
    """
    from ..federation.oidc_access_token_hash import compute_at_hash

    return compute_at_hash(value, signing_alg="HS256")


class JWTTokenManager:
    """
    JWT token generation and validation.
    Uses PyJWT library with xwsystem SecureHash for signing.
    """

    def __init__(
        self,
        secret: str,
        algorithm: str = "HS256",
        issuer: str | None = None,
        audience: str | None = None,
        verify_secrets: list[str] | None = None,
        active_key_id: str | None = None,
        revoked_jti_store: IRevokedJtiStore | None = None,
    ):
        """
        Initialize JWT token manager.

        Args:
            secret: Secret key for signing tokens.
            algorithm: JWT algorithm (HS256, RS256, …).
            issuer: Token issuer (optional).
            audience: Token audience (optional).
            verify_secrets: Additional verification secrets (for key rotation).
            active_key_id: Optional ``kid`` header value.
            revoked_jti_store: Pluggable revoked-jti storage.
                ``None`` (default) → :class:`InMemoryRevokedJtiStore`, which is
                **single-node only** (revocations are not shared across
                processes and do not survive restart).
                **Production deployments MUST inject a distributed store**
                (e.g. :class:`RedisRevokedJtiStore`) or revocations will
                silently fail to propagate.

        Security note (jti revocation):
            Previous versions stored revoked jti values in a process-local
            ``set[str]``. That set did not survive process restart and was
            not visible across nodes, effectively making ``revoke_jti`` a
            no-op in multi-worker deployments. The store is now pluggable;
            see :mod:`exonware.xwauth.identity.tokens.revoked_jti_store`.
        """
        self._secret = secret
        self._verify_secrets = [secret] + [s for s in (verify_secrets or []) if s and s != secret]
        self._algorithm = algorithm
        self._issuer = issuer
        self._audience = audience
        self._active_key_id = active_key_id
        self._revoked_jti_store: IRevokedJtiStore = (
            revoked_jti_store if revoked_jti_store is not None else InMemoryRevokedJtiStore()
        )
        logger.debug(
            "JWTTokenManager initialized with revoked_jti_store=%s",
            type(self._revoked_jti_store).__name__,
        )

    def generate_token(
        self,
        user_id: str | None,
        client_id: str,
        scopes: list[str],
        expires_in: int = 3600,
        additional_claims: dict[str, Any] | None = None
    ) -> str:
        """
        Generate JWT access token.
        Args:
            user_id: User identifier (None for client credentials)
            client_id: Client identifier
            scopes: List of granted scopes
            expires_in: Token expiration in seconds
            additional_claims: Additional JWT claims
        Returns:
            JWT token string
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=expires_in)
        payload = {
            'sub': user_id or client_id,  # Subject
            'client_id': client_id,
            'scope': ' '.join(scopes),
            'iat': int(now.timestamp()),  # Issued at
            'exp': int(expires_at.timestamp()),  # Expiration
            'jti': str(uuid.uuid4()),
        }
        # Add issuer if configured
        if self._issuer:
            payload['iss'] = self._issuer
        # Add audience if configured
        if self._audience:
            payload['aud'] = self._audience
        # Add additional claims
        if additional_claims:
            payload.update(additional_claims)
        # Generate token
        headers = {}
        if self._active_key_id:
            headers["kid"] = self._active_key_id
        token = jwt.encode(payload, self._secret, algorithm=self._algorithm, headers=headers or None)
        logger.debug(f"Generated JWT token for client: {client_id}")
        return token

    def generate_id_token(
        self,
        *,
        sub: str,
        aud: str,
        issuer: str,
        nonce: str,
        expires_in: int = 3600,
        c_hash: str | None = None,
        at_hash: str | None = None,
    ) -> str:
        """Sign an OpenID Connect ID Token (JWT)."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=expires_in)
        payload: dict[str, Any] = {
            "sub": sub,
            "aud": aud,
            "nonce": nonce,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(uuid.uuid4()),
        }
        if issuer:
            payload["iss"] = issuer
        if c_hash:
            payload["c_hash"] = c_hash
        if at_hash:
            payload["at_hash"] = at_hash
        headers: dict[str, str] = {"typ": "JWT"}
        if self._active_key_id:
            headers["kid"] = self._active_key_id
        token = jwt.encode(
            payload, self._secret, algorithm=self._algorithm, headers=headers
        )
        logger.debug("Generated OIDC id_token")
        return token

    def validate_token(self, token: str) -> dict[str, Any]:
        """
        Validate JWT token.
        Args:
            token: JWT token string
        Returns:
            Decoded token payload
        Raises:
            XWInvalidTokenError: If token is invalid
            XWExpiredTokenError: If token is expired
        """
        try:
            # Decode and verify token
            last_error: Exception | None = None
            payload: dict[str, Any] | None = None
            for candidate_secret in self._verify_secrets:
                try:
                    payload = jwt.decode(
                        token,
                        candidate_secret,
                        algorithms=[self._algorithm],
                        issuer=self._issuer,
                        audience=self._audience
                    )
                    break
                except jwt.InvalidTokenError as exc:
                    last_error = exc
                    continue
            if payload is None:
                raise last_error or jwt.InvalidTokenError("Token verification failed")
            jti = payload.get("jti")
            if jti and self.is_jti_revoked(str(jti)):
                raise XWInvalidTokenError(
                    "JWT token has been revoked",
                    error_code="token_revoked"
                )
            return payload
        except jwt.ExpiredSignatureError:
            raise XWExpiredTokenError(
                "JWT token has expired",
                error_code="token_expired"
            )
        except jwt.InvalidTokenError as e:
            raise XWInvalidTokenError(
                f"Invalid JWT token: {e}",
                error_code="invalid_token"
            )

    def revoke_jti(self, jti: str, *, exp_ts: int | None = None) -> None:
        """Mark JWT ``jti`` as revoked via the injected revocation store.

        Args:
            jti: The ``jti`` claim value of the token to revoke.
            exp_ts: Optional original token ``exp`` (Unix seconds). When the
                store supports TTL pruning (e.g.
                :class:`RedisRevokedJtiStore`), the revocation record is
                auto-expired once the underlying token would have naturally
                expired — no cleanup worker required, no unbounded memory
                growth.

        Callers that have the decoded token payload are strongly encouraged
        to pass ``exp_ts=payload["exp"]`` so the store can prune efficiently.
        """
        if not jti:
            return
        self._revoked_jti_store.add(str(jti), exp_ts=exp_ts)

    def is_jti_revoked(self, jti: str) -> bool:
        """Check if JWT jti has been revoked (via the injected store)."""
        if not jti:
            return False
        return self._revoked_jti_store.contains(str(jti))

    def get_token_info(self, token: str) -> dict[str, Any]:
        """
        Get token information without validation (for introspection).
        Args:
            token: JWT token string
        Returns:
            Token information dictionary
        """
        try:
            # Decode without verification (for introspection)
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except jwt.InvalidTokenError as e:
            raise XWInvalidTokenError(
                f"Invalid JWT token: {e}",
                error_code="invalid_token"
            )

    def is_token_expired(self, token: str) -> bool:
        """
        Check if token is expired.
        Args:
            token: JWT token string
        Returns:
            True if expired, False otherwise
        """
        try:
            payload = self.get_token_info(token)
            exp = payload.get('exp')
            if exp:
                return datetime.now(timezone.utc).timestamp() > exp
            return False
        except XWInvalidTokenError:
            return True
