#!/usr/bin/env python3
"""
# exonware/xwlogin/providers/apple.py
Apple OAuth Provider
Apple Sign In OAuth 2.0 provider implementation.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.4
Generation Date: 20-Dec-2025
"""

from __future__ import annotations

from exonware.xwlogin.provider_connector import ABaseProvider, ProviderType
import time
from typing import Any, Optional

import jwt

from exonware.xwsystem import get_logger
from exonware.xwsystem.io.errors import SerializationError
from exonware.xwsystem.io.serialization.formats.text import json as xw_json
logger = get_logger(__name__)

# Apple: client_secret must be an ES256 JWT; exp must be <= ~6 months from iat.
APPLE_TOKEN_AUDIENCE = "https://appleid.apple.com"
APPLE_MAX_CLIENT_SECRET_TTL_SECONDS = 15777000


def parse_apple_authorization_user(user_json: str | bytes | bytearray | None) -> dict[str, Any]:
    """
    Parse Apple's `user` JSON from the authorization `form_post` callback.

    Apple only sends name/email in this payload on the **first** successful sign-in for that
    user+client pair; later authorizations omit it. Map to common OIDC-style keys for JIT / broker.
    """
    if user_json is None:
        return {}
    if isinstance(user_json, (bytes, bytearray)):
        try:
            user_json = user_json.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    if not str(user_json).strip():
        return {}
    try:
        raw = xw_json.loads(user_json)
    except (xw_json.JSONDecodeError, SerializationError, TypeError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    email = raw.get("email")
    if email is not None and str(email).strip():
        out["email"] = str(email).strip()
    name_obj = raw.get("name")
    if isinstance(name_obj, dict):
        fn = name_obj.get("firstName") or name_obj.get("first_name")
        mn = name_obj.get("middleName") or name_obj.get("middle_name")
        ln = name_obj.get("lastName") or name_obj.get("last_name")
        if fn is not None and str(fn).strip():
            out["given_name"] = str(fn).strip()
        if ln is not None and str(ln).strip():
            out["family_name"] = str(ln).strip()
        parts = [p for p in (fn, mn, ln) if p is not None and str(p).strip()]
        if parts:
            out["name"] = " ".join(str(p).strip() for p in parts)
    return out


def merge_apple_sign_in_profile(
    *,
    id_token_claims: dict[str, Any] | None,
    authorization_user_json: str | bytes | bytearray | None,
) -> dict[str, Any]:
    """
    Merge **validated** id_token claims with Apple's one-time ``user`` JSON (form_post).

    Same layering as typical SaaS IdPs: the signed id_token is authoritative for ``sub`` and
    stable claims; the first-login ``user`` object fills **display** fields when the token omits them.
    """
    merged: dict[str, Any] = dict(id_token_claims or {})
    extra = parse_apple_authorization_user(authorization_user_json)

    def _empty(v: Any) -> bool:
        return v is None or (isinstance(v, str) and not v.strip())

    if extra.get("email") and _empty(merged.get("email")):
        merged["email"] = extra["email"]
    for k in ("given_name", "family_name", "name"):
        if extra.get(k) and _empty(merged.get(k)):
            merged[k] = extra[k]
    return merged


def build_apple_client_secret_jwt(
    *,
    team_id: str,
    client_id: str,
    key_id: str,
    private_key_pem: str,
    ttl_seconds: int = 2592000,
) -> str:
    """
    Build the `client_secret` JWT required by Apple's token endpoint (ES256).

    Claims follow Apple's "Sign in with Apple" documentation: iss, iat, exp, aud, sub.
    """
    now = int(time.time())
    ttl = min(max(int(ttl_seconds), 60), APPLE_MAX_CLIENT_SECRET_TTL_SECONDS)
    payload: dict[str, Any] = {
        "iss": team_id,
        "iat": now,
        "exp": now + ttl,
        "aud": APPLE_TOKEN_AUDIENCE,
        "sub": client_id,
    }
    headers = {"kid": key_id, "alg": "ES256"}
    return jwt.encode(payload, private_key_pem.strip(), algorithm="ES256", headers=headers)


class AppleProvider(ABaseProvider):
    """Apple Sign In OAuth 2.0 provider."""
    AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize"
    TOKEN_URL = "https://appleid.apple.com/auth/token"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        team_id: str,
        key_id: str,
        private_key: str,
        *,
        apple_auto_sign_client_secret: bool = True,
        apple_client_secret_ttl_seconds: int = 2592000,
        apple_include_openid_scope: bool = False,
        **kwargs: Any,
    ):
        """
        Initialize Apple provider.
        Args:
            client_id: Apple Services ID (sub claim in client_secret JWT).
            client_secret: Fallback static secret when JWT signing is off or key load fails (tests / legacy).
            team_id: Apple team ID (iss claim).
            key_id: Key ID from Apple Developer (JWT header kid).
            private_key: PEM for the **EC private key** (P-256 / prime256v1) used to sign the client_secret JWT.
            apple_auto_sign_client_secret: When True, try ES256 JWT for token exchange when PEM looks valid.
            apple_client_secret_ttl_seconds: JWT lifetime (capped at Apple's maximum).
            apple_include_openid_scope: When True, prepend ``openid`` to scopes if missing (id_token + nonce).
            **kwargs: Additional configuration forwarded to ABaseProvider.
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=self.AUTHORIZATION_URL,
            token_url=self.TOKEN_URL,
            userinfo_url=None,  # Apple doesn't have userinfo endpoint
            **kwargs,
        )
        self._team_id = team_id
        self._key_id = key_id
        self._private_key = private_key
        self._apple_auto_sign = apple_auto_sign_client_secret
        self._apple_jwt_ttl = int(apple_client_secret_ttl_seconds)
        self._apple_include_openid_scope = bool(apple_include_openid_scope)

    async def get_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        state: str,
        scopes: Optional[list[str]] = None,
        nonce: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> str:
        merged = list(scopes or [])
        if self._apple_include_openid_scope:
            lower = {s.lower() for s in merged if isinstance(s, str)}
            if "openid" not in lower:
                merged = ["openid", *merged]
        return await super().get_authorization_url(
            client_id, redirect_uri, state, merged, nonce, code_verifier
        )

    @property

    def provider_name(self) -> str:
        """Get provider name."""
        return self.provider_type.value
    @property

    def provider_type(self) -> ProviderType:
        """Get provider type."""
        return ProviderType.APPLE

    @property
    def oidc_issuer(self) -> str | None:
        """Apple Sign in uses OIDC; primary user claims arrive via id_token (no userinfo URL)."""
        return "https://appleid.apple.com"

    @property
    def oidc_jwks_uri(self) -> str | None:
        return "https://appleid.apple.com/auth/keys"

    def _token_exchange_client_secret(self) -> str:
        if not self._apple_auto_sign:
            return self._client_secret
        pem = (self._private_key or "").strip()
        if "BEGIN" not in pem or "PRIVATE KEY" not in pem:
            return self._client_secret
        try:
            return build_apple_client_secret_jwt(
                team_id=self._team_id,
                client_id=self._client_id,
                key_id=self._key_id,
                private_key_pem=pem,
                ttl_seconds=self._apple_jwt_ttl,
            )
        except Exception as e:
            logger.warning(
                "Apple ES256 client_secret JWT could not be built (%s); using static client_secret",
                e,
            )
            return self._client_secret

    def _get_authorization_params(self) -> dict[str, Any]:
        """Get Apple-specific authorization parameters."""
        return {
            'response_mode': 'form_post',  # Apple requires form_post
        }

    async def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Get user information from Apple.
        Note: Apple doesn't provide a userinfo endpoint.
        User info is included in the ID token during authorization.
        Args:
            access_token: Access token
        Returns:
            User information dictionary (limited)
        """
        # Apple doesn't have userinfo endpoint
        # User info is in ID token during authorization
        return {
            'id': None,  # Apple doesn't provide user ID via access token
            'email': None,
        }
