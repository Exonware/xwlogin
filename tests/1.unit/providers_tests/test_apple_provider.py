#!/usr/bin/env python3
"""
#exonware/xwauth/tests/1.unit/providers_tests/test_apple_provider.py
Unit tests for Apple OAuth provider.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.0
Generation Date: 20-Dec-2025
"""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from urllib.parse import parse_qs, urlparse
from unittest.mock import AsyncMock, Mock

from exonware.xwlogin.provider_connector import ProviderType, XWProviderConnectionError
from exonware.xwlogin.providers.apple import (
    APPLE_MAX_CLIENT_SECRET_TTL_SECONDS,
    APPLE_TOKEN_AUDIENCE,
    AppleProvider,
    build_apple_client_secret_jwt,
    merge_apple_sign_in_profile,
    parse_apple_authorization_user,
)

pytestmark = pytest.mark.xwlogin_unit


class TestAppleProvider:
    """Test AppleProvider implementation."""
    @pytest.fixture

    def provider(self):
        """Create AppleProvider instance."""
        return AppleProvider(
            client_id="test_apple_client",
            client_secret="test_apple_secret",
            team_id="TEST_TEAM_ID",
            key_id="TEST_KEY_ID",
            private_key="-----BEGIN PRIVATE KEY-----\nTEST_KEY\n-----END PRIVATE KEY-----"
        )

    def test_provider_name(self, provider):
        """Test provider name."""
        assert provider.provider_name == "apple"

    def test_provider_type(self, provider):
        """Test provider type."""
        assert provider.provider_type == ProviderType.APPLE

    def test_oidc_issuer_and_jwks_for_id_token_validation(self, provider):
        """Federation broker uses issuer + JWKS to validate Apple id_tokens."""
        assert provider.oidc_issuer == "https://appleid.apple.com"
        assert provider.oidc_jwks_uri == "https://appleid.apple.com/auth/keys"

    @pytest.mark.asyncio

    async def test_get_authorization_url(self, provider):
        """Test authorization URL generation."""
        url = await provider.get_authorization_url(
            client_id="test_apple_client",
            redirect_uri="https://example.com/callback",
            state="test_state",
            scopes=["name", "email"]
        )
        assert url is not None
        parsed = urlparse(url)
        assert parsed.netloc == "appleid.apple.com"
        assert parsed.path == "/auth/authorize"
        query = parse_qs(parsed.query)
        assert query["client_id"] == ["test_apple_client"]
        assert query["redirect_uri"] == ["https://example.com/callback"]
        assert query["state"] == ["test_state"]
        assert query["response_type"] == ["code"]
        assert query["scope"] == ["name email"]
        assert query["response_mode"] == ["form_post"]

    @pytest.mark.asyncio
    async def test_get_authorization_url_includes_pkce_s256(self, provider):
        """Apple supports PKCE; verifier produces code_challenge + method on auth URL."""
        url = await provider.get_authorization_url(
            client_id="test_apple_client",
            redirect_uri="https://example.com/callback",
            state="test_state",
            scopes=["openid", "email"],
            code_verifier="d" * 43,
        )
        query = parse_qs(urlparse(url).query)
        assert "code_challenge" in query
        assert query["code_challenge_method"] == ["S256"]

    @pytest.mark.asyncio
    async def test_exchange_code_for_token(self, provider):
        """Test Apple token exchange uses deterministic async mock."""
        provider._async_http_client = AsyncMock()
        provider._async_http_client.post.return_value = Mock(
            status_code=200,
            json=lambda: {"access_token": "apple-at", "id_token": "id-token"},
        )
        response = await provider.exchange_code_for_token(
            code="test_code",
            redirect_uri="https://example.com/callback",
            code_verifier="v" * 43,
        )
        assert response == {"access_token": "apple-at", "id_token": "id-token"}
        posted = provider._async_http_client.post.await_args
        data = posted.kwargs.get("data")
        assert isinstance(data, dict)
        assert data.get("code_verifier") == "v" * 43

    @pytest.mark.asyncio
    async def test_get_user_info_returns_stub_shape(self, provider):
        """Test Apple get_user_info returns documented stub payload."""
        user_info = await provider.get_user_info("test_access_token")
        assert user_info == {"id": None, "email": None}

    def test_parse_apple_authorization_user_first_signin_payload(self) -> None:
        raw = (
            '{"name":{"firstName":"A","lastName":"B"},"email":"a@privaterelay.appleid.com"}'
        )
        claims = parse_apple_authorization_user(raw)
        assert claims["email"] == "a@privaterelay.appleid.com"
        assert claims["given_name"] == "A"
        assert claims["family_name"] == "B"
        assert claims["name"] == "A B"

    def test_parse_apple_authorization_user_invalid_returns_empty(self) -> None:
        assert parse_apple_authorization_user(None) == {}
        assert parse_apple_authorization_user("") == {}
        assert parse_apple_authorization_user("not-json") == {}

    @pytest.mark.asyncio
    async def test_apple_include_openid_scope_prepends_openid(self) -> None:
        p = AppleProvider(
            client_id="test_apple_client",
            client_secret="x",
            team_id="T",
            key_id="K",
            private_key="-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----",
            apple_include_openid_scope=True,
        )
        url = await p.get_authorization_url(
            client_id="test_apple_client",
            redirect_uri="https://example.com/callback",
            state="s",
            scopes=["name", "email"],
        )
        q = parse_qs(urlparse(url).query)
        assert q["scope"] == ["openid name email"]
        assert "nonce" not in q

    @pytest.mark.asyncio
    async def test_apple_include_openid_scope_with_nonce_when_openid_present(self) -> None:
        p = AppleProvider(
            client_id="cid",
            client_secret="x",
            team_id="T",
            key_id="K",
            private_key="-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----",
            apple_include_openid_scope=True,
        )
        url = await p.get_authorization_url(
            client_id="cid",
            redirect_uri="https://example.com/cb",
            state="s",
            scopes=["email"],
            nonce="n1",
        )
        q = parse_qs(urlparse(url).query)
        assert "openid" in q["scope"][0]
        assert q.get("nonce") == ["n1"]

    @pytest.mark.asyncio
    async def test_exchange_code_for_token_surfaces_oauth_error_json(self, provider) -> None:
        provider._async_http_client = AsyncMock()
        provider._async_http_client.post.return_value = Mock(
            status_code=400,
            text='{"error":"invalid_grant","error_description":"code expired"}',
            json=lambda: {
                "error": "invalid_grant",
                "error_description": "code expired",
            },
        )
        with pytest.raises(XWProviderConnectionError) as ei:
            await provider.exchange_code_for_token(
                code="bad",
                redirect_uri="https://example.com/callback",
                code_verifier="v" * 43,
            )
        assert "invalid_grant" in str(ei.value)
        assert "code expired" in str(ei.value)

    def test_build_apple_client_secret_jwt_claims(self):
        """Apple token endpoint expects ES256 JWT with iss/aud/sub per Apple documentation."""
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        token = build_apple_client_secret_jwt(
            team_id="T1",
            client_id="com.example.svc",
            key_id="K1",
            private_key_pem=pem,
            ttl_seconds=3600,
        )
        parts = token.split(".")
        assert len(parts) == 3
        pad = "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + pad))
        assert header["alg"] == "ES256"
        assert header["kid"] == "K1"
        pad2 = "=" * (-len(parts[1]) % 4)
        body = json.loads(base64.urlsafe_b64decode(parts[1] + pad2))
        assert body["iss"] == "T1"
        assert body["sub"] == "com.example.svc"
        assert body["aud"] == APPLE_TOKEN_AUDIENCE

    def test_build_apple_client_secret_jwt_caps_exp_delta(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        token = build_apple_client_secret_jwt(
            team_id="T",
            client_id="cid",
            key_id="K",
            private_key_pem=pem,
            ttl_seconds=APPLE_MAX_CLIENT_SECRET_TTL_SECONDS + 999999,
        )
        parts = token.split(".")
        pad2 = "=" * (-len(parts[1]) % 4)
        body = json.loads(base64.urlsafe_b64decode(parts[1] + pad2))
        assert body["exp"] - body["iat"] <= APPLE_MAX_CLIENT_SECRET_TTL_SECONDS

    @pytest.mark.asyncio
    async def test_exchange_code_falls_back_to_static_secret_when_pem_invalid(self) -> None:
        p = AppleProvider(
            client_id="cid",
            client_secret="static-fallback",
            team_id="T",
            key_id="K",
            private_key="not-a-valid-pem",
            apple_auto_sign_client_secret=True,
        )
        p._async_http_client = AsyncMock()
        p._async_http_client.post.return_value = Mock(
            status_code=200,
            json=lambda: {"access_token": "at"},
        )
        await p.exchange_code_for_token(
            code="c",
            redirect_uri="https://example.com/callback",
            code_verifier="v" * 43,
        )
        secret = p._async_http_client.post.await_args.kwargs.get("data", {}).get("client_secret")
        assert secret == "static-fallback"

    @pytest.mark.asyncio
    async def test_exchange_code_sends_jwt_client_secret_with_valid_ec_key(self):
        """With a real P-256 key, token exchange uses a JWT client_secret (not the static string)."""
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        provider = AppleProvider(
            client_id="com.example.svc",
            client_secret="must-not-use-this-when-jwt-works",
            team_id="T9",
            key_id="K9",
            private_key=pem,
        )
        provider._async_http_client = AsyncMock()
        provider._async_http_client.post.return_value = Mock(
            status_code=200,
            json=lambda: {"access_token": "at", "id_token": "it"},
        )
        await provider.exchange_code_for_token(
            code="c",
            redirect_uri="https://example.com/callback",
            code_verifier="v" * 43,
        )
        posted = provider._async_http_client.post.await_args
        secret = posted.kwargs.get("data", {}).get("client_secret")
        assert secret != "must-not-use-this-when-jwt-works"
        assert len(str(secret).split(".")) == 3
