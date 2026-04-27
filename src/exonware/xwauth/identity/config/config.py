#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/config/config.py
XWAuth Configuration
Configuration management for xwauth, reusing xwsystem AConfigBase patterns.
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
Version: 0.0.1.11
Generation Date: 20-Dec-2025
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Any
from pathlib import Path
from exonware.xwsystem.config.base import AConfigBase
from exonware.xwauth.identity.defs import PasswordHashAlgorithm
from exonware.xwauth.identity.errors import XWConfigError

if TYPE_CHECKING:
    from ..storage.interface import IStorageProvider  # noqa: F401
# Default test client for E2E/app when registered_clients not set. Do not use in production.
DEFAULT_TEST_CLIENTS: list[dict[str, Any]] = [
    {
        "client_id": "test",
        "client_secret": "secret",
        "redirect_uris": [
            "https://example.com/cb",
            "http://localhost:8000/cb",
            "http://127.0.0.1:8000/cb",
            "http://testserver/cb",
        ],
    },
]
_DEFAULT_TEST_CLIENT_ID = "test"
_DEFAULT_TEST_CLIENT_SECRET = "secret"

PROTOCOL_PROFILE_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "A": {
        "min_conformance": 98.0,
        "required_flags": [
            "oauth21_compliant",
            "require_exact_redirect_uri",
            "require_state_in_authorize",
            "pkce_s256_only",
        ],
    },
    "B": {
        "min_conformance": 99.0,
        "required_flags": [
            "oauth21_compliant",
            "require_exact_redirect_uri",
            "require_state_in_authorize",
            "pkce_s256_only",
            "fapi20_compliant",
            "fapi20_require_par",
        ],
    },
    "C": {
        "min_conformance": 99.5,
        "required_flags": [
            "oauth21_compliant",
            "require_exact_redirect_uri",
            "require_state_in_authorize",
            "pkce_s256_only",
            "fapi20_compliant",
            "fapi20_require_par",
            "fapi20_require_jar",
            "fapi20_require_dpop_or_mtls",
            "saml_strict_validation",
        ],
    },
}
@dataclass

class XWAuthConfig:
    """
    Main configuration for xwauth.
    Following GUIDE_DEV.md: Reuse xwsystem components where possible.
    """
    # Core configuration
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    # OpenID Connect: issuer URL for id_token `iss` (required for compliant hybrid/code+id_token responses).
    oidc_issuer: Optional[str] = None
    # OIDC id_token lifetime (seconds). When unset, uses access_token_lifetime.
    oidc_id_token_lifetime_seconds: Optional[int] = None
    # Optional PEM PKCS8 private key for asymmetric id_token signing (RS256 / ES256 / ES384 / ES512).
    oidc_id_token_signing_pem: Optional[str] = None
    # JWS ``kid`` for id_token when using PEM signing (or first ``kid`` from jwks_active_keys if omitted).
    oidc_id_token_signing_kid: Optional[str] = None
    # Token lifetimes (in seconds)
    access_token_lifetime: int = 3600  # 1 hour
    refresh_token_lifetime: int = 86400 * 7  # 7 days
    # Storage
    storage_provider: Optional[IStorageProvider] = None
    # Providers
    providers: list[str] = field(default_factory=list)
    # Security features
    enable_pkce: bool = True
    enable_csrf: bool = True
    rate_limit_enabled: bool = True
    # Password hashing
    password_hash_algorithm: PasswordHashAlgorithm = PasswordHashAlgorithm.BCRYPT
    # OAuth 2.0 settings
    require_exact_redirect_uri: bool = True  # OAuth 2.1 requirement
    require_state_in_authorize: bool = True  # CSRF; client must send state
    pkce_s256_only: bool = True  # Reject "plain"; S256 only (OWASP)
    # OAuth 2.1 security enhancements
    oauth21_compliant: bool = True  # Enable OAuth 2.1 compliance mode
    require_pkce_for_public_clients: bool = True  # OAuth 2.1: PKCE mandatory for public clients
    allow_password_grant: bool = False  # OAuth 2.1: Password grant disabled by default
    # B2B: org_id / organization_id on /authorize must map to an authenticated user who is a member
    # (pass Authorization: Bearer on the authorize request). Set False only for legacy dev flows.
    authorize_org_hint_requires_membership: bool = True
    enable_dpop: bool = False  # DPoP (RFC 9449) support (optional)
    enable_mtls: bool = False  # mTLS certificate-bound tokens (RFC 8705) support (optional)
    # FAPI 2.0 alignment (Financial-grade API security profile)
    fapi20_compliant: bool = False  # Enable FAPI 2.0 compliance mode
    fapi20_require_par: bool = False  # FAPI 2.0: Require PAR (Pushed Authorization Requests) for all requests
    # RFC 9126: PAR ``request_uri`` lifetime (seconds). Bounded in validate() for operational safety.
    par_request_lifetime: int = 60
    # When True, the browser authorize URL may only carry allow-listed params alongside ``request_uri``.
    par_strict_authorize_query: bool = True
    fapi20_require_jar: bool = False  # FAPI 2.0: Require JAR (JWT Secured Authorization Request) - RFC 9101
    fapi20_require_dpop_or_mtls: bool = False  # FAPI 2.0: Require DPoP or mTLS for token binding
    fapi20_token_lifetime: Optional[int] = None  # FAPI 2.0: Custom token lifetime (overrides access_token_lifetime)
    fapi20_max_token_lifetime: int = 3600  # FAPI 2.0: Maximum token lifetime (1 hour default)
    fapi20_require_https: bool = True  # FAPI 2.0: Require HTTPS for all endpoints
    fapi20_enforce_scope_restrictions: bool = False  # FAPI 2.0: Enforce strict scope validation
    # JWKS lifecycle publication controls
    jwks_active_keys: list[dict[str, Any]] = field(default_factory=list)
    jwks_next_keys: list[dict[str, Any]] = field(default_factory=list)
    jwks_publish_next_keys: bool = False
    # Protocol rigor profile
    protocol_profile: str = "A"
    protocol_strict_startup_validation: bool = True
    saml_strict_validation: bool = False
    # IdP signing certs (PEM). When non-empty, SAML responses must carry a verifiable XML signature.
    saml_idp_signing_certificates_pem: list[str] = field(default_factory=list)
    # Optional SHA-256 fingerprints (hex) of IdP signing certs; if set, embedded KeyInfo cert must match.
    saml_idp_certificate_pins_sha256: list[str] = field(default_factory=list)
    # Optional PEM bundle (concatenated CAs) for chain validation passed to the XML verifier.
    saml_idp_ca_bundle_pem: str | None = None
    saml_entity_id: str | None = None
    saml_expected_audiences: list[str] = field(default_factory=list)
    saml_clock_skew_seconds: int = 120
    federated_sso_client_id: str = "saml_sso"
    # Federation broker: cache upstream JWKS documents (seconds); 0 disables caching.
    federation_jwks_cache_ttl_seconds: int = 3600
    # When True (default), validate OIDC id_token *at_hash* / *c_hash* after JWKS verification.
    federation_verify_oidc_token_hashes: bool = True
    default_scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    # Registered OAuth clients (static config). Each: client_id, client_secret (optional), redirect_uris: list[str]
    registered_clients: list[dict[str, Any]] = field(default_factory=list)
    # Development-only escape hatch for legacy local configs using DEFAULT_TEST_CLIENTS.
    allow_insecure_test_clients: bool = False
    # Development-only: allow in-memory MockStorageProvider fallback when no real storage is configured.
    allow_mock_storage_fallback: bool = False
    # Dev-only: never True in production. When False, OTP/magic link never returned in API response.
    dev_return_secrets_in_response: bool = False
    # Session settings
    session_timeout: int = 86400  # 24 hours
    max_concurrent_sessions: Optional[int] = None
    # Rate limiting
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_hour: int = 1000
    # MFA at-rest (TOTP seed envelope). mfa_at_rest_key_b64: optional 32-byte key (base64);
    # if unset, key is derived from jwt_secret (operational; prefer dedicated key in production).
    mfa_at_rest_algorithm: str = "aes256-gcm"
    mfa_at_rest_key_b64: str | None = None
    mfa_totp_max_failed_attempts: int = 5
    mfa_totp_lockout_seconds: int = 900
    mfa_backup_code_count: int = 10
    # WebAuthn / passkeys
    webauthn_rp_name: str = "xwauth"
    webauthn_rp_id: str | None = None
    webauthn_origin: str | None = None
    webauthn_allowed_origins: list[str] = field(default_factory=list)
    webauthn_challenge_ttl_seconds: int = 300
    webauthn_challenge_backend: str = "memory"
    webauthn_credential_index_backend: str = "memory"
    webauthn_redis_url: str | None = None
    webauthn_redis_key_prefix: str = "xwauth:webauthn:ch:"
    webauthn_redis_credential_key_prefix: str = "xwauth:webauthn:cred:"
    webauthn_timeout_ms: int = 60000
    webauthn_attestation: str = "none"
    webauthn_user_verification: str = "preferred"
    webauthn_allow_insecure_defaults: bool = False
    webauthn_allow_passkey_sync: bool = True
    # Enterprise attestation: PEM CA bundle applied to non-NONE formats (py_webauthn pem_root_certs_bytes_by_fmt).
    webauthn_trusted_attestation_ca_pem: list[str] = field(default_factory=list)
    # When True, passkey login verify returns a generic OAuth error for common failure codes (user enumeration resistance).
    webauthn_anti_enumeration_login: bool = True
    # Discoverable / resident credentials (WebAuthn residentKey): discouraged | preferred | required
    webauthn_resident_key: str = "preferred"
    # Allow login/verify without user_id when assertion credential id can be resolved (passkey autofill UX).
    webauthn_discoverable_login: bool = True
    mfa_failure_delay_ms: int = 0
    # Additional configuration
    extra_config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "jwt_secret": self.jwt_secret,
            "jwt_algorithm": self.jwt_algorithm,
            "access_token_lifetime": self.access_token_lifetime,
            "refresh_token_lifetime": self.refresh_token_lifetime,
            "providers": self.providers,
            "enable_pkce": self.enable_pkce,
            "enable_csrf": self.enable_csrf,
            "rate_limit_enabled": self.rate_limit_enabled,
            "password_hash_algorithm": self.password_hash_algorithm.value,
            "require_exact_redirect_uri": self.require_exact_redirect_uri,
            "require_state_in_authorize": self.require_state_in_authorize,
            "pkce_s256_only": self.pkce_s256_only,
            "oauth21_compliant": self.oauth21_compliant,
            "require_pkce_for_public_clients": self.require_pkce_for_public_clients,
            "allow_password_grant": self.allow_password_grant,
            "enable_dpop": self.enable_dpop,
            "enable_mtls": self.enable_mtls,
            "fapi20_compliant": self.fapi20_compliant,
            "fapi20_require_par": self.fapi20_require_par,
            "par_request_lifetime": self.par_request_lifetime,
            "par_strict_authorize_query": self.par_strict_authorize_query,
            "fapi20_require_jar": self.fapi20_require_jar,
            "fapi20_require_dpop_or_mtls": self.fapi20_require_dpop_or_mtls,
            "fapi20_token_lifetime": self.fapi20_token_lifetime,
            "fapi20_max_token_lifetime": self.fapi20_max_token_lifetime,
            "fapi20_require_https": self.fapi20_require_https,
            "fapi20_enforce_scope_restrictions": self.fapi20_enforce_scope_restrictions,
            "jwks_active_keys": self.jwks_active_keys,
            "jwks_next_keys": self.jwks_next_keys,
            "jwks_publish_next_keys": self.jwks_publish_next_keys,
            "protocol_profile": self.protocol_profile,
            "protocol_strict_startup_validation": self.protocol_strict_startup_validation,
            "saml_strict_validation": self.saml_strict_validation,
            "saml_idp_signing_certificates_pem": self.saml_idp_signing_certificates_pem,
            "saml_idp_certificate_pins_sha256": self.saml_idp_certificate_pins_sha256,
            "saml_idp_ca_bundle_pem": self.saml_idp_ca_bundle_pem,
            "saml_entity_id": self.saml_entity_id,
            "saml_expected_audiences": self.saml_expected_audiences,
            "saml_clock_skew_seconds": self.saml_clock_skew_seconds,
            "federated_sso_client_id": self.federated_sso_client_id,
            "federation_jwks_cache_ttl_seconds": self.federation_jwks_cache_ttl_seconds,
            "federation_verify_oidc_token_hashes": self.federation_verify_oidc_token_hashes,
            "default_scopes": self.default_scopes,
            "registered_clients": self.registered_clients,
            "allow_insecure_test_clients": self.allow_insecure_test_clients,
            "allow_mock_storage_fallback": self.allow_mock_storage_fallback,
            "dev_return_secrets_in_response": self.dev_return_secrets_in_response,
            "session_timeout": self.session_timeout,
            "max_concurrent_sessions": self.max_concurrent_sessions,
            "rate_limit_requests_per_minute": self.rate_limit_requests_per_minute,
            "rate_limit_requests_per_hour": self.rate_limit_requests_per_hour,
            "mfa_at_rest_algorithm": self.mfa_at_rest_algorithm,
            "mfa_at_rest_key_b64": self.mfa_at_rest_key_b64,
            "mfa_totp_max_failed_attempts": self.mfa_totp_max_failed_attempts,
            "mfa_totp_lockout_seconds": self.mfa_totp_lockout_seconds,
            "mfa_backup_code_count": self.mfa_backup_code_count,
            "webauthn_rp_name": self.webauthn_rp_name,
            "webauthn_rp_id": self.webauthn_rp_id,
            "webauthn_origin": self.webauthn_origin,
            "webauthn_allowed_origins": self.webauthn_allowed_origins,
            "webauthn_challenge_ttl_seconds": self.webauthn_challenge_ttl_seconds,
            "webauthn_challenge_backend": self.webauthn_challenge_backend,
            "webauthn_credential_index_backend": self.webauthn_credential_index_backend,
            "webauthn_redis_url": self.webauthn_redis_url,
            "webauthn_redis_key_prefix": self.webauthn_redis_key_prefix,
            "webauthn_redis_credential_key_prefix": self.webauthn_redis_credential_key_prefix,
            "webauthn_timeout_ms": self.webauthn_timeout_ms,
            "webauthn_attestation": self.webauthn_attestation,
            "webauthn_user_verification": self.webauthn_user_verification,
            "webauthn_allow_insecure_defaults": self.webauthn_allow_insecure_defaults,
            "webauthn_allow_passkey_sync": self.webauthn_allow_passkey_sync,
            "webauthn_trusted_attestation_ca_pem": self.webauthn_trusted_attestation_ca_pem,
            "webauthn_anti_enumeration_login": self.webauthn_anti_enumeration_login,
            "webauthn_resident_key": self.webauthn_resident_key,
            "webauthn_discoverable_login": self.webauthn_discoverable_login,
            "mfa_failure_delay_ms": self.mfa_failure_delay_ms,
            "extra_config": self.extra_config,
        }
    @classmethod

    def from_dict(cls, data: dict[str, Any]) -> XWAuthConfig:
        """Create configuration from dictionary."""
        # Extract extra_config
        known_keys = {
            "jwt_secret", "jwt_algorithm", "access_token_lifetime",
            "refresh_token_lifetime", "providers", "enable_pkce",
            "enable_csrf", "rate_limit_enabled", "password_hash_algorithm",
            "require_exact_redirect_uri", "require_state_in_authorize", "pkce_s256_only",
            "oauth21_compliant", "require_pkce_for_public_clients",
            "allow_password_grant", "enable_dpop", "enable_mtls",
            "fapi20_compliant", "fapi20_require_par", "fapi20_require_jar",
            "fapi20_require_dpop_or_mtls", "fapi20_token_lifetime",
            "fapi20_max_token_lifetime", "fapi20_require_https",
            "fapi20_enforce_scope_restrictions",
            "jwks_active_keys", "jwks_next_keys", "jwks_publish_next_keys",
            "protocol_profile", "protocol_strict_startup_validation",
            "saml_strict_validation",
            "saml_idp_signing_certificates_pem",
            "saml_idp_certificate_pins_sha256",
            "saml_idp_ca_bundle_pem",
            "saml_entity_id",
            "saml_expected_audiences",
            "saml_clock_skew_seconds",
            "federated_sso_client_id",
            "federation_jwks_cache_ttl_seconds",
            "federation_verify_oidc_token_hashes",
            "default_scopes",
            "registered_clients",
            "allow_insecure_test_clients",
            "allow_mock_storage_fallback",
            "dev_return_secrets_in_response",
            "session_timeout", "max_concurrent_sessions",
            "rate_limit_requests_per_minute", "rate_limit_requests_per_hour",
            "mfa_at_rest_algorithm", "mfa_at_rest_key_b64",
            "mfa_totp_max_failed_attempts", "mfa_totp_lockout_seconds", "mfa_backup_code_count",
            "webauthn_rp_name", "webauthn_rp_id", "webauthn_origin", "webauthn_allowed_origins",
            "webauthn_challenge_ttl_seconds", "webauthn_challenge_backend",
            "webauthn_credential_index_backend", "webauthn_redis_url",
            "webauthn_redis_key_prefix", "webauthn_redis_credential_key_prefix", "webauthn_timeout_ms", "webauthn_attestation",
            "webauthn_user_verification", "webauthn_allow_insecure_defaults", "webauthn_allow_passkey_sync",
            "webauthn_trusted_attestation_ca_pem", "webauthn_anti_enumeration_login",
            "webauthn_resident_key", "webauthn_discoverable_login",
            "mfa_failure_delay_ms",
            "extra_config"
        }
        extra_config = {k: v for k, v in data.items() if k not in known_keys}
        config_data = {k: v for k, v in data.items() if k in known_keys}
        if "password_hash_algorithm" in config_data:
            config_data["password_hash_algorithm"] = PasswordHashAlgorithm(
                config_data["password_hash_algorithm"]
            )
        config_data["extra_config"] = extra_config
        return cls(**config_data)

    def get_registered_client(self, client_id: str) -> Optional[dict[str, Any]]:
        """Look up registered client by client_id. Returns None if not found."""
        # Check dynamic clients first (from DCR)
        if hasattr(self, '_dynamic_clients') and self._dynamic_clients:
            if client_id in self._dynamic_clients:
                client = self._dynamic_clients[client_id]
                # Convert to format expected by existing code
                return {
                    "client_id": client.get("client_id"),
                    "client_secret": client.get("client_secret"),
                    "redirect_uris": client.get("redirect_uris", []),
                }
        # Check static registered clients
        for c in self.registered_clients:
            if c.get("client_id") == client_id:
                return c
        return None

    def is_fapi20_enabled(self) -> bool:
        """Check if FAPI 2.0 compliance mode is enabled."""
        return self.fapi20_compliant

    def get_effective_token_lifetime(self) -> int:
        """Get effective access token lifetime considering FAPI 2.0 settings."""
        if self.fapi20_compliant and self.fapi20_token_lifetime is not None:
            # FAPI 2.0 custom lifetime takes precedence
            return min(self.fapi20_token_lifetime, self.fapi20_max_token_lifetime)
        elif self.fapi20_compliant:
            # Use FAPI 2.0 max lifetime if FAPI is enabled
            return min(self.access_token_lifetime, self.fapi20_max_token_lifetime)
        else:
            # Standard lifetime
            return self.access_token_lifetime

    def get_protocol_profile_requirements(self) -> dict[str, Any]:
        """Return strictness requirements for the configured protocol profile."""
        profile = (self.protocol_profile or "A").upper()
        return PROTOCOL_PROFILE_REQUIREMENTS.get(profile, PROTOCOL_PROFILE_REQUIREMENTS["A"])

    def validate(self) -> None:
        """
        Validate configuration values. Raises XWConfigError on invalid settings.
        Aligns with xlib_OLD/xauth config validation and GUIDE_31_DEV.
        """
        if not (self.jwt_secret and self.jwt_secret.strip()):
            raise XWConfigError("jwt_secret is required and must be non-empty")
        if self.access_token_lifetime <= 0:
            raise XWConfigError("access_token_lifetime must be positive")
        if self.refresh_token_lifetime <= 0:
            raise XWConfigError("refresh_token_lifetime must be positive")
        if self.par_request_lifetime < 10 or self.par_request_lifetime > 600:
            raise XWConfigError("par_request_lifetime must be between 10 and 600 seconds (RFC 9126 operational bounds)")
        if self.session_timeout <= 0:
            raise XWConfigError("session_timeout must be positive")
        if self.rate_limit_requests_per_minute <= 0:
            raise XWConfigError("rate_limit_requests_per_minute must be positive")
        if self.rate_limit_requests_per_hour <= 0:
            raise XWConfigError("rate_limit_requests_per_hour must be positive")
        if self.max_concurrent_sessions is not None and self.max_concurrent_sessions <= 0:
            raise XWConfigError("max_concurrent_sessions must be positive when set")
        profile = (self.protocol_profile or "").upper()
        if profile not in PROTOCOL_PROFILE_REQUIREMENTS:
            raise XWConfigError("protocol_profile must be one of: A, B, C")
        if not isinstance(self.default_scopes, list) or not self.default_scopes:
            raise XWConfigError("default_scopes must be a non-empty list[str]")
        if any((not isinstance(scope, str) or not scope.strip()) for scope in self.default_scopes):
            raise XWConfigError("default_scopes values must be non-empty strings")
        if not isinstance(self.registered_clients, list):
            raise XWConfigError("registered_clients must be a list[dict[str, Any]]")
        if not isinstance(self.allow_insecure_test_clients, bool):
            raise XWConfigError("allow_insecure_test_clients must be boolean")
        if not isinstance(self.allow_mock_storage_fallback, bool):
            raise XWConfigError("allow_mock_storage_fallback must be boolean")
        if not self.allow_insecure_test_clients:
            for client in self.registered_clients:
                if not isinstance(client, dict):
                    raise XWConfigError("registered_clients entries must be dictionaries")
                if (
                    client.get("client_id") == _DEFAULT_TEST_CLIENT_ID
                    and client.get("client_secret") == _DEFAULT_TEST_CLIENT_SECRET
                ):
                    raise XWConfigError(
                        "DEFAULT_TEST_CLIENTS credentials are blocked by default. "
                        "Set allow_insecure_test_clients=True for local tests only."
                    )
        att_pem = self.webauthn_trusted_attestation_ca_pem
        if not isinstance(att_pem, list) or any(not isinstance(x, str) for x in att_pem):
            raise XWConfigError("webauthn_trusted_attestation_ca_pem must be a list[str]")
        rk = (self.webauthn_resident_key or "").strip().lower()
        if rk not in ("discouraged", "preferred", "required"):
            raise XWConfigError("webauthn_resident_key must be one of: discouraged, preferred, required")
        idx_b = (self.webauthn_credential_index_backend or "memory").strip().lower()
        if idx_b not in ("memory", "redis"):
            raise XWConfigError("webauthn_credential_index_backend must be one of: memory, redis")
        for key_set_name in ("jwks_active_keys", "jwks_next_keys"):
            key_set = getattr(self, key_set_name, [])
            if not isinstance(key_set, list):
                raise XWConfigError(f"{key_set_name} must be a list[dict[str, Any]]")
            for key in key_set:
                if not isinstance(key, dict):
                    raise XWConfigError(f"{key_set_name} entries must be dictionaries")
                if not key.get("kty"):
                    raise XWConfigError(f"{key_set_name} entries require 'kty'")
                if not key.get("kid"):
                    raise XWConfigError(f"{key_set_name} entries require 'kid'")
        pem_list = self.saml_idp_signing_certificates_pem
        if not isinstance(pem_list, list) or any(not isinstance(x, str) for x in pem_list):
            raise XWConfigError("saml_idp_signing_certificates_pem must be a list[str]")
        pin_list = self.saml_idp_certificate_pins_sha256
        if not isinstance(pin_list, list) or any(not isinstance(x, str) for x in pin_list):
            raise XWConfigError("saml_idp_certificate_pins_sha256 must be a list[str]")
        for pin in pin_list:
            p = pin.strip().lower().replace(":", "")
            if len(p) != 64 or any(c not in "0123456789abcdef" for c in p):
                raise XWConfigError("saml_idp_certificate_pins_sha256 entries must be 64 hex chars (SHA-256)")
        if self.saml_idp_ca_bundle_pem is not None and (
            not isinstance(self.saml_idp_ca_bundle_pem, str) or not self.saml_idp_ca_bundle_pem.strip()
        ):
            raise XWConfigError("saml_idp_ca_bundle_pem must be a non-empty string when set")
        requirements = self.get_protocol_profile_requirements()
        for flag_name in requirements["required_flags"]:
            if not bool(getattr(self, flag_name, False)):
                raise XWConfigError(
                    f"protocol_profile={profile} requires {flag_name}=True"
                )
    @classmethod

    def from_env(cls) -> XWAuthConfig:
        """
        Build configuration from environment variables (XWAUTH_*).
        Required: XWAUTH_JWT_SECRET. Optional: XWAUTH_JWT_ALGORITHM,
        XWAUTH_ACCESS_TOKEN_LIFETIME, XWAUTH_REFRESH_TOKEN_LIFETIME,
        XWAUTH_SESSION_TIMEOUT, XWAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE,
        XWAUTH_RATE_LIMIT_REQUESTS_PER_HOUR, XWAUTH_ENABLE_PKCE, XWAUTH_ENABLE_CSRF,
        XWAUTH_RATE_LIMIT_ENABLED (true/false), etc.
        """
        def _env(key: str, default: str) -> str:
            return os.getenv(key, default).strip()
        def _env_int(key: str, default: int) -> int:
            v = os.getenv(key, str(default))
            try:
                return int(v)
            except ValueError as e:
                raise XWConfigError(f"Invalid integer for {key}: {v!r}") from e
        def _env_bool(key: str, default: bool) -> bool:
            v = os.getenv(key, "true" if default else "false").lower()
            return v in ("true", "1", "yes", "y", "t")
        def _env_csv(key: str, default: list[str]) -> list[str]:
            raw = os.getenv(key, "")
            if not raw.strip():
                return list(default)
            return [part.strip() for part in raw.split(",") if part.strip()]
        jwt_secret = _env("XWAUTH_JWT_SECRET", "")
        if not jwt_secret:
            raise XWConfigError(
                "XWAUTH_JWT_SECRET is required when using from_env()"
            )
        return cls(
            jwt_secret=jwt_secret,
            jwt_algorithm=_env("XWAUTH_JWT_ALGORITHM", "HS256"),
            access_token_lifetime=_env_int("XWAUTH_ACCESS_TOKEN_LIFETIME", 3600),
            refresh_token_lifetime=_env_int("XWAUTH_REFRESH_TOKEN_LIFETIME", 86400 * 7),
            session_timeout=_env_int("XWAUTH_SESSION_TIMEOUT", 86400),
            rate_limit_requests_per_minute=_env_int("XWAUTH_RATE_LIMIT_REQUESTS_PER_MINUTE", 60),
            rate_limit_requests_per_hour=_env_int("XWAUTH_RATE_LIMIT_REQUESTS_PER_HOUR", 1000),
            enable_pkce=_env_bool("XWAUTH_ENABLE_PKCE", True),
            enable_csrf=_env_bool("XWAUTH_ENABLE_CSRF", True),
            rate_limit_enabled=_env_bool("XWAUTH_RATE_LIMIT_ENABLED", True),
            protocol_profile=_env("XWAUTH_PROTOCOL_PROFILE", "A").upper(),
            protocol_strict_startup_validation=_env_bool("XWAUTH_PROTOCOL_STRICT_STARTUP_VALIDATION", True),
            saml_strict_validation=_env_bool("XWAUTH_SAML_STRICT_VALIDATION", False),
            default_scopes=_env_csv("XWAUTH_DEFAULT_SCOPES", ["openid", "profile", "email"]),
            allow_insecure_test_clients=_env_bool("XWAUTH_ALLOW_INSECURE_TEST_CLIENTS", False),
            allow_mock_storage_fallback=_env_bool("XWAUTH_ALLOW_MOCK_STORAGE_FALLBACK", False),
        )
# -----------------------------------------------------------------------------
# Optional global config (parity with xlib_OLD/xauth get_config/set_config/reset_config)
# -----------------------------------------------------------------------------
_config_lock = threading.Lock()
_config: Optional[XWAuthConfig] = None


def get_config() -> XWAuthConfig:
    """
    Return the global XWAuthConfig. If none set, builds one from environment
    via XWAuthConfig.from_env() and validates it.
    """
    global _config
    with _config_lock:
        if _config is None:
            _config = XWAuthConfig.from_env()
            _config.validate()
        return _config


def set_config(config: XWAuthConfig) -> None:
    """Set the global configuration. Validates before setting."""
    config.validate()
    global _config
    with _config_lock:
        _config = config


def reset_config() -> None:
    """Clear the global config so next get_config() reloads from environment."""
    global _config
    with _config_lock:
        _config = None
