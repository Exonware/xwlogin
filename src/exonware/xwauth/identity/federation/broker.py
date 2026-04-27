#!/usr/bin/env python3
"""
Federation broker for OAuth/OIDC and LDAP adapters.
"""

from __future__ import annotations
import inspect
from typing import Any

import jwt

from exonware.xwauth.identity.federation.errors import FederationUpstreamCode, XWFederationError
from .jwks_cache import JwksDocumentCache
from .mapping import apply_claim_mapping_v1
from .oidc_access_token_hash import verify_at_hash, verify_c_hash
from .oidc_id_token import (
    OidcIdTokenValidationParams,
    decode_id_token_unverified,
    validate_federated_id_token,
)
from .types import FederatedIdentity


class FederationBroker:
    """Unified broker that normalizes identities across federation mechanisms."""

    def __init__(
        self,
        provider_registry: Any,
        *,
        jwks_cache_ttl_seconds: int = 3600,
        jwks_negative_cache_ttl_seconds: int = 20,
    ):
        self._provider_registry = provider_registry
        self._ldap_providers: dict[str, Any] = {}
        self._saml_providers: dict[str, Any] = {}
        self._http_client: Any = None
        ttl = int(jwks_cache_ttl_seconds or 0)
        neg = max(0, int(jwks_negative_cache_ttl_seconds or 0))
        self._jwks_cache: JwksDocumentCache | None = (
            JwksDocumentCache(
                float(ttl), negative_cache_ttl_seconds=float(neg)
            )
            if ttl > 0
            else None
        )

    def _http(self) -> Any:
        if self._http_client is None:
            from exonware.xwsystem.http_client import AsyncHttpClient

            self._http_client = AsyncHttpClient()
        return self._http_client

    async def _http_get(self, url: str) -> Any:
        return await self._http().get(url)

    def register_ldap_provider(self, name: str, provider: Any) -> None:
        self._ldap_providers[str(name)] = provider

    def register_saml_provider(self, name: str, provider: Any) -> None:
        self._saml_providers[str(name)] = provider

    async def start_oauth2(
        self,
        provider_name: str,
        *,
        client_id: str,
        redirect_uri: str,
        state: str,
        scopes: list[str] | None = None,
        nonce: str | None = None,
        code_verifier: str | None = None,
    ) -> str:
        provider = self._provider_registry.get(provider_name)
        sig = inspect.signature(provider.get_authorization_url)
        params = sig.parameters
        call_kw: dict[str, Any] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        if "scopes" in params:
            call_kw["scopes"] = scopes or []
        if "nonce" in params:
            call_kw["nonce"] = nonce
        if code_verifier is not None:
            if "code_verifier" not in params:
                raise XWFederationError(
                    "OAuth provider does not support PKCE (code_verifier)",
                    upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
                    oauth_error="invalid_request",
                    safe_description="This provider integration does not support PKCE.",
                )
            call_kw["code_verifier"] = code_verifier
        return await provider.get_authorization_url(**call_kw)

    async def complete_oauth2(
        self,
        provider_name: str,
        *,
        code: str,
        redirect_uri: str,
        client_id: str | None = None,
        code_verifier: str | None = None,
        expected_nonce: str | None = None,
        claim_mapping_rules: list[dict[str, Any]] | None = None,
        id_token_validation: OidcIdTokenValidationParams | None = None,
        validate_id_token: bool | None = None,
        userinfo_fallback_from_id_token: bool = True,
        verify_oidc_token_hashes: bool = True,
        extra_user_claims: dict[str, Any] | None = None,
    ) -> FederatedIdentity:
        """
        *extra_user_claims*: callback-only fields (e.g. Apple form_post ``user``) merged **after**
        id_token fallback so signed token claims win; only fills keys still empty.
        """
        provider = self._provider_registry.get(provider_name)
        audience = client_id or getattr(provider, "_client_id", None) or ""

        sig = inspect.signature(provider.exchange_code_for_token)
        if code_verifier is not None and "code_verifier" not in sig.parameters:
            raise XWFederationError(
                "OAuth provider does not support PKCE code_verifier on token exchange",
                upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
            )
        if "code_verifier" in sig.parameters:
            token_data = await provider.exchange_code_for_token(
                code, redirect_uri, code_verifier=code_verifier
            )
        else:
            token_data = await provider.exchange_code_for_token(code, redirect_uri)

        if not isinstance(token_data, dict):
            raise XWFederationError(
                "Invalid token response from identity provider",
                upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
            )

        access_token = token_data.get("access_token")
        id_tok = token_data.get("id_token")
        if expected_nonce is not None and not id_tok:
            raise XWFederationError(
                "OpenID Connect nonce was requested but id_token is missing",
                upstream_code=FederationUpstreamCode.INVALID_NONCE,
            )
        id_claims: dict[str, Any] | None = None
        validation_mode = "none"
        oidc_hash_trace: dict[str, str] | None = None

        vparams = id_token_validation
        if validate_id_token is False:
            do_full = False
        elif vparams is not None:
            do_full = bool(id_tok)
        elif validate_id_token is True:
            if not id_tok:
                raise XWFederationError(
                    "id_token required for strict validation",
                    upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
                )
            iss = getattr(provider, "oidc_issuer", None)
            jwks_uri = getattr(provider, "oidc_jwks_uri", None)
            if not (iss and jwks_uri and audience):
                raise XWFederationError(
                    "Strict id_token validation requires issuer, JWKS URI, and client_id (audience)",
                    upstream_code=FederationUpstreamCode.MISCONFIGURED_IDP,
                )
            vparams = OidcIdTokenValidationParams(issuer=iss, audience=audience, jwks_uri=jwks_uri)
            do_full = True
        else:
            iss = getattr(provider, "oidc_issuer", None)
            jwks_uri = getattr(provider, "oidc_jwks_uri", None)
            if id_tok and iss and jwks_uri and audience:
                vparams = OidcIdTokenValidationParams(issuer=iss, audience=audience, jwks_uri=jwks_uri)
                do_full = True
            else:
                do_full = False

        if id_tok and do_full and vparams is not None:
            id_claims = await validate_federated_id_token(
                id_tok,
                vparams,
                expected_nonce=expected_nonce,
                http_get=self._http_get,
                jwks_document_cache=self._jwks_cache,
            )
            validation_mode = "jwks"
            if id_claims is not None:
                if verify_oidc_token_hashes:
                    header_alg: str | None = None
                    try:
                        hdr = jwt.get_unverified_header(id_tok)
                        alg_raw = hdr.get("alg")
                        header_alg = alg_raw if isinstance(alg_raw, str) else None
                    except Exception:
                        header_alg = None

                    if id_claims.get("c_hash") is not None:
                        if not code:
                            cht = "skipped_no_code"
                        elif not verify_c_hash(code, id_claims.get("c_hash"), header_alg):
                            raise XWFederationError(
                                "OpenID Connect c_hash validation failed",
                                upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
                                oauth_error="invalid_grant",
                            )
                        else:
                            cht = "verified"
                    else:
                        cht = "skipped_no_claim"

                    if id_claims.get("at_hash") is not None:
                        if not access_token:
                            aht = "skipped_no_access_token"
                        elif not verify_at_hash(
                            str(access_token), id_claims.get("at_hash"), header_alg
                        ):
                            raise XWFederationError(
                                "OpenID Connect at_hash validation failed",
                                upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
                                oauth_error="invalid_grant",
                            )
                        else:
                            aht = "verified"
                    else:
                        aht = "skipped_no_claim"
                    oidc_hash_trace = {"c_hash": cht, "at_hash": aht}
                else:
                    oidc_hash_trace = {
                        "c_hash": "skipped_disabled",
                        "at_hash": "skipped_disabled",
                    }
        elif id_tok and expected_nonce is not None:
            payload = decode_id_token_unverified(id_tok)
            if payload.get("nonce") != expected_nonce:
                raise XWFederationError(
                    "OpenID Connect nonce mismatch",
                    upstream_code=FederationUpstreamCode.INVALID_NONCE,
                )
            id_claims = payload
            validation_mode = "nonce_only"
        elif id_tok and not do_full:
            try:
                id_claims = jwt.decode(
                    id_tok,
                    options={
                        "verify_signature": False,
                        "verify_aud": False,
                        "verify_exp": False,
                    },
                )
                validation_mode = "unverified"
            except Exception as exc:
                raise XWFederationError(
                    "Invalid id_token from identity provider",
                    upstream_code=FederationUpstreamCode.TOKEN_VALIDATION_FAILED,
                ) from exc

        user_info: dict[str, Any] = {}
        if access_token and getattr(provider, "get_user_info", None):
            try:
                user_info = await provider.get_user_info(access_token) or {}
            except Exception:
                user_info = {}

        if userinfo_fallback_from_id_token and id_claims:
            for k in (
                "sub",
                "email",
                "email_verified",
                "name",
                "given_name",
                "family_name",
                "preferred_username",
                "tid",
                "tenant_id",
            ):
                if id_claims.get(k) is not None and (k not in user_info or user_info.get(k) in (None, "")):
                    user_info[k] = id_claims[k]

        if extra_user_claims:
            for k, v in extra_user_claims.items():
                if v is None or (isinstance(v, str) and not v.strip()):
                    continue
                if k not in user_info or user_info.get(k) in (None, ""):
                    user_info[k] = v

        merged_user_info = dict(user_info)
        for key in ("access_token", "refresh_token", "token_type", "expires_in", "scope", "id_token"):
            if token_data.get(key) is not None:
                merged_user_info.setdefault(key, token_data.get(key))

        dsl_trace: dict[str, Any] | None = None
        if claim_mapping_rules:
            merged_user_info, dsl_trace = apply_claim_mapping_v1(merged_user_info, claim_mapping_rules)

        ident = self._normalize_user_info(provider_name, merged_user_info)
        base_trace = dict(ident.mapping_trace or {})
        base_trace["id_token_validation"] = validation_mode
        if oidc_hash_trace is not None:
            base_trace["oidc_token_hashes"] = oidc_hash_trace
        if dsl_trace is not None:
            base_trace["dsl_v1"] = dsl_trace
        ident.mapping_trace = base_trace
        return ident

    async def authenticate_ldap(
        self,
        provider_name: str,
        *,
        username: str,
        password: str,
    ) -> FederatedIdentity:
        provider = self._ldap_providers.get(provider_name)
        if provider is None:
            raise ValueError(f"LDAP provider '{provider_name}' is not registered")
        user_info: dict[str, Any] | None = None
        if hasattr(provider, "authenticate"):
            user_info = await self._maybe_await(
                provider.authenticate({"username": username, "password": password})
            )
        elif hasattr(provider, "bind"):
            bind_result = await self._maybe_await(provider.bind(username=username, password=password))
            if isinstance(bind_result, dict):
                user_info = bind_result
            elif bind_result:
                user_info = {"username": username}
        elif hasattr(provider, "login"):
            user_info = await self._maybe_await(provider.login(username=username, password=password))
        if not isinstance(user_info, dict):
            raise ValueError(f"LDAP provider '{provider_name}' did not return user info")
        return self._normalize_user_info(provider_name, user_info)

    async def start_saml(self, provider_name: str, *, relay_state: str) -> str:
        provider = self._saml_providers.get(provider_name)
        if provider is None:
            raise ValueError(f"SAML provider '{provider_name}' is not registered")
        if hasattr(provider, "build_authn_request_url"):
            return str(await self._maybe_await(provider.build_authn_request_url(relay_state=relay_state)))
        if hasattr(provider, "get_login_url"):
            return str(await self._maybe_await(provider.get_login_url(return_url=relay_state)))
        raise ValueError(f"SAML provider '{provider_name}' does not expose login URL builder")

    async def complete_saml(
        self,
        provider_name: str,
        *,
        saml_response: str,
        relay_state: str | None = None,
    ) -> FederatedIdentity:
        provider = self._saml_providers.get(provider_name)
        if provider is None:
            raise ValueError(f"SAML provider '{provider_name}' is not registered")
        user_info: dict[str, Any] | None = None
        if hasattr(provider, "complete_login"):
            user_info = await self._maybe_await(
                provider.complete_login(saml_response=saml_response, relay_state=relay_state)
            )
        elif hasattr(provider, "consume_response"):
            user_info = await self._maybe_await(
                provider.consume_response(saml_response=saml_response, relay_state=relay_state)
            )
        elif hasattr(provider, "validate_assertion"):
            user_info = await self._maybe_await(
                provider.validate_assertion(saml_response=saml_response, relay_state=relay_state)
            )
        elif hasattr(provider, "authenticate"):
            user_info = await self._maybe_await(
                provider.authenticate({"SAMLResponse": saml_response, "RelayState": relay_state})
            )
        if not isinstance(user_info, dict):
            raise ValueError(f"SAML provider '{provider_name}' did not return user info")
        return self._normalize_user_info(provider_name, user_info)

    @staticmethod
    async def _maybe_await(value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    @staticmethod
    def _resolve_claim_value(
        user_info: dict[str, Any],
        candidates: list[str],
        fallback: Any = None,
    ) -> tuple[Any, dict[str, Any]]:
        for key in candidates:
            value = user_info.get(key)
            if value is not None and value != "":
                return value, {"selected_key": key, "candidates": list(candidates)}
        return fallback, {"selected_key": None, "candidates": list(candidates)}

    @staticmethod
    def _normalize_user_info(provider_name: str, user_info: dict[str, Any]) -> FederatedIdentity:
        subject_raw, subject_trace = FederationBroker._resolve_claim_value(
            user_info,
            ["id", "sub", "user_id", "username"],
            fallback="",
        )
        email_raw, email_trace = FederationBroker._resolve_claim_value(
            user_info,
            ["email", "mail", "userPrincipalName"],
            fallback=None,
        )
        tenant_raw, tenant_trace = FederationBroker._resolve_claim_value(
            user_info,
            ["tenant_id", "tid"],
            fallback=None,
        )
        return FederatedIdentity(
            provider=provider_name,
            subject_id=str(subject_raw),
            email=str(email_raw) if email_raw is not None else None,
            tenant_id=str(tenant_raw) if tenant_raw is not None else None,
            claims=dict(user_info),
            mapping_trace={
                "subject_id": subject_trace,
                "email": email_trace,
                "tenant_id": tenant_trace,
            },
        )
