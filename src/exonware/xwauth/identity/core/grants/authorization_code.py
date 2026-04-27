#!/usr/bin/env python3
"""
#exonware/xwauth/src/exonware/xwauth/core/grants/authorization_code.py
Authorization Code Grant Implementation
OAuth 2.0 Authorization Code grant type (RFC 6749 Section 4.1).
PKCE S256 only; state required; redirect_uri per-client allowlist; codes in storage.
"""

from __future__ import annotations
from typing import Any
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from exonware.xwsystem import get_logger
from exonware.xwsystem.security.hazmat import secure_random
import base64
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from exonware.xwauth.identity.defs import GrantType
from exonware.xwauth.identity.errors import (
    XWOAuthError,
    XWInvalidRequestError,
    XWUnauthorizedClientError,
    XWAccessDeniedError,
)
from exonware.xwauth.identity.core.grants.base import ABaseGrant
from ..pkce import PKCE
logger = get_logger(__name__)


def _append_redirect_params(redirect_uri: str, params: dict[str, str], mode: str) -> str:
    """Attach authorize response parameters via query or fragment (OAuth/OIDC redirect)."""
    p = urlparse(redirect_uri)
    if mode == "fragment":
        frag = urlencode(params)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, frag))
    if mode == "query":
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        for k, v in params.items():
            q[k] = v
        new_q = urlencode(list(q.items()))
        return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
    raise ValueError(f"unsupported redirect mode for URL encoding: {mode}")


def _refresh_metadata_from_code_attrs(attrs: Mapping[str, Any]) -> dict[str, Any] | None:
    """Persist tenancy/session on refresh tokens so refresh grant can re-issue org-bound access tokens."""
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
        v = attrs.get(k)
        if v is not None and v not in ("", []):
            out[k] = v
    return out or None


class AuthorizationCodeGrant(ABaseGrant):
    """
    Authorization Code grant type implementation.
    Most secure and recommended grant type for web applications.
    Requires PKCE (S256 only), state from client, redirect_uri allowlist.
    """
    @property

    def grant_type(self) -> GrantType:
        """Get grant type."""
        return GrantType.AUTHORIZATION_CODE

    async def validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Validate authorization code grant request (authorize or token exchange).
        Args:
            request: Request parameters (authorize vs token exchange)
        Returns:
            Validated request data
        Raises:
            XWOAuthError: If validation fails
        """
        if "code" in request and request.get("code"):
            return await self._validate_token_exchange(request)
        return await self._validate_authorize(request)

    async def _validate_authorize(self, request: dict[str, Any]) -> dict[str, Any]:
        """Validate /authorize request."""
        client_id = request.get("client_id")
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request",
                error_description="client_id parameter is required",
            )
        client = self._validate_client(
            client_id, request.get("client_secret"), require_secret=False
        )
        redirect_uris: list[str] = client.get("redirect_uris") or []
        redirect_uri = request.get("redirect_uri")
        if not redirect_uri:
            raise XWInvalidRequestError(
                "redirect_uri is required",
                error_code="invalid_request",
                error_description="redirect_uri parameter is required",
            )
        self._validate_redirect_uri(redirect_uri, redirect_uris)
        scopes = self._validate_scope(request.get("scope"))
        state = request.get("state")
        if getattr(self._config, "require_state_in_authorize", True):
            if not state:
                raise XWInvalidRequestError(
                    "state is required",
                    error_code="invalid_request",
                    error_description="state parameter is required for CSRF protection",
                )
        code_challenge = request.get("code_challenge")
        code_challenge_method = (request.get("code_challenge_method") or "S256").strip()
        # OAuth 2.1: PKCE mandatory for public clients
        is_public = self._is_public_client(client)
        require_pkce = False
        if getattr(self._config, "oauth21_compliant", True):
            # OAuth 2.1 compliance: PKCE required for public clients
            if getattr(self._config, "require_pkce_for_public_clients", True) and is_public:
                require_pkce = True
        elif self._config.enable_pkce:
            # Legacy: PKCE enabled globally
            require_pkce = True
        if require_pkce:
            if not code_challenge:
                raise XWInvalidRequestError(
                    "code_challenge is required (PKCE mandatory for public clients in OAuth 2.1)",
                    error_code="invalid_request",
                    error_description="code_challenge parameter is required for PKCE",
                )
            if getattr(self._config, "pkce_s256_only", True):
                if code_challenge_method.upper() != "S256":
                    raise XWInvalidRequestError(
                        "Only S256 code_challenge_method is supported",
                        error_code="invalid_request",
                        error_description="code_challenge_method must be S256",
                    )
            elif code_challenge_method.upper() not in ("S256", "PLAIN"):
                raise XWInvalidRequestError(
                    f"Unsupported code_challenge_method: {code_challenge_method}",
                    error_code="invalid_request",
                    error_description="code_challenge_method must be S256 or plain",
                )
        if not state:
            state = self._generate_state()
        raw_org = request.get("org_id")
        raw_org_alt = request.get("organization_id")
        if raw_org and raw_org_alt:
            a, b = str(raw_org).strip(), str(raw_org_alt).strip()
            if a and b and a != b:
                raise XWInvalidRequestError(
                    "org_id and organization_id must match when both are sent",
                    error_code="invalid_request",
                    error_description="org_id and organization_id cannot differ",
                )
        out: dict[str, Any] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scopes": scopes,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "response_type": request.get("response_type", "code"),
            "_is_authorize": True,
        }
        sub = request.get("_xwauth_authorize_subject_id")
        if sub is not None and str(sub).strip():
            out["_xwauth_authorize_subject_id"] = str(sub).strip()
        response_type_str = str(out["response_type"]).strip()
        rt_parts = set(response_type_str.split())
        if getattr(self._config, "oauth21_compliant", True) and "token" in rt_parts:
            raise XWInvalidRequestError(
                "access_token in the authorization response is not allowed in OAuth 2.1",
                error_code="invalid_request",
                error_description=(
                    "Use the authorization code grant to obtain access_token at the token endpoint, "
                    "or set oauth21_compliant=False for legacy hybrid flows that return token on redirect"
                ),
            )
        auth_sub = out.get("_xwauth_authorize_subject_id")
        if "id_token" in rt_parts:
            if "openid" not in scopes:
                raise XWInvalidRequestError(
                    "scope openid is required when id_token is requested",
                    error_code="invalid_request",
                    error_description="Include openid in the scope parameter for OpenID Connect",
                )
            nonce = request.get("nonce")
            if not nonce or not str(nonce).strip():
                raise XWInvalidRequestError(
                    "nonce is required when id_token is requested",
                    error_code="invalid_request",
                    error_description="nonce is required for hybrid and implicit id_token responses",
                )
            out["nonce"] = str(nonce).strip()
            if not auth_sub:
                raise XWInvalidRequestError(
                    "Authenticated user required for OpenID Connect id_token response",
                    error_code="invalid_request",
                    error_description="Complete user authentication before authorizing id_token responses",
                )
            oidc_iss = getattr(self._config, "oidc_issuer", None)
            if not oidc_iss or not str(oidc_iss).strip():
                raise XWInvalidRequestError(
                    "Server oidc_issuer must be configured for id_token responses",
                    error_code="invalid_request",
                    error_description="Set oidc_issuer on XWAuthConfig to this authorization server's issuer URL",
                )
        if "token" in rt_parts:
            if not auth_sub:
                raise XWInvalidRequestError(
                    "Authenticated user required when access_token is returned from the authorize endpoint",
                    error_code="invalid_request",
                    error_description="Complete user authentication before returning tokens on the authorization response",
                )
        raw_rm = request.get("response_mode")
        if raw_rm is not None and str(raw_rm).strip():
            rm = str(raw_rm).strip().lower()
            if rm not in ("query", "fragment", "form_post"):
                raise XWInvalidRequestError(
                    f"Unsupported response_mode: {raw_rm}",
                    error_code="invalid_request",
                    error_description="response_mode must be query, fragment, or form_post",
                )
            out["_effective_response_mode"] = rm
        else:
            p = urlparse(str(redirect_uri))
            if rt_parts == {"code"}:
                out["_effective_response_mode"] = "query"
            elif not p.query:
                out["_effective_response_mode"] = "fragment"
            else:
                out["_effective_response_mode"] = "query"
        for k in ("org_id", "organization_id", "project_id", "tenant_id", "tid"):
            v = request.get(k)
            if v is not None and str(v).strip():
                out[k] = str(v).strip()
        if getattr(self._config, "authorize_org_hint_requires_membership", True):
            hinted_org = out.get("org_id") or out.get("organization_id")
            if hinted_org:
                auth_sub = out.get("_xwauth_authorize_subject_id")
                if not auth_sub:
                    raise XWInvalidRequestError(
                        "org_id requires an authenticated user on the authorize request",
                        error_code="invalid_request",
                        error_description=(
                            "Send Authorization: Bearer <access_token> when using org_id, "
                            "or omit org_id until the user session is implemented."
                        ),
                    )
                from ...organizations.manager import OrganizationManager

                om = OrganizationManager(self._auth)
                member_role = await om.get_member_role(str(hinted_org), auth_sub)
                if not member_role:
                    raise XWAccessDeniedError(
                        "User is not a member of the requested organization",
                        "access_denied",
                        error_description="The authenticated subject is not a member of this organization",
                    )
                out["_xwauth_org_member_role"] = member_role
        return out

    async def _validate_token_exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        """Validate token request (authorization_code grant)."""
        code = request.get("code")
        redirect_uri = request.get("redirect_uri")
        client_id = request.get("client_id")
        code_verifier = request.get("code_verifier")
        if not code:
            raise XWInvalidRequestError(
                "code is required",
                error_code="invalid_request",
                error_description="code parameter is required",
            )
        if not redirect_uri:
            raise XWInvalidRequestError(
                "redirect_uri is required",
                error_code="invalid_request",
                error_description="redirect_uri parameter is required",
            )
        if not client_id:
            raise XWInvalidRequestError(
                "client_id is required",
                error_code="invalid_request",
                error_description="client_id parameter is required",
            )
        if not code_verifier:
            raise XWInvalidRequestError(
                "code_verifier is required (PKCE)",
                error_code="invalid_request",
                error_description="code_verifier parameter is required",
            )
        self._validate_client(client_id, request.get("client_secret"))
        return {
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
            "_is_authorize": False,
        }

    async def process(self, request: dict[str, Any]) -> dict[str, Any]:
        """
        Process authorization code grant (authorize or token exchange).
        Args:
            request: Validated request parameters
        Returns:
            Redirect response (authorize) or token response (exchange)
        """
        if request.get("_is_authorize"):
            return await self._process_authorize(request)
        return await self._process_token_exchange(request)

    async def _process_authorize(self, request: dict[str, Any]) -> dict[str, Any]:
        """Create authorization code, persist, return redirect (query/fragment) or form_post payload."""
        rt_parts = set(str(request.get("response_type", "code")).split())
        effective_rm = str(request.get("_effective_response_mode", "query"))
        authorization_code = self._generate_authorization_code()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=10)
        scopes = request["scopes"]
        if not isinstance(scopes, list):
            scopes = list(scopes) if scopes else []
        attrs: dict[str, Any] = dict(state=request["state"])
        for k in ("org_id", "organization_id", "project_id", "tenant_id", "tid"):
            v = request.get(k)
            if v is not None and str(v).strip():
                attrs[k] = str(v).strip()
        org_role = request.get("_xwauth_org_member_role")
        if org_role:
            attrs["roles"] = [org_role]
        auth_sub = request.get("_xwauth_authorize_subject_id")
        code_user_id = str(auth_sub).strip() if auth_sub else None
        code_obj = SimpleNamespace(
            code=authorization_code,
            client_id=request["client_id"],
            redirect_uri=request["redirect_uri"],
            scopes=scopes,
            code_challenge=request.get("code_challenge"),
            code_challenge_method=request.get("code_challenge_method"),
            expires_at=expires_at,
            created_at=now,
            user_id=code_user_id,
            attributes=attrs,
        )
        await self._storage.save_authorization_code(code_obj)

        response_params: dict[str, str] = {"state": request["state"]}
        if "code" in rt_parts:
            response_params["code"] = authorization_code

        token_manager = getattr(self._auth, "_token_manager", None)
        access_token_str: str | None = None
        if "token" in rt_parts:
            if not token_manager:
                raise XWOAuthError(
                    "Token manager not configured",
                    error_code="server_error",
                    error_description="Cannot issue access_token from authorize",
                )
            token_claims = {
                "tenant_id": attrs.get("tenant_id") or attrs.get("tid"),
                "tid": attrs.get("tid") or attrs.get("tenant_id"),
                "org_id": attrs.get("org_id") or attrs.get("organization_id"),
                "organization_id": attrs.get("organization_id") or attrs.get("org_id"),
                "project_id": attrs.get("project_id") or attrs.get("application_id"),
                "roles": attrs.get("roles", []),
                "aal": attrs.get("aal"),
                "amr": attrs.get("amr", []),
            }
            token_claims = {k: v for k, v in token_claims.items() if v not in (None, [], "")}
            session_id = attrs.get("session_id")
            access_token_str = await token_manager.generate_access_token(
                user_id=code_user_id,
                client_id=request["client_id"],
                scopes=scopes,
                session_id=session_id,
                additional_claims=token_claims or None,
            )
            response_params["access_token"] = access_token_str
            response_params["token_type"] = "Bearer"
            response_params["expires_in"] = str(int(self._config.access_token_lifetime))

        if "id_token" in rt_parts:
            if not token_manager:
                raise XWOAuthError(
                    "Token manager not configured",
                    error_code="server_error",
                    error_description="Cannot issue id_token from authorize",
                )
            issuer = str(getattr(self._config, "oidc_issuer", "") or "").strip()
            id_token = await token_manager.generate_id_token(
                sub=str(code_user_id),
                client_id=request["client_id"],
                issuer=issuer,
                nonce=str(request["nonce"]),
                authorization_code=authorization_code if "code" in rt_parts else None,
                access_token_for_hash=access_token_str,
            )
            response_params["id_token"] = id_token

        if effective_rm == "form_post":
            return {
                "response_mode": "form_post",
                "redirect_uri": request["redirect_uri"],
                "form_fields": response_params,
                "code": authorization_code if "code" in rt_parts else None,
                "state": request["state"],
            }

        redirect_url = _append_redirect_params(
            request["redirect_uri"], response_params, effective_rm
        )
        result: dict[str, Any] = {
            "redirect_uri": redirect_url,
            "state": request["state"],
        }
        if "code" in rt_parts:
            result["code"] = authorization_code
        return result

    async def _process_token_exchange(self, request: dict[str, Any]) -> dict[str, Any]:
        """Exchange code for tokens; verify PKCE, redirect_uri, client_id; one-time use."""
        code = request["code"]
        redirect_uri = request["redirect_uri"]
        client_id = request["client_id"]
        code_verifier = request["code_verifier"]
        stored = await self._storage.get_authorization_code(code)
        if not stored:
            raise XWOAuthError(
                "Invalid or expired authorization code",
                error_code="invalid_grant",
                error_description="The provided authorization grant is invalid, expired, or revoked",
            )
        expires_at = stored.expires_at
        if hasattr(expires_at, "timestamp"):
            exp_ts = expires_at.timestamp()
        else:
            exp_ts = expires_at if isinstance(expires_at, (int, float)) else 0
        if exp_ts and datetime.now(timezone.utc).timestamp() > exp_ts:
            await self._storage.delete_authorization_code(code)
            raise XWOAuthError(
                "Authorization code expired",
                error_code="invalid_grant",
                error_description="The provided authorization grant has expired",
            )
        if stored.client_id != client_id:
            await self._storage.delete_authorization_code(code)
            raise XWOAuthError(
                "client_id mismatch",
                error_code="invalid_grant",
                error_description="client_id does not match authorization code",
            )
        if stored.redirect_uri != redirect_uri:
            await self._storage.delete_authorization_code(code)
            raise XWOAuthError(
                "redirect_uri mismatch",
                error_code="invalid_grant",
                error_description="redirect_uri does not match authorization request",
            )
        challenge = getattr(stored, "code_challenge", None) or (stored.attributes or {}).get("code_challenge")
        method = getattr(stored, "code_challenge_method", None) or (stored.attributes or {}).get("code_challenge_method") or "S256"
        if getattr(self._config, "pkce_s256_only", True):
            method = "S256"
        if challenge:
            PKCE.verify_code_challenge(code_verifier, challenge, method)
        await self._storage.delete_authorization_code(code)
        scopes = getattr(stored, "scopes", None) or []
        if isinstance(scopes, str):
            scopes = scopes.split() if scopes else []
        user_id = getattr(stored, "user_id", None)
        code_attrs = getattr(stored, "attributes", {}) or {}
        session_id = code_attrs.get("session_id")
        token_claims = {
            "tenant_id": code_attrs.get("tenant_id") or code_attrs.get("tid"),
            "tid": code_attrs.get("tid") or code_attrs.get("tenant_id"),
            "org_id": code_attrs.get("org_id") or code_attrs.get("organization_id"),
            "organization_id": code_attrs.get("organization_id") or code_attrs.get("org_id"),
            "project_id": code_attrs.get("project_id") or code_attrs.get("application_id"),
            "roles": code_attrs.get("roles", []),
            "aal": code_attrs.get("aal"),
            "amr": code_attrs.get("amr", []),
        }
        token_claims = {k: v for k, v in token_claims.items() if v not in (None, [], "")}
        token_manager = getattr(self._auth, "_token_manager", None)
        if not token_manager:
            logger.warning("Token manager not available; returning placeholder token")
            return {
                "access_token": "placeholder_token",
                "token_type": "Bearer",
                "expires_in": self._config.access_token_lifetime,
                "scope": " ".join(scopes) if scopes else None,
            }
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
                attributes={"grant_type": "authorization_code", "client_id": client_id},
                tenant_id=token_claims.get("tenant_id") or token_claims.get("tid"),
                org_id=token_claims.get("org_id") or token_claims.get("organization_id"),
                project_id=token_claims.get("project_id"),
            )
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self._config.access_token_lifetime,
            "scope": " ".join(scopes) if scopes else None,
        }
        # Generate refresh token if user_id is present (user authorization, not client-only)
        if user_id:
            refresh_token = await token_manager.generate_refresh_token(
                user_id=user_id,
                client_id=client_id,
                refresh_metadata=_refresh_metadata_from_code_attrs(code_attrs),
            )
            response["refresh_token"] = refresh_token
        return response

    def _generate_authorization_code(self) -> str:
        """Generate cryptographically random authorization code."""
        random_bytes = secure_random(32)
        return base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")
