# exonware/xwlogin/handlers/mixins/sso_providers.py
"""
SSO OAuth callbacks.
Handlers for Google, Microsoft, Apple, GitHub, Discord, Slack are explicit (custom
email/attrs). All other providers use a generic OAuth2 callback; provider names
come from providers.callback_providers discovery (and config.providers). All
callbacks use the Providers OpenAPI tag for docs grouping.
"""

from __future__ import annotations
from typing import Any

from collections.abc import Callable
from exonware.xwapi.http import Depends, Form, Header, Request
from exonware.xwapi.http import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwlogin.handlers.connector_http import (
    AUTH_PREFIX,
    PROVIDERS_TAGS,
    get_auth,
    get_user_lifecycle,
    oauth_error_to_http,
)
# Providers with custom handlers (email/attrs). Do not create generic handlers for these.
EXPLICIT_SSO_PROVIDERS = frozenset({
    "google", "microsoft", "apple", "github", "discord", "slack", "saml",
})

_EXPLICIT_PROVIDER_EMAIL_KEYS: dict[str, tuple[str, ...]] = {
    "google": ("email",),
    "microsoft": ("email", "userPrincipalName"),
    "apple": ("email",),
    "github": ("email",),
    "discord": ("email",),
    "slack": ("email",),
}

_EXPLICIT_PROVIDER_EXTRA_ATTRS: dict[str, tuple[str, ...]] = {
    "google": ("picture",),
    "microsoft": (),
    "apple": (),
    "github": ("login", "avatar_url"),
    "discord": ("username", "avatar_url", "verified"),
    "slack": ("real_name", "display_name", "avatar_url", "team_id", "team_name"),
}

def _oauth_json_error(
    error: str,
    description: str,
    *,
    status_code: int | None = None,
) -> JSONResponse:
    body, status = oauth_error_response(
        error,
        description,
        status_code=status_code,
    )
    return JSONResponse(content=body, status_code=status)

async def _explicit_oauth_callback_impl(request: Request, provider_name: str) -> Any:
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    if error:
        return _oauth_json_error(
            error,
            request.query_params.get("error_description", "OAuth error"),
            status_code=400,
        )
    if not code:
        return _oauth_json_error("invalid_request", "Authorization code is required", status_code=400)

    auth = get_auth(request)
    try:
        has_provider = bool(getattr(auth, "has_provider", lambda _name: False)(provider_name))
        if not has_provider:
            return _oauth_json_error(
                "not_configured",
                f"{provider_name.title()} OAuth not configured",
                status_code=503,
            )
        redirect_uri = str(request.url).split("?")[0]
        identity = await auth.complete_federation_login(
            provider_name=provider_name,
            code=code,
            redirect_uri=redirect_uri,
        )
        user_info = dict(identity.claims or {})

        email = None
        for key in _EXPLICIT_PROVIDER_EMAIL_KEYS.get(provider_name, ("email",)):
            if user_info.get(key):
                email = user_info.get(key)
                break

        extra_attrs = {
            key: user_info.get(key)
            for key in _EXPLICIT_PROVIDER_EXTRA_ATTRS.get(provider_name, ())
            if user_info.get(key) is not None
        }
        response = await _link_or_create_federated_identity(
            auth,
            provider_name=provider_name,
            subject_id=str(identity.subject_id or user_info.get("id") or user_info.get("sub") or ""),
            email=email,
            claims=user_info,
            tenant_id=identity.tenant_id,
            extra_attributes=extra_attrs,
        )
        if isinstance(response, dict):
            response = dict(response)
            if user_info.get("access_token") is not None:
                response["access_token"] = user_info.get("access_token")
        return response
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
@XWAction(
    operationId="auth_google_callback",
    summary="Google OAuth Callback",
    method="GET",
    description="Handle Google OAuth callback.",
    tags=PROVIDERS_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "code": {"type": "string", "description": "Authorization code", "minLength": 1, "maxLength": 2048},
        "state": {"type": "string", "description": "State for CSRF", "minLength": 1, "maxLength": 512},
        "error": {"type": "string", "description": "OAuth error code", "maxLength": 256},
        "error_description": {"type": "string", "description": "OAuth error description", "maxLength": 1024},
    },
)
async def google_callback(request: Request) -> Any:
    return await _explicit_oauth_callback_impl(request, "google")
# -----------------------------------------------------------------------------
# GET /auth/microsoft/callback
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_microsoft_callback",
    summary="Microsoft OAuth Callback",
    method="GET",
    description="Handle Microsoft OAuth callback.",
    tags=PROVIDERS_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "code": {
            "type": "string",
            "description": "Authorization code from OAuth provider",
            "minLength": 1,
            "maxLength": 2048
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection",
            "minLength": 1,
            "maxLength": 512
        },
        "error": {
            "type": "string",
            "description": "OAuth error code (if authorization failed)",
            "maxLength": 256
        },
        "error_description": {
            "type": "string",
            "description": "OAuth error description",
            "maxLength": 1024
        }
    },
)
async def microsoft_callback(request: Request) -> Any:
    return await _explicit_oauth_callback_impl(request, "microsoft")
# -----------------------------------------------------------------------------
# GET /auth/apple/callback
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_apple_callback",
    summary="Apple OAuth Callback",
    method="GET",
    description="Handle Apple OAuth callback.",
    tags=PROVIDERS_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "code": {
            "type": "string",
            "description": "Authorization code from OAuth provider",
            "minLength": 1,
            "maxLength": 2048
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection",
            "minLength": 1,
            "maxLength": 512
        },
        "error": {
            "type": "string",
            "description": "OAuth error code (if authorization failed)",
            "maxLength": 256
        },
        "error_description": {
            "type": "string",
            "description": "OAuth error description",
            "maxLength": 1024
        }
    },
)
async def apple_callback(request: Request) -> Any:
    return await _explicit_oauth_callback_impl(request, "apple")
# -----------------------------------------------------------------------------
# GET /auth/github/callback
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_github_callback",
    summary="GitHub OAuth Callback",
    method="GET",
    description="Handle GitHub OAuth callback.",
    tags=PROVIDERS_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "code": {
            "type": "string",
            "description": "Authorization code from OAuth provider",
            "minLength": 1,
            "maxLength": 2048
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection",
            "minLength": 1,
            "maxLength": 512
        },
        "error": {
            "type": "string",
            "description": "OAuth error code (if authorization failed)",
            "maxLength": 256
        },
        "error_description": {
            "type": "string",
            "description": "OAuth error description",
            "maxLength": 1024
        }
    },
)
async def github_callback(request: Request) -> Any:
    return await _explicit_oauth_callback_impl(request, "github")
# -----------------------------------------------------------------------------
# GET /auth/discord/callback
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_discord_callback",
    summary="Discord OAuth Callback",
    method="GET",
    description="Handle Discord OAuth callback.",
    tags=PROVIDERS_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "code": {
            "type": "string",
            "description": "Authorization code from OAuth provider",
            "minLength": 1,
            "maxLength": 2048
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection",
            "minLength": 1,
            "maxLength": 512
        },
        "error": {
            "type": "string",
            "description": "OAuth error code (if authorization failed)",
            "maxLength": 256
        },
        "error_description": {
            "type": "string",
            "description": "OAuth error description",
            "maxLength": 1024
        }
    },
)
async def discord_callback(request: Request) -> Any:
    return await _explicit_oauth_callback_impl(request, "discord")
# -----------------------------------------------------------------------------
# GET /auth/slack/callback
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_slack_callback",
    summary="Slack OAuth Callback",
    method="GET",
    description="Handle Slack OAuth callback.",
    tags=PROVIDERS_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "code": {
            "type": "string",
            "description": "Authorization code from OAuth provider",
            "minLength": 1,
            "maxLength": 2048
        },
        "state": {
            "type": "string",
            "description": "State parameter for CSRF protection",
            "minLength": 1,
            "maxLength": 512
        },
        "error": {
            "type": "string",
            "description": "OAuth error code (if authorization failed)",
            "maxLength": 256
        },
        "error_description": {
            "type": "string",
            "description": "OAuth error description",
            "maxLength": 1024
        }
    },
)
async def slack_callback(request: Request) -> Any:
    return await _explicit_oauth_callback_impl(request, "slack")
# -----------------------------------------------------------------------------
# Shared OAuth2 callback logic for registry-based providers (Twitter, LinkedIn, etc.)
# -----------------------------------------------------------------------------
_OAUTH2_CALLBACK_IN_TYPES = {
    "code": {"type": "string", "description": "Authorization code", "minLength": 1, "maxLength": 2048},
    "state": {"type": "string", "description": "State for CSRF", "minLength": 1, "maxLength": 512},
    "error": {"type": "string", "description": "OAuth error code", "maxLength": 256},
    "error_description": {"type": "string", "description": "OAuth error description", "maxLength": 1024},
}

async def _link_or_create_federated_identity(
    auth: Any,
    *,
    provider_name: str,
    subject_id: str,
    email: str | None,
    claims: dict[str, Any],
    tenant_id: str | None = None,
    extra_attributes: dict[str, Any] | None = None,
) -> Any:
    user_lifecycle = get_user_lifecycle(auth)
    if not email:
        return _oauth_json_error("no_email", f"{provider_name.title()} account has no email", status_code=400)
    existing = await user_lifecycle.get_user_by_email(email)
    attrs = {f"{provider_name}_id": subject_id or claims.get("id"), "name": claims.get("name")}
    for k in ("username", "picture", "avatar_url"):
        if claims.get(k) is not None:
            attrs[k] = claims[k]
    if tenant_id:
        attrs["tenant_id"] = tenant_id
    if extra_attributes:
        for k, v in extra_attributes.items():
            if v is not None:
                attrs[k] = v
    if existing:
        return {
            "user_id": existing.id,
            "email": email,
            "message": f"{provider_name.title()} account linked successfully",
        }
    new_user = await user_lifecycle.create_user(email=email, attributes=attrs)
    return {
        "user_id": new_user.id,
        "email": email,
        "message": f"User created from {provider_name.title()} account",
    }

async def _oauth2_callback_impl(request: Request, provider_name: str) -> Any:
    """Handle OAuth2 callback for a registry-based provider. Used by Twitter, LinkedIn, Reddit, etc."""
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    if error:
        return _oauth_json_error(
            error,
            request.query_params.get("error_description", "OAuth error"),
            status_code=400,
        )
    if not code:
        return _oauth_json_error("invalid_request", "Authorization code is required", status_code=400)
    auth = get_auth(request)
    try:
        redirect_uri = str(request.url).split("?")[0]
        federated_login = getattr(auth, "complete_federation_login", None)
        if not callable(federated_login):
            return _oauth_json_error("not_supported", "Federation broker not available", status_code=503)
        identity = await federated_login(
            provider_name,
            code=code,
            redirect_uri=redirect_uri,
        )
        user_info = dict(identity.claims or {})
        return await _link_or_create_federated_identity(
            auth,
            provider_name=provider_name,
            subject_id=identity.subject_id,
            email=identity.email or user_info.get("email"),
            claims=user_info,
            tenant_id=identity.tenant_id,
        )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)

@XWAction(
    operationId="auth_saml_callback",
    summary="SAML Assertion Consumer Service Callback",
    method="POST",
    description="Handle SAML SSO callback using federation broker normalization.",
    tags=PROVIDERS_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "SAMLResponse": {"type": "string", "description": "Base64 encoded SAMLResponse", "minLength": 1},
        "RelayState": {"type": "string", "description": "Opaque relay state", "maxLength": 4096},
    },
)
async def saml_callback(
    request: Request,
    SAMLResponse: str | None = Form(default=None),
    RelayState: str | None = Form(default=None),
) -> Any:
    saml_response = SAMLResponse or request.query_params.get("SAMLResponse")
    relay_state = RelayState or request.query_params.get("RelayState")
    if not saml_response:
        return _oauth_json_error("invalid_request", "SAMLResponse is required", status_code=400)
    auth = get_auth(request)
    try:
        complete_saml = getattr(auth, "complete_federation_saml", None)
        if not callable(complete_saml):
            return _oauth_json_error("not_supported", "SAML federation is not supported", status_code=503)
        identity = await complete_saml(
            "saml",
            saml_response=saml_response,
            relay_state=relay_state,
        )
        claims = dict(identity.claims or {})
        return await _link_or_create_federated_identity(
            auth,
            provider_name="saml",
            subject_id=identity.subject_id,
            email=identity.email or claims.get("email"),
            claims=claims,
            tenant_id=identity.tenant_id,
        )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)

def _make_oauth2_callback(provider_name: str, operation_id: str, summary: str) -> Callable[..., Any]:
    """Create an XWAction-decorated OAuth2 callback handler for a given provider."""
    @XWAction(
        operationId=operation_id,
        summary=summary,
        method="GET",
        description=f"Handle {provider_name.title()} OAuth callback.",
        tags=PROVIDERS_TAGS,
        engine="fastapi",
        profile=ActionProfile.ENDPOINT,
        in_types=_OAUTH2_CALLBACK_IN_TYPES,
    )
    async def _handler(request: Request) -> Any:
        return await _oauth2_callback_impl(request, provider_name)
    return _handler

def build_dynamic_callback_handlers(provider_names: list[str]) -> dict[str, Callable[..., Any]]:
    """Build generic OAuth2 callback handlers for providers not in EXPLICIT_SSO_PROVIDERS."""
    out: dict[str, Callable[..., Any]] = {}
    for name in provider_names:
        if name in EXPLICIT_SSO_PROVIDERS:
            continue
        op_id = f"auth_{name}_callback"
        summary = f"{name.title()} OAuth Callback"
        out[name] = _make_oauth2_callback(name, op_id, summary)
    return out
# Explicit handlers (custom logic). Used by get_provider_callback_routes.
_EXPLICIT_HANDLERS = {
    "google": None,   # set below after definition
    "microsoft": None,
    "apple": None,
    "github": None,
    "discord": None,
    "slack": None,
    "saml": None,
}

def _register_explicit_handlers() -> None:
    _EXPLICIT_HANDLERS["google"] = google_callback
    _EXPLICIT_HANDLERS["microsoft"] = microsoft_callback
    _EXPLICIT_HANDLERS["apple"] = apple_callback
    _EXPLICIT_HANDLERS["github"] = github_callback
    _EXPLICIT_HANDLERS["discord"] = discord_callback
    _EXPLICIT_HANDLERS["slack"] = slack_callback
    _EXPLICIT_HANDLERS["saml"] = saml_callback

def get_provider_callback_routes(auth: Any, auth_prefix: str) -> list[tuple[str, str, Callable[..., Any]]]:
    """
    Return (path, method, handler) for all SSO callback endpoints.
    Uses providers.callback_providers OAUTH2_CALLBACK_PROVIDER_NAMES plus
    auth.config.providers. Explicit providers (google, etc.) use custom handlers;
    the rest use the generic OAuth2 callback.
    """
    from exonware.xwlogin.providers.callback_providers import get_oauth2_callback_provider_names
    extra = getattr(auth.config, "providers", None) or []
    names = get_oauth2_callback_provider_names(extra=extra)
    _register_explicit_handlers()
    dynamic = build_dynamic_callback_handlers(names)
    routes: list[tuple[str, str, Callable[..., Any]]] = []
    prefix = (auth_prefix or AUTH_PREFIX).rstrip("/")
    for n in names:
        if n in _EXPLICIT_HANDLERS and _EXPLICIT_HANDLERS[n] is not None:
            method = "POST" if n == "saml" else "GET"
            routes.append((f"{prefix}/{n}/callback", method, _EXPLICIT_HANDLERS[n]))
        elif n in dynamic:
            routes.append((f"{prefix}/{n}/callback", "GET", dynamic[n]))
    if "saml" not in names:
        routes.append((f"{prefix}/saml/callback", "POST", saml_callback))
    return routes
