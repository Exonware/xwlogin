# exonware/xwlogin/handlers/mixins/passkeys.py
"""WebAuthn/Passkeys: register/login options and verify."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse

from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.io.serialization.formats.text import json as xw_json
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwlogin.authentication.mfa_webauthn_audit import audit_webauthn_event

from exonware.xwlogin.handlers.connector_http import (
    AUTH_TAGS,
    XWAuthError,
    XWInvalidRequestError,
    UserLifecycle,
    get_auth,
    get_current_user_id,
    oauth_error_to_http,
    track_critical_handler,
)


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


def _build_webauthn_manager(request: Request, auth: Any) -> Any:
    """Resolve rp_id and origin allowlist from app.state and config (explicit-first)."""
    from exonware.xwlogin.authentication.webauthn import WebAuthnManager

    cfg = auth.config
    issuer = (getattr(request.app.state, "xwauth_issuer", None) or "").strip()
    rp_id = getattr(request.app.state, "xwauth_rp_id", None) or cfg.webauthn_rp_id
    origins: list[str] = []
    state_o = getattr(request.app.state, "xwauth_allowed_origins", None)
    if state_o:
        origins.extend(str(x).rstrip("/") for x in state_o if x)
    for o in cfg.webauthn_allowed_origins or []:
        o = str(o).rstrip("/")
        if o and o not in origins:
            origins.append(o)
    primary = getattr(request.app.state, "xwauth_origin", None) or cfg.webauthn_origin
    if primary:
        p = str(primary).rstrip("/")
        if p not in origins:
            origins.insert(0, p)
    allow = bool(getattr(cfg, "webauthn_allow_insecure_defaults", False))
    iss = issuer
    if iss and "://" not in iss:
        iss = f"https://{iss}"
    if not rp_id and iss:
        rp_id = urlparse(iss).hostname
    if not origins and iss:
        origins = [iss.rstrip("/")]
    if allow:
        rp_id = rp_id or "localhost"
        if not origins:
            origins = ["http://localhost:8000"]
    if not rp_id or not origins:
        raise XWInvalidRequestError(
            "WebAuthn is not configured (webauthn_rp_id and allowed origins required)",
            error_code="webauthn_misconfigured",
            error_description="Set app.state or XWAuthConfig webauthn_* or webauthn_allow_insecure_defaults for dev",
        )
    return WebAuthnManager(
        auth,
        rp_name=getattr(cfg, "webauthn_rp_name", "xwauth"),
        rp_id=rp_id,
        expected_origins=origins,
    )


_PASSKEY_LOGIN_UNIFORM_CODES = frozenset(
    {
        "invalid_challenge",
        "verification_failed",
        "no_credentials",
        "invalid_credential",
        "user_not_found",
        "webauthn_clone_detected",
        "webauthn_synced_passkey_rejected",
    }
)


def _maybe_uniform_passkey_login_error(auth: Any, exc: Exception) -> JSONResponse | None:
    if not getattr(auth.config, "webauthn_anti_enumeration_login", True):
        return None
    code = getattr(exc, "error_code", None)
    if not isinstance(code, str) or code not in _PASSKEY_LOGIN_UNIFORM_CODES:
        return None
    return _oauth_json_error(
        "access_denied",
        "Passkey authentication could not be completed",
        status_code=400,
    )


def _enforce_origin_header(request: Request, webauthn_manager: Any) -> None:
    hdr = request.headers.get("origin") or request.headers.get("Origin")
    if not hdr:
        return
    h = hdr.rstrip("/")
    allowed = {str(o).rstrip("/") for o in (webauthn_manager._expected_origins or [])}
    if h not in allowed:
        raise XWInvalidRequestError(
            "Request Origin is not in the WebAuthn allowlist",
            error_code="invalid_origin",
        )


@XWAction(
    operationId="auth_passkeys_register_options",
    summary="Generate Passkey Registration Options",
    method="POST",
    description="Generate WebAuthn registration options (challenge) for passkey registration.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Registration options generated"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
    },
    in_types={
        "user_id": {"type": "string", "description": "User identifier (optional if authenticated)", "maxLength": 256},
        "user_email": {"type": "string", "format": "email", "description": "User email (required)", "maxLength": 256},
        "user_name": {"type": "string", "description": "User display name", "maxLength": 256},
        "authenticator_attachment": {"type": "string", "enum": ["platform", "cross-platform"], "maxLength": 32},
    },
)
async def passkeys_register_options(request: Request) -> Any:
    """Generate WebAuthn registration options."""
    try:
        body = await request.body()
        if body:
            data = xw_json.loads(body.decode("utf-8"))
        else:
            form = await request.form()
            data = dict(form)
    except Exception as e:
        return _oauth_json_error("invalid_request", f"Invalid JSON: {e!s}")
    user_id = data.get("user_id")
    user_email = data.get("user_email")
    user_name = data.get("user_name")
    authenticator_attachment = data.get("authenticator_attachment")
    if not user_id:
        user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error(
            "unauthorized",
            "user_id required or authentication required",
            status_code=401,
        )
    if not user_email:
        return _oauth_json_error("invalid_request", "user_email is required")
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "auth_passkeys_register_options"):
            webauthn_manager = _build_webauthn_manager(request, auth)
            options = await webauthn_manager.generate_registration_options(
                user_id=user_id,
                user_email=user_email,
                user_name=user_name,
                authenticator_attachment=authenticator_attachment,
            )
            return options
    except XWInvalidRequestError as e:
        return _oauth_json_error(
            getattr(e, "error_code", "invalid_request"),
            getattr(e, "error_description", None) or str(e),
            status_code=400,
        )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(
    operationId="auth_passkeys_register_verify",
    summary="Verify Passkey Registration",
    method="POST",
    description="""
    Verify WebAuthn registration response and store passkey.
    Include webauthn_challenge_handle from the registration options response.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Passkey registered successfully"},
        400: {"description": "Invalid request or verification failed"},
        401: {"description": "Authentication required"},
    },
    rate_limit="20/hour",
    audit=True,
    in_types={
        "user_id": {"type": "string", "description": "User identifier", "maxLength": 256},
        "webauthn_challenge_handle": {
            "type": "string",
            "description": "Opaque handle from registration options",
            "maxLength": 256,
        },
    },
)
async def passkeys_register_verify(request: Request) -> Any:
    """Verify WebAuthn registration and store passkey."""
    try:
        body = await request.body()
        if body:
            data = xw_json.loads(body.decode("utf-8"))
        else:
            return _oauth_json_error("invalid_request", "Request body required")
    except Exception as e:
        return _oauth_json_error("invalid_request", f"Invalid JSON: {e!s}")
    user_id = data.get("user_id")
    registration_response = data.get("registration_response")
    challenge_handle = data.get("webauthn_challenge_handle")
    if not user_id:
        user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error(
            "unauthorized",
            "user_id required or authentication required",
            status_code=401,
        )
    if not registration_response:
        return _oauth_json_error("invalid_request", "registration_response is required")
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "auth_passkeys_register_verify"):
            webauthn_manager = _build_webauthn_manager(request, auth)
            _enforce_origin_header(request, webauthn_manager)
            result = await webauthn_manager.verify_registration(
                user_id=user_id,
                registration_response=registration_response,
                challenge_handle=challenge_handle,
            )
            return result
    except (XWInvalidRequestError, XWAuthError) as e:
        await audit_webauthn_event(
            auth,
            "webauthn.register.failed",
            user_id=user_id,
            attributes={"error_code": getattr(e, "error_code", None)},
        )
        return _oauth_json_error(
            getattr(e, "error_code", "invalid_request"),
            getattr(e, "error_description", None) or str(e),
            status_code=400,
        )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(
    operationId="auth_passkeys_login_options",
    summary="Generate Passkey Authentication Options",
    method="POST",
    description="Generate WebAuthn authentication options; returns webauthn_challenge_handle for verify.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    rate_limit="100/hour",
    audit=True,
    in_types={
        "user_id": {"type": "string", "description": "User identifier (optional)", "maxLength": 256},
        "email": {"type": "string", "format": "email", "description": "User email (optional)", "maxLength": 256},
    },
)
async def passkeys_login_options(request: Request) -> Any:
    """Generate WebAuthn authentication options."""
    try:
        body = await request.body()
        if body:
            data = xw_json.loads(body.decode("utf-8"))
        else:
            form = await request.form()
            data = dict(form)
    except Exception as e:
        return _oauth_json_error("invalid_request", f"Invalid JSON: {e!s}")
    user_id = data.get("user_id")
    email = data.get("email")
    auth = get_auth(request)
    if email and not user_id:
        user_lifecycle = UserLifecycle(auth)
        user = await user_lifecycle.get_user_by_email(email)
        if user:
            user_id = user.id
    try:
        async with track_critical_handler(request, "auth_passkeys_login_options"):
            webauthn_manager = _build_webauthn_manager(request, auth)
            allow_credentials = None
            if user_id:
                user_lifecycle = UserLifecycle(auth)
                user = await user_lifecycle.get_user(user_id)
                if user:
                    credentials = user.attributes.get("webauthn_credentials", [])
                    allow_credentials = [
                        {"id": cred.get("credential_id"), "type": "public-key"}
                        for cred in credentials
                    ]
            options = await webauthn_manager.generate_authentication_options(
                user_id=user_id,
                allow_credentials=allow_credentials,
            )
            return options
    except XWInvalidRequestError as e:
        return _oauth_json_error(
            getattr(e, "error_code", "invalid_request"),
            getattr(e, "error_description", None) or str(e),
            status_code=400,
        )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(
    operationId="auth_passkeys_login_verify",
    summary="Verify Passkey Authentication",
    method="POST",
    description=(
        "Verify WebAuthn authentication; include webauthn_challenge_handle from login options. "
        "When webauthn_discoverable_login is true, user_id may be omitted if authentication_response.id "
        "matches a registered credential (discoverable / conditional UI flow)."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    rate_limit="100/hour",
    audit=True,
    in_types={
        "user_id": {
            "type": "string",
            "description": "User identifier (optional when discoverable login resolves credential id)",
            "maxLength": 256,
        },
        "webauthn_challenge_handle": {
            "type": "string",
            "description": "Opaque handle from authentication options",
            "maxLength": 256,
        },
    },
)
async def passkeys_login_verify(request: Request) -> Any:
    """Verify WebAuthn authentication and issue token."""
    try:
        body = await request.body()
        if body:
            data = xw_json.loads(body.decode("utf-8"))
        else:
            return _oauth_json_error("invalid_request", "Request body required")
    except Exception as e:
        return _oauth_json_error("invalid_request", f"Invalid JSON: {e!s}")
    user_id = data.get("user_id")
    authentication_response = data.get("authentication_response")
    challenge_handle = data.get("webauthn_challenge_handle")
    if not authentication_response:
        return _oauth_json_error("invalid_request", "authentication_response is required")
    auth = get_auth(request)
    resolved_uid = (str(user_id).strip() if user_id else "") or None
    if not resolved_uid and getattr(auth.config, "webauthn_discoverable_login", True):
        from exonware.xwlogin.authentication.webauthn_credential_index import (
            resolve_user_for_webauthn_credential,
        )

        resolved_uid = await resolve_user_for_webauthn_credential(
            auth, authentication_response.get("id")
        )
    if not resolved_uid:
        if getattr(auth.config, "webauthn_anti_enumeration_login", True):
            return _oauth_json_error(
                "access_denied",
                "Passkey authentication could not be completed",
                status_code=400,
            )
        return _oauth_json_error(
            "invalid_request",
            "user_id is required unless discoverable login can resolve the credential id",
        )
    user_id = resolved_uid
    try:
        async with track_critical_handler(request, "auth_passkeys_login_verify"):
            webauthn_manager = _build_webauthn_manager(request, auth)
            _enforce_origin_header(request, webauthn_manager)
            result = await webauthn_manager.verify_authentication(
                user_id=user_id,
                authentication_response=authentication_response,
                challenge_handle=challenge_handle,
            )
            return result
    except (XWInvalidRequestError, XWAuthError) as e:
        await audit_webauthn_event(
            auth,
            "webauthn.login.failed",
            user_id=user_id,
            attributes={"error_code": getattr(e, "error_code", None)},
        )
        uniform = _maybe_uniform_passkey_login_error(auth, e)
        if uniform is not None:
            return uniform
        return _oauth_json_error(
            getattr(e, "error_code", "invalid_request"),
            getattr(e, "error_description", None) or str(e),
            status_code=400,
        )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
