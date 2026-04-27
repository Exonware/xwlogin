# exonware/xwauth/handlers/mixins/oauth2_extended.py
"""
OAuth 2.0 / OIDC endpoints that complete the surface on top of ``auth_core``.

These cover the less-common but still RFC-defined endpoints:

* Device verification UI — RFC 8628 §3.3 (the page the user visits after
  starting a device-code flow to approve the device).
* CIBA backchannel authorize — OpenID CIBA Core 1.0.
* OIDC Session Management ``check_session_iframe`` — OpenID Session Management 1.0.
* OIDC Back-Channel Logout receiver — OpenID Back-Channel Logout 1.0.

The implementations are intentionally minimal — they answer with spec-compliant
JSON/HTML responses and delegate to ``XWAuth`` internals where the server
already has the primitive (e.g. ``device_code_lookup_by_user_code``). Where the
full flow requires infrastructure the project hasn't shipped yet (push
notifications for CIBA, logout-token verification), the endpoint returns
``501 not_implemented`` with a clear ``hint`` so integrators can spot exactly
which piece is missing rather than getting a 404.
"""

from __future__ import annotations

import html
import time
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from exonware.xwsystem.security.oauth_errors import oauth_error_response

from .._common import AUTH_TAGS, get_auth


def _oauth_json_error(
    error: str,
    description: str,
    *,
    status_code: int | None = None,
    **extra: Any,
) -> JSONResponse:
    body, status = oauth_error_response(error, description, status_code=status_code)
    if extra:
        body.update(extra)
    return JSONResponse(content=body, status_code=status)


# -----------------------------------------------------------------------------
# GET/POST /v1/oauth2/device  —  RFC 8628 §3.3 (user verification page)
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oauth2_device_verify",
    summary="Device verification page (RFC 8628)",
    method="GET",
    description=(
        "Human-facing verification endpoint for the Device Authorization Grant (RFC 8628). "
        "The user lands here after scanning a QR code or typing the verification URL on "
        "their phone. Supply ``user_code`` (directly in the URL or the form) to approve "
        "the device."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Verification page rendered or approval JSON returned"},
        400: {"description": "Missing or invalid user_code"},
        404: {"description": "user_code does not match an active device flow"},
    },
    in_types={
        "user_code": {
            "type": "string",
            "description": "User code from the device authorization response",
            "minLength": 1,
            "maxLength": 32,
            "default": None,
        },
        "action": {
            "type": "string",
            "description": "Approval action: 'approve' or 'deny' (POST only)",
            "enum": ["approve", "deny"],
            "default": None,
        },
    },
)
async def device_verify(request: Request) -> Any:
    method = request.method.upper()
    auth = get_auth(request)

    # Pull user_code from either query string (GET) or form body (POST).
    user_code: str | None
    action: str | None = None
    if method == "POST":
        form = await request.form()
        user_code = form.get("user_code") or request.query_params.get("user_code")
        action = (form.get("action") or "approve").lower()
    else:
        user_code = request.query_params.get("user_code")

    if method == "GET":
        # Render a small HTML form. Auto-fills user_code from the query string
        # so ``verification_uri_complete`` links work out of the box.
        pre_filled = html.escape(user_code or "")
        page = (
            "<!DOCTYPE html><html><head><title>Device verification</title>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
            "<style>body{font-family:system-ui;max-width:420px;margin:40px auto;padding:0 16px}"
            "input,button{font-size:16px;padding:8px 12px;margin:4px 0;width:100%;box-sizing:border-box}"
            "button{cursor:pointer}</style></head><body>"
            "<h2>Approve this device</h2>"
            "<p>Enter the code displayed on the device to sign it in to your account.</p>"
            f"<form method='POST'><input name='user_code' placeholder='XXXX-YYYY' value='{pre_filled}' required/>"
            "<button name='action' value='approve'>Approve</button>"
            "<button name='action' value='deny' formnovalidate>Deny</button></form>"
            "</body></html>"
        )
        return HTMLResponse(content=page, status_code=200)

    if not user_code:
        return _oauth_json_error("invalid_request", "user_code is required", status_code=400)

    try:
        async with track_critical_handler(request, "oauth2_device_verify"):
            # Hand off to the auth server if it knows how to resolve/approve;
            # otherwise emit a 501 so integrators see exactly what to wire up.
            resolver = getattr(auth, "device_code_lookup_by_user_code", None)
            approver = getattr(auth, "device_code_approve", None)
            denier = getattr(auth, "device_code_deny", None)
            if not callable(resolver):
                return _oauth_json_error(
                    "not_implemented",
                    "device_code_lookup_by_user_code is not implemented on this server",
                    status_code=501,
                    hint="Wire device-code approval in the XWAuth facade",
                )
            device_code = await resolver(user_code)
            if not device_code:
                return _oauth_json_error(
                    "not_found",
                    "user_code does not match an active device authorization",
                    status_code=404,
                )
            if action == "deny":
                if callable(denier):
                    await denier(device_code)
                return {"user_code": user_code, "status": "denied"}
            # Default to approve. If the server needs a user_id (signed-in session),
            # that must be resolved from the request context; integrators that do
            # session-bound verification can override this handler.
            if callable(approver):
                user_id = request.query_params.get("user_id") or None
                await approver(device_code, user_id=user_id)
            return {"user_code": user_code, "status": "approved"}
    except Exception as e:  # noqa: BLE001
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(
    operationId="oauth2_device_verify_post",
    summary="Approve/deny a device verification (RFC 8628)",
    method="POST",
    description="POST form variant of /v1/oauth2/device — submits user_code + action.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "user_code": {"type": "string", "minLength": 1, "maxLength": 32, "default": None},
        "action": {"type": "string", "enum": ["approve", "deny"], "default": None},
    },
)
async def device_verify_post(request: Request) -> Any:
    return await device_verify(request)


# -----------------------------------------------------------------------------
# POST /v1/oauth2/bc-authorize  —  OpenID CIBA Core 1.0
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oauth2_backchannel_authorize",
    summary="CIBA backchannel authorize (OIDC CIBA Core 1.0)",
    method="POST",
    description=(
        "Client-Initiated Backchannel Authentication endpoint. Clients that cannot "
        "open a browser (IoT, voice agents, smart appliances) use this to push an "
        "authentication request to the user's authentication device. Returns "
        "``auth_req_id``; the client polls /v1/oauth2/token with "
        "``grant_type=urn:openid:params:grant-type:ciba``."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "auth_req_id issued"},
        400: {"description": "Invalid CIBA request"},
        501: {"description": "CIBA not enabled on this server"},
    },
    in_types={
        "scope": {"type": "string", "description": "Requested scopes", "default": None},
        "client_notification_token": {"type": "string", "default": None},
        "acr_values": {"type": "string", "default": None},
        "login_hint_token": {"type": "string", "default": None},
        "id_token_hint": {"type": "string", "default": None},
        "login_hint": {"type": "string", "default": None},
        "binding_message": {"type": "string", "default": None},
        "user_code": {"type": "string", "default": None},
        "requested_expiry": {"type": "integer", "default": None},
        "client_id": {"type": "string", "default": None},
        "client_secret": {"type": "string", "default": None},
    },
)
async def backchannel_authorize(request: Request) -> Any:
    form = await request.form()
    # CIBA requires at least one of login_hint / login_hint_token / id_token_hint.
    hints = [form.get("login_hint"), form.get("login_hint_token"), form.get("id_token_hint")]
    if not any(hints):
        return _oauth_json_error(
            "invalid_request",
            "One of login_hint, login_hint_token, or id_token_hint is required",
            status_code=400,
        )
    auth = get_auth(request)
    backchannel = getattr(auth, "ciba_backchannel_authorize", None)
    if not callable(backchannel):
        return _oauth_json_error(
            "not_implemented",
            "CIBA backchannel authentication is not enabled on this server",
            status_code=501,
            hint="Implement XWAuth.ciba_backchannel_authorize to activate this endpoint",
        )
    try:
        async with track_critical_handler(request, "oauth2_ciba"):
            req = {k: v for k, v in form.items() if v is not None}
            return await backchannel(req)
    except Exception as e:  # noqa: BLE001
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


# -----------------------------------------------------------------------------
# GET /v1/oidc/check_session_iframe  —  OIDC Session Management 1.0
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oidc_check_session_iframe",
    summary="OIDC check_session_iframe (Session Management 1.0)",
    method="GET",
    description=(
        "Returns the HTML iframe used by relying parties to detect single-sign-out "
        "per the OpenID Connect Session Management 1.0 specification. The iframe "
        "listens for postMessage events containing the RP's client_id and session_state "
        "and replies with 'changed', 'unchanged', or 'error'."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={200: {"description": "HTML iframe document"}},
    in_types={},
)
async def check_session_iframe(request: Request) -> Response:
    # Static HTML document. The inline script honors the OIDC Session Management
    # spec: receive `{client_id} {session_state}` via postMessage, compare against
    # the current session cookie's hash, post back one of:
    #   "changed" — user signed in/out somewhere else
    #   "unchanged" — session is stable
    #   "error" — malformed request or policy rejection
    html_doc = """<!DOCTYPE html>
<html><head><title>check_session_iframe</title><meta charset="utf-8"/></head>
<body>
<script>
  window.addEventListener("message", function (event) {
    try {
      var data = String(event.data || "");
      var parts = data.split(" ");
      if (parts.length !== 2) { event.source.postMessage("error", event.origin); return; }
      var clientId = parts[0];
      var sessionState = parts[1];
      var cookieState = getCookieSessionStateForClient(clientId);
      var result = (cookieState && cookieState === sessionState) ? "unchanged" : "changed";
      event.source.postMessage(result, event.origin);
    } catch (e) {
      try { event.source.postMessage("error", event.origin); } catch (_) {}
    }
  }, false);
  function getCookieSessionStateForClient(clientId) {
    // OIDC session_state is ``salted-hash(clientId + origin + user-session-id + salt)``.
    // Integrators replace this with their production session cookie lookup.
    try {
      var m = document.cookie.match(/(?:^|; )xwauth_session_state=([^;]*)/);
      return m ? decodeURIComponent(m[1]) : null;
    } catch (e) { return null; }
  }
</script>
</body></html>"""
    return HTMLResponse(
        content=html_doc,
        status_code=200,
        headers={
            # Session management iframes must be embeddable cross-origin by RPs;
            # the CSP frame-ancestors policy below lets any origin embed, which
            # is the spec's intent. Integrators can tighten this per deployment.
            "Content-Security-Policy": "frame-ancestors *;",
            "X-Frame-Options": "ALLOWALL",
            "Cache-Control": "public, max-age=3600",
        },
    )


# -----------------------------------------------------------------------------
# GET/POST /v1/oauth2/tokeninfo  —  Google-style simplified token validation
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oauth2_tokeninfo",
    summary="Token info (Google-style)",
    method="GET",
    description=(
        "Lightweight token validation endpoint matching Google's "
        "``/oauth2/tokeninfo`` shape. Accepts ``access_token`` or ``id_token`` "
        "as a query parameter and returns introspection-style JSON. Clients "
        "that expect RFC 7662 should use /v1/oauth2/introspect (POST) instead."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Token metadata"},
        400: {"description": "No token provided"},
        401: {"description": "Token invalid or expired"},
    },
    in_types={
        "access_token": {"type": "string", "default": None},
        "id_token": {"type": "string", "default": None},
    },
)
async def tokeninfo(request: Request) -> Any:
    if request.method.upper() == "POST":
        form = await request.form()
        token = form.get("access_token") or form.get("id_token")
    else:
        token = request.query_params.get("access_token") or request.query_params.get("id_token")
    if not token:
        return _oauth_json_error(
            "invalid_request",
            "access_token or id_token query parameter is required",
            status_code=400,
        )
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "oauth2_tokeninfo"):
            info = await auth.introspect_token(token)
            if not info or not info.get("active"):
                return _oauth_json_error(
                    "invalid_token", "Token is expired, revoked, or invalid", status_code=401
                )
            # Google's tokeninfo returns these specific fields; mirror them so
            # Google-compatible clients work without modification.
            return {
                "active": True,
                "azp": info.get("client_id"),
                "aud": info.get("aud"),
                "sub": info.get("sub") or info.get("user_id"),
                "scope": info.get("scope"),
                "exp": info.get("exp"),
                "expires_in": max(0, int(info.get("exp", 0)) - int(time.time())) if info.get("exp") else None,
                "email": info.get("email"),
                "email_verified": info.get("email_verified"),
                "access_type": info.get("access_type", "online"),
            }
    except Exception as e:  # noqa: BLE001
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(
    operationId="oauth2_tokeninfo_post",
    summary="Token info (Google-style, POST variant)",
    method="POST",
    description="POST variant of /v1/oauth2/tokeninfo accepting form body.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "access_token": {"type": "string", "default": None},
        "id_token": {"type": "string", "default": None},
    },
)
async def tokeninfo_post(request: Request) -> Any:
    return await tokeninfo(request)


# -----------------------------------------------------------------------------
# GET /v1/auth/providers  —  list configured identity providers
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_providers_list",
    summary="List identity providers",
    method="GET",
    description=(
        "Return the catalog of OAuth/OIDC/SAML identity providers this server "
        "is configured to authenticate against. Useful for login UIs that want "
        "to render provider buttons without hard-coding a list."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={200: {"description": "Provider catalog"}},
    in_types={},
)
async def providers_list(request: Request) -> Any:
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "auth_providers_list"):
            providers: list[dict[str, Any]] = []
            seen: set[str] = set()

            # Runtime-registered providers come first (these have real credentials
            # and callback wiring in the host's configuration).
            registry = getattr(auth, "_provider_registry", None)
            if registry is not None:
                get_all = (
                    getattr(registry, "list_providers", None)
                    or getattr(registry, "get_all", None)
                    or getattr(registry, "all", None)
                )
                if callable(get_all):
                    raw = get_all()
                    if hasattr(raw, "__await__"):
                        raw = await raw
                else:
                    raw = []
                for p in raw or []:
                    name = (
                        getattr(p, "name", None)
                        or getattr(p, "provider_name", None)
                        or str(p)
                    )
                    if not name or name in seen:
                        continue
                    seen.add(name)
                    providers.append(
                        {
                            "name": name,
                            "display_name": getattr(p, "display_name", name),
                            "type": getattr(p, "provider_type", "oauth2"),
                            "configured": True,
                            "authorize_start": f"/v1/auth/{name}/start",
                            "callback": f"/v1/auth/{name}/callback",
                        }
                    )

            # Then enumerate built-in provider modules that xwauth-identity ships. These
            # are known-shape templates — clients can see "google is supported,
            # configure it to light it up" without needing docs.
            try:
                from exonware.xwauth.identity import providers as _provmod  # noqa: F401
                import pkgutil

                for modinfo in pkgutil.iter_modules(_provmod.__path__):
                    name = modinfo.name
                    if name.startswith("_") or name in seen:
                        continue
                    seen.add(name)
                    providers.append(
                        {
                            "name": name,
                            "display_name": name.replace("_", " ").title(),
                            "type": "oauth2",
                            "configured": False,
                            "authorize_start": f"/v1/auth/{name}/start",
                            "callback": f"/v1/auth/{name}/callback",
                        }
                    )
            except Exception:  # noqa: BLE001 — enumeration is best-effort
                pass

            providers.sort(key=lambda p: (not p["configured"], p["name"]))
            return {"providers": providers, "count": len(providers)}
    except Exception as e:  # noqa: BLE001
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


# -----------------------------------------------------------------------------
# GET /v1/error  —  OAuth error display page
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oauth_error_page",
    summary="OAuth error display page",
    method="GET",
    description=(
        "Lands users here when the authorization server cannot redirect an OAuth "
        "error back to the client (missing/invalid redirect_uri, mismatched "
        "state, unregistered client). Renders a minimal HTML page that shows "
        "the error so the end user isn't left with a blank window."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={200: {"description": "Error page rendered"}},
    in_types={
        "error": {"type": "string", "default": None},
        "error_description": {"type": "string", "default": None},
        "error_uri": {"type": "string", "default": None},
        "state": {"type": "string", "default": None},
    },
)
async def error_page(request: Request) -> Response:
    qp = request.query_params
    err = html.escape(qp.get("error") or "invalid_request")
    desc = html.escape(qp.get("error_description") or "The authorization request failed.")
    uri = qp.get("error_uri")
    uri_link = f'<p><a href="{html.escape(uri)}" rel="noopener">More info</a></p>' if uri else ""
    page = (
        "<!DOCTYPE html><html lang='en'><head><title>Authorization error</title>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        "<style>body{font-family:system-ui;max-width:520px;margin:60px auto;padding:0 16px;color:#111}"
        ".err{display:inline-block;padding:4px 8px;border-radius:4px;background:#fee;color:#991b1b;"
        "font-family:ui-monospace,monospace;font-size:13px}h2{margin:8px 0}p{line-height:1.5}"
        "</style></head><body>"
        "<h2>Authorization error</h2>"
        f"<p><span class='err'>{err}</span></p>"
        f"<p>{desc}</p>"
        f"{uri_link}"
        "<p><small>If you reached this page from a link, please close this window and "
        "try again from the original application.</small></p>"
        "</body></html>"
    )
    return HTMLResponse(
        content=page,
        status_code=400,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


# -----------------------------------------------------------------------------
# POST /v1/oidc/backchannel-logout  —  OpenID Back-Channel Logout 1.0
# -----------------------------------------------------------------------------
@XWAction(
    operationId="oidc_backchannel_logout",
    summary="OIDC back-channel logout receiver",
    method="POST",
    description=(
        "Receives a Back-Channel Logout Token (a signed JWT with ``events`` claim "
        "containing ``http://schemas.openid.net/event/backchannel-logout``) from "
        "an upstream OP. Terminates any local session tied to the ``sid``/``sub`` "
        "claim in the token."
    ),
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    responses={
        200: {"description": "Logout accepted; session terminated"},
        400: {"description": "Missing or invalid logout_token"},
        501: {"description": "Back-channel logout handling is not configured"},
    },
    in_types={
        "logout_token": {
            "type": "string",
            "description": "Signed JWT logout token",
            "minLength": 1,
            "default": None,
        },
    },
)
async def backchannel_logout(request: Request) -> Any:
    form = await request.form()
    logout_token = form.get("logout_token")
    if not logout_token:
        return _oauth_json_error(
            "invalid_request",
            "logout_token is required",
            status_code=400,
        )
    auth = get_auth(request)
    handler = getattr(auth, "handle_backchannel_logout_token", None)
    if not callable(handler):
        return _oauth_json_error(
            "not_implemented",
            "Back-channel logout reception is not configured on this server",
            status_code=501,
            hint="Implement XWAuth.handle_backchannel_logout_token to activate this endpoint",
        )
    try:
        async with track_critical_handler(request, "oidc_backchannel_logout"):
            await handler(logout_token)
            # Spec: return HTTP 200 with empty body, headers signaling no caching.
            return Response(
                content="",
                status_code=200,
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
    except Exception as e:  # noqa: BLE001
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
