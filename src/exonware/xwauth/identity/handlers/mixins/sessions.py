# exonware/xwauth/handlers/mixins/sessions.py
"""Sessions: list, revoke, revoke_others, HTML reference view."""

from __future__ import annotations

import html
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from .._common import (
    AUTH_TAGS,
    XWAUTH_REFERENCE_ACCESS_TOKEN_COOKIE,
    get_auth,
    get_bearer_token,
    get_current_user_id,
    get_current_user_id_for_sessions_reference_html,
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
@XWAction(
    operationId="auth_sessions_list",
    summary="List Active Sessions",
    method="GET",
    description="List all active sessions for the current authenticated user.",
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={200: {"description": "List of active sessions"}, 401: {"description": "Authentication required"}},
    audit=True,
    in_types={},
)
async def sessions_list(request: Request) -> Any:
    """List all active sessions for current user."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "sessions_list"):
            sessions = await auth._session_manager.list_user_sessions(user_id)
            return {"sessions": sessions}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


# -----------------------------------------------------------------------------
# GET /auth/sessions/view  (static segment before {session_id})
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_sessions_list_html",
    summary="List Active Sessions (HTML reference)",
    method="GET",
    description=f"""
    Minimal **HTML** table of active sessions for the current user.
    Authenticate with ``Authorization: Bearer`` or, for same-origin browser views only,
    the documented cookie ``{XWAUTH_REFERENCE_ACCESS_TOKEN_COOKIE}`` (access token value;
    integrator-set, prefer **HttpOnly** + **Secure** + **SameSite**). JSON APIs such as
    ``GET /auth/sessions`` still require Bearer only.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "HTML page with session table"},
        401: {"description": "Authentication required"},
    },
    audit=True,
    in_types={},
)
async def sessions_list_html(request: Request) -> Any:
    """Server-rendered session list (escaped); Bearer or optional reference cookie."""
    user_id = await get_current_user_id_for_sessions_reference_html(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "sessions_list_html"):
            sessions = await auth._session_manager.list_user_sessions(user_id)
            rows_html: list[str] = []
            for s in sessions:
                sid = html.escape(str(s.get("session_id", "")))
                created = html.escape(str(s.get("created_at", "")))
                last = html.escape(str(s.get("last_accessed_at", "")))
                status_s = html.escape(str(s.get("status", "")))
                rows_html.append(
                    f"<tr><td><code>{sid}</code></td><td>{created}</td><td>{last}</td><td>{status_s}</td></tr>"
                )
            tbody = "\n".join(rows_html) if rows_html else (
                '<tr><td colspan="4">No active sessions.</td></tr>'
            )
            doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Active sessions</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 56rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #f4f4f4; }}
    caption {{ text-align: left; font-weight: bold; margin-bottom: 0.5rem; }}
  </style>
</head>
<body>
  <h1>Active sessions</h1>
  <p>Reference view: <code>Authorization: Bearer</code> or cookie <code>{html.escape(XWAUTH_REFERENCE_ACCESS_TOKEN_COOKIE)}</code> (same-origin). JSON: <code>GET …/auth/sessions</code>.</p>
  <table>
    <caption>Your sessions</caption>
    <thead><tr><th>Session</th><th>Created</th><th>Last access</th><th>Status</th></tr></thead>
    <tbody>
{tbody}
    </tbody>
  </table>
</body>
</html>"""
            return HTMLResponse(content=doc, media_type="text/html; charset=utf-8")
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


# -----------------------------------------------------------------------------
# DELETE /auth/sessions/{session_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_sessions_revoke",
    summary="Revoke Specific Session",
    method="DELETE",
    description="""
    Revoke a specific session by session_id.
    This will log out the user from that specific device/session.
    Security: Requires Bearer token authentication.
    Only the session owner can revoke their own sessions.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        204: {"description": "Session revoked successfully"},
        401: {"description": "Authentication required"},
        403: {"description": "Not authorized to revoke this session"},
        404: {"description": "Session not found"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={
        "session_id": {
            "type": "string",
            "description": "Session identifier to revoke",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def sessions_revoke(session_id: str, request: Request) -> Any:
    """Revoke a specific session."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "sessions_revoke"):
            # Verify session belongs to user
            session = await auth._session_manager._storage.get_session(session_id)
            if not session:
                return _oauth_json_error("session_not_found", "Session not found", status_code=404)
            if session.user_id != user_id:
                return _oauth_json_error(
                    "forbidden",
                    "Not authorized to revoke this session",
                    status_code=403,
                )
            await auth._session_manager.revoke_session(session_id)
            return Response(status_code=204)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# DELETE /auth/sessions/exclude-current
# -----------------------------------------------------------------------------
@XWAction(
    operationId="auth_sessions_revoke_others",
    summary="Logout All Other Devices",
    method="DELETE",
    description="""
    Revoke all active sessions except the current one.
    This will log out the user from all other devices while keeping
    the current session active.
    Security: Requires Bearer token authentication.
    """,
    tags=AUTH_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Other sessions revoked successfully"},
        401: {"description": "Authentication required"},
    },
    examples={
        "response": {
            "revoked_count": 3,
            "message": "Revoked 3 other sessions"
        }
    },
    rate_limit="10/hour",
    audit=True,
    in_types={},  # Exclude Request parameter from schema
)
async def sessions_revoke_others(request: Request) -> Any:
    """Revoke all sessions except the current one."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    # Get current session ID from token
    token = get_bearer_token(request)
    if not token:
        return _oauth_json_error("unauthorized", "Bearer token required", status_code=401)
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "sessions_revoke_others"):
            # Extract session_id from token claims (if stored in token)
            current_session_id = None
            # Try to extract session_id from token
            token_manager = getattr(auth, '_token_manager', None)
            if token_manager:
                try:
                    # Try JWT token first
                    if hasattr(token_manager, '_jwt_manager') and token_manager._jwt_manager:
                        try:
                            payload = token_manager._jwt_manager.validate_token(token)
                            current_session_id = payload.get('session_id')
                        except Exception:
                            pass
                    # Try opaque token if JWT didn't work
                    if not current_session_id and hasattr(token_manager, '_opaque_manager'):
                        try:
                            token_data = await token_manager._opaque_manager.get_token(token)
                            if token_data:
                                current_session_id = token_data.get('attributes', {}).get('session_id')
                        except Exception:
                            pass
                except Exception:
                    pass
            # Fallback: Find current session (most recently accessed active session)
            if not current_session_id:
                all_sessions = await auth._session_manager._storage.list_user_sessions(user_id)
                active_sessions = [s for s in all_sessions if s.is_active()]
                if active_sessions:
                    # Sort by last_accessed_at, most recent first
                    active_sessions.sort(key=lambda s: s.last_accessed_at, reverse=True)
                    current_session_id = active_sessions[0].id
            if not current_session_id:
                return _oauth_json_error("no_active_session", "No active session found")
            # Revoke all except current
            revoked_count = await auth._session_manager.revoke_all_sessions_except(
                user_id=user_id,
                exclude_session_id=current_session_id
            )
            return {
                "revoked_count": revoked_count,
                "message": f"Revoked {revoked_count} other session(s)"
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
