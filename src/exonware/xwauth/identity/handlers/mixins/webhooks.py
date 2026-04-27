# exonware/xwauth/handlers/mixins/webhooks.py
"""Webhooks: register, list, delete, test."""

from __future__ import annotations
from typing import Any
from fastapi import Request, Depends, Header
from fastapi.responses import JSONResponse, RedirectResponse, Response
from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwauth.identity.oauth_http.errors import oauth_error_to_http
from exonware.xwauth.identity.ops_hooks import track_critical_handler
from .._common import (
    WEBHOOK_TAGS, get_auth, get_current_user_id, get_webhook_manager
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
# -----------------------------------------------------------------------------
# POST /webhooks
# -----------------------------------------------------------------------------
@XWAction(
    operationId="webhooks_register",
    summary="Register Webhook",
    method="POST",
    description="""
    Register a new webhook endpoint for event notifications.
    Supported events:
    - user.created, user.deleted, user.updated
    - org.created, org.deleted, org.updated
    - login.failed, login.succeeded
    - mfa.enrolled, mfa.removed
    - token.issued, token.revoked
    Security: Requires Bearer token authentication.
    """,
    tags=WEBHOOK_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        201: {"description": "Webhook registered successfully"},
        400: {"description": "Invalid request"},
        401: {"description": "Authentication required"},
    },
    examples={
        "register_webhook": {
            "url": "https://example.com/webhooks",
            "events": ["user.created", "user.deleted"],
            "active": True
        }
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "url": {
            "type": "string",
            "description": "Webhook URL endpoint",
            "format": "uri",
            "minLength": 1,
            "maxLength": 512
        },
        "events": {
            "type": "array",
            "description": "List of events to subscribe to",
            "items": {
                "type": "string",
                "enum": [
                    "user.created", "user.deleted", "user.updated",
                    "org.created", "org.deleted", "org.updated",
                    "login.failed", "login.succeeded",
                    "mfa.enrolled", "mfa.removed",
                    "token.issued", "token.revoked"
                ]
            },
            "minItems": 1
        },
        "secret": {
            "type": "string",
            "description": "Optional webhook secret for HMAC signing (auto-generated if not provided)",
            "maxLength": 256
        },
        "active": {
            "type": "boolean",
            "description": "Whether webhook is active",
            "default": True
        }
    },
)
async def webhooks_register(request: Request) -> Any:
    """Register a new webhook."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    body_data = await request.json() if hasattr(request, 'json') else {}
    try:
        async with track_critical_handler(request, "webhooks_register"):
            manager = get_webhook_manager(auth)
            webhook = await manager.register_webhook(
                url=body_data.get("url"),
                events=body_data.get("events", []),
                secret=body_data.get("secret"),
                active=body_data.get("active", True),
            )
            return JSONResponse(
                content=webhook,
                status_code=201,
            )
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# GET /webhooks
# -----------------------------------------------------------------------------
@XWAction(
    operationId="webhooks_list",
    summary="List Registered Webhooks",
    method="GET",
    description="""
    List all registered webhook endpoints.
    Security: Requires Bearer token authentication.
    """,
    tags=WEBHOOK_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "List of webhooks"},
        401: {"description": "Authentication required"},
    },
    rate_limit="100/hour",
    audit=True,
    in_types={},  # Exclude Request parameter from schema
)
async def webhooks_list(request: Request) -> Any:
    """List all registered webhooks."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "webhooks_list"):
            manager = get_webhook_manager(auth)
            webhooks = await manager.list_webhooks()
            return {"webhooks": webhooks}
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# DELETE /webhooks/{webhook_id}
# -----------------------------------------------------------------------------
@XWAction(
    operationId="webhooks_delete",
    summary="Delete Webhook",
    method="DELETE",
    description="""
    Delete a registered webhook endpoint.
    Security: Requires Bearer token authentication.
    """,
    tags=WEBHOOK_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        204: {"description": "Webhook deleted successfully"},
        401: {"description": "Authentication required"},
        404: {"description": "Webhook not found"},
    },
    rate_limit="50/hour",
    audit=True,
    in_types={
        "webhook_id": {
            "type": "string",
            "description": "Webhook identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def webhooks_delete(webhook_id: str, request: Request) -> Any:
    """Delete a webhook."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "webhooks_delete"):
            manager = get_webhook_manager(auth)
            await manager.delete_webhook(webhook_id)
            return Response(status_code=204)
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
# POST /webhooks/{webhook_id}/test
# -----------------------------------------------------------------------------
@XWAction(
    operationId="webhooks_test",
    summary="Test Webhook Delivery",
    method="POST",
    description="""
    Test webhook delivery by sending a test event.
    Security: Requires Bearer token authentication.
    """,
    tags=WEBHOOK_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    responses={
        200: {"description": "Test delivery result"},
        401: {"description": "Authentication required"},
        404: {"description": "Webhook not found"},
    },
    examples={
        "test_result": {
            "webhook_id": "webhook123",
            "url": "https://example.com/webhooks",
            "delivered": True,
            "status_code": 200
        }
    },
    rate_limit="10/hour",
    audit=True,
    in_types={
        "webhook_id": {
            "type": "string",
            "description": "Webhook identifier",
            "minLength": 1,
            "maxLength": 256
        }
    },
)
async def webhooks_test(webhook_id: str, request: Request) -> Any:
    """Test webhook delivery."""
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    try:
        async with track_critical_handler(request, "webhooks_test"):
            manager = get_webhook_manager(auth)
            result = await manager.test_webhook(webhook_id)
            return result
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
# -----------------------------------------------------------------------------
