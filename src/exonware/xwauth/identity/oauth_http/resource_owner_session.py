#!/usr/bin/env python3
"""
Resource-owner session helper: validate existing Cookie/Authorization against a probe URL,
then fall back to OAuth 2.0 password grant and derive API headers for reuse.

Supports:
- LiveMe-style JSON envelopes: ``{"code": 200, "message": "success", "data": {...}}``
- RFC 6749 token responses with top-level ``access_token`` / ``token_type``.
"""

from __future__ import annotations

from typing import Any

import requests

from exonware.xwauth.identity.errors import XWTokenError


def _try_response_json(response: requests.Response) -> Any | None:
    try:
        return response.json()
    except ValueError:
        return None


def _probe_indicates_authenticated(response: requests.Response, body: Any) -> bool:
    if response.status_code in (401, 403):
        return False
    if not isinstance(body, dict):
        return 200 <= response.status_code < 400
    code = body.get("code")
    if code in (401, 403):
        return False
    if code == 200:
        return True
    msg = str(body.get("message") or body.get("msg") or body.get("error") or "").lower()
    auth_hints = (
        "unauthor",
        "forbidden",
        "token invalid",
        "token expired",
        "invalid token",
        "please login",
        "invalid credential",
    )
    if code not in (200, None) and any(h in msg for h in auth_hints):
        return False
    return False


def _normalize_token_success(body: dict[str, Any]) -> dict[str, Any]:
    """Return flat token fields: access_token, token_type, uid (optional), company_id (optional)."""
    if body.get("code") == 200 and body.get("message") == "success" and isinstance(body.get("data"), dict):
        data = body["data"]
        access = data.get("access_token")
        if not access:
            raise XWTokenError(
                "Token response missing access_token in data",
                context={"body_keys": list(body.keys())},
            )
        return {
            "access_token": access,
            "token_type": data.get("token_type") or "Bearer",
            "uid": data.get("uid"),
            "company_id": data.get("company_id"),
            "raw": body,
        }
    access = body.get("access_token")
    if access:
        return {
            "access_token": access,
            "token_type": body.get("token_type") or "Bearer",
            "uid": body.get("uid"),
            "company_id": body.get("company_id"),
            "raw": body,
        }
    raise XWTokenError(
        "Unrecognized token response shape (expected RFC access_token or LiveMe code/message/data)",
        context={"body_keys": list(body.keys())},
    )


def _build_api_headers(fields: dict[str, Any]) -> tuple[str, str]:
    token_type = str(fields["token_type"])
    access = str(fields["access_token"])
    authorization = f"{token_type} {access}".strip()
    uid = fields.get("uid")
    if uid is not None:
        cookie = f"uid={uid}; token={token_type}%20{access}"
    else:
        cookie = f"token={token_type}%20{access}"
    return cookie, authorization


def ensure_resource_owner_session(
    *,
    probe_url: str,
    token_url: str,
    username: str,
    password: str,
    cookie_header: str | None = None,
    authorization_header: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    grant_type: str = "password",
    extra_token_fields: dict[str, str] | None = None,
    session: requests.Session | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    If ``Cookie`` / ``Authorization`` already work against ``probe_url``, return them as API headers.
    Otherwise request a token at ``token_url`` with the resource-owner password grant and derive headers.

    Args:
        probe_url: GET URL used only to test whether existing credentials are still accepted.
        token_url: OAuth 2.0 token endpoint (password grant by default).
        username: Resource owner username.
        password: Resource owner password.
        cookie_header: Optional full ``Cookie`` header value (e.g. ``uid=...; token=Bearer%20...``).
        authorization_header: Optional ``Authorization`` header (e.g. ``Bearer ...``).
        client_id / client_secret: Optional OAuth client credentials appended to the token request.
        grant_type: OAuth grant type (default ``password``).
        extra_token_fields: Extra form fields for the token POST (e.g. ``scope``).
        session: Optional shared ``requests.Session`` (creates one if omitted).
        timeout: HTTP timeout in seconds.

    Returns:
        dict with ``source`` (``existing_session`` | ``password_grant``), ``headers_cookie``,
        ``headers_authorization``, ``token_fields`` (normalized dict), and ``raw`` (probe or token body).

    Raises:
        XWTokenError: When login is required but credentials are missing, or the token endpoint rejects login.
    """
    sess = session or requests.Session()
    has_existing = bool((cookie_header or "").strip() or (authorization_header or "").strip())

    if has_existing:
        headers: dict[str, str] = {
            "Accept": "application/json, text/plain, */*",
        }
        ck = (cookie_header or "").strip()
        if ck:
            headers["Cookie"] = ck
        auth_h = (authorization_header or "").strip()
        if auth_h:
            headers["Authorization"] = auth_h
        probe = sess.get(probe_url, headers=headers, timeout=timeout)
        body = _try_response_json(probe)
        if _probe_indicates_authenticated(probe, body):
            return {
                "source": "existing_session",
                "headers_cookie": ck,
                "headers_authorization": auth_h,
                "token_fields": {},
                "raw": body if isinstance(body, dict) else {"status_code": probe.status_code},
            }

    if not (username and password):
        raise XWTokenError(
            "Existing session not accepted and username/password not provided for password grant",
            context={"probe_url": probe_url, "token_url": token_url},
        )

    form: dict[str, Any] = {
        "grant_type": grant_type,
        "username": username,
        "password": password,
    }
    if client_id is not None:
        form["client_id"] = client_id
    if client_secret is not None:
        form["client_secret"] = client_secret
    if extra_token_fields:
        form.update(extra_token_fields)

    post_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    token_resp = sess.post(token_url, data=form, headers=post_headers, timeout=timeout)
    token_body = _try_response_json(token_resp)

    if isinstance(token_body, dict):
        # HTTP OK but API-level failure (common for wrapped JSON APIs)
        if token_resp.ok and token_body.get("code") not in (200, None) and "access_token" not in token_body:
            raise XWTokenError(
                f"Token endpoint returned business error code={token_body.get('code')!r}",
                context={"token_url": token_url, "body": token_body},
            )
        if token_body.get("error") and "access_token" not in token_body:
            raise XWTokenError(
                f"Token endpoint error: {token_body.get('error')}",
                context={
                    "token_url": token_url,
                    "error_description": token_body.get("error_description"),
                    "body": token_body,
                },
            )
    if not token_resp.ok:
        raise XWTokenError(
            f"Token HTTP {token_resp.status_code}",
            context={"token_url": token_url, "body": token_body},
        )
    if not isinstance(token_body, dict):
        raise XWTokenError(
            "Token response was not a JSON object",
            context={"token_url": token_url, "status_code": token_resp.status_code},
        )

    fields = _normalize_token_success(token_body)
    cookie_hdr, auth_hdr = _build_api_headers(fields)
    return {
        "source": "password_grant",
        "headers_cookie": cookie_hdr,
        "headers_authorization": auth_hdr,
        "token_fields": {
            "access_token": fields["access_token"],
            "token_type": fields["token_type"],
            "uid": fields.get("uid"),
            "company_id": fields.get("company_id"),
        },
        "raw": token_body,
    }
