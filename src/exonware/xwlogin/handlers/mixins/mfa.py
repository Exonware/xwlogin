# exonware/xwlogin/handlers/mixins/mfa.py
"""MFA TOTP: setup, verify (encrypted at rest, enrollment confirm, lockout, backup codes)."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

from exonware.xwapi.http import JSONResponse, Request

from exonware.xwaction import XWAction
from exonware.xwaction.defs import ActionProfile
from exonware.xwsystem.security.oauth_errors import oauth_error_response
from exonware.xwlogin.authentication.mfa_webauthn_audit import audit_mfa_event

from exonware.xwlogin.handlers.connector_http import (
    MFA_TAGS,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_backup_codes,
    get_auth,
    get_bearer_token,
    get_current_user_id,
    get_user_lifecycle,
    hash_backup_code,
    merge_amr_claims,
    oauth_error_to_http,
    require_backup_codes,
    track_critical_handler,
    verify_backup_code,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso_utc(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        s = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _normalize_amr(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v]
    if isinstance(value, str):
        return [value] if value else []
    return []


async def _persist_session_step_up(auth: Any, session_id: str | None, *, aal: str, amr: list[str]) -> None:
    if not session_id:
        return
    session_manager = getattr(auth, "_session_manager", None)
    if not session_manager:
        return
    storage = getattr(session_manager, "_storage", None)
    if not storage:
        return
    session = await storage.get_session(session_id)
    if not session:
        return
    session.attributes["aal"] = aal
    session.attributes["amr"] = list(amr)
    await storage.save_session(session)


async def _issue_step_up_token(request: Request, auth: Any, user_id: str) -> dict[str, Any] | None:
    bearer = get_bearer_token(request)
    if not bearer:
        return None
    resolver = getattr(auth, "resolve_auth_context", None)
    token_manager = getattr(auth, "_token_manager", None)
    if not callable(resolver) or token_manager is None:
        return None
    context = await resolver(bearer)
    if not context:
        return None
    existing_amr = _normalize_amr(getattr(context, "claims", {}).get("amr"))
    merged_amr = merge_amr_claims(existing_amr, "otp", "totp")
    claims = {
        "tenant_id": context.tenant_id,
        "tid": context.tenant_id,
        "roles": list(context.roles),
        "aal": "aal2",
        "amr": merged_amr,
    }
    claims = {k: v for k, v in claims.items() if v not in (None, [], "")}
    client_id = str(context.claims.get("client_id") or "step_up")
    step_up_token = await token_manager.generate_access_token(
        user_id=user_id,
        client_id=client_id,
        scopes=list(context.scopes),
        session_id=context.session_id,
        additional_claims=claims or None,
    )
    await _persist_session_step_up(auth, context.session_id, aal="aal2", amr=merged_amr)
    return {
        "access_token": step_up_token,
        "token_type": "Bearer",
        "expires_in": getattr(auth.config, "access_token_lifetime", 3600),
        "aal": "aal2",
        "amr": merged_amr,
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


def _get_totp_plain_secret(user_attrs: dict[str, Any], config: Any) -> str | None:
    enc = user_attrs.get("mfa_totp_secret_enc")
    if enc:
        try:
            return decrypt_totp_secret(enc, config)
        except Exception:
            return None
    legacy = user_attrs.get("mfa_totp_secret")
    return str(legacy) if legacy else None


@XWAction(
    operationId="auth_mfa_setup_totp",
    summary="Setup TOTP MFA",
    method="POST",
    description="Begin TOTP enrollment: returns secret and provisioning URI; MFA activates after successful verify.",
    tags=MFA_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    security="Bearer",
    mfa_required=False,
    responses={
        200: {"description": "TOTP MFA setup successful"},
        401: {"description": "Authentication required"},
        404: {"description": "User not found"},
        501: {"description": "pyotp library not installed"},
    },
    audit=True,
    in_types={},
)
async def mfa_setup_totp(request: Request) -> Any:
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    cfg = auth.config
    try:
        async with track_critical_handler(request, "mfa_setup_totp"):
            try:
                import pyotp
            except ImportError:
                return _oauth_json_error("not_implemented", "pyotp library not installed", status_code=501)
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return _oauth_json_error("user_not_found", "User not found", status_code=404)
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            issuer = (getattr(request.app.state, "xwauth_issuer", None) or "xwauth").rstrip("/")
            provisioning_uri = totp.provisioning_uri(
                name=user.email or user_id,
                issuer_name=issuer,
            )
            enc = encrypt_totp_secret(totp_secret, cfg)
            base_attrs = user.attributes if hasattr(user, "attributes") else {}
            new_attrs = {
                **base_attrs,
                "mfa_totp_secret_enc": enc,
                "mfa_totp_pending": True,
                "mfa_enabled": False,
                "mfa_totp_failed_attempts": 0,
                "mfa_totp_lockout_until": None,
            }
            new_attrs.pop("mfa_totp_secret", None)
            await user_lifecycle.update_user(user_id, {"attributes": new_attrs})
            await audit_mfa_event(
                auth,
                "mfa.totp.setup.completed",
                user_id=user_id,
                attributes={"stage": "pending_verify"},
            )
            return {
                "secret": totp_secret,
                "provisioning_uri": provisioning_uri,
                "mfa_totp_pending": True,
                "mfa_enabled": False,
                "message": "Scan the QR code and call verify to activate TOTP MFA.",
            }
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)


@XWAction(
    operationId="auth_mfa_verify_totp",
    summary="Verify TOTP or backup code",
    method="POST",
    description="Verify TOTP code or a one-time backup code; issues step-up token when bearer present.",
    tags=MFA_TAGS,
    engine="fastapi",
    profile=ActionProfile.ENDPOINT,
    in_types={
        "totp_code": {
            "type": "string",
            "description": "6-digit TOTP code from authenticator app",
            "pattern": "^\\d{6}$",
            "minLength": 6,
            "maxLength": 6,
        },
        "backup_code": {
            "type": "string",
            "description": "One-time backup code (profile B/C)",
            "maxLength": 32,
        },
    },
)
async def mfa_verify_totp(request: Request) -> Any:
    user_id = await get_current_user_id(request)
    if not user_id:
        return _oauth_json_error("unauthorized", "Authentication required", status_code=401)
    form = await request.form()
    totp_code = form.get("totp_code")
    backup_code = form.get("backup_code")
    if not totp_code and not backup_code:
        return _oauth_json_error("invalid_request", "totp_code or backup_code is required")
    auth = get_auth(request)
    user_lifecycle = get_user_lifecycle(auth)
    cfg = auth.config
    max_fail = int(getattr(cfg, "mfa_totp_max_failed_attempts", 5) or 5)
    lockout_sec = int(getattr(cfg, "mfa_totp_lockout_seconds", 900) or 900)
    try:
        async with track_critical_handler(request, "mfa_verify_totp"):
            try:
                import pyotp
            except ImportError:
                return _oauth_json_error("not_implemented", "pyotp library not installed", status_code=501)
            user = await user_lifecycle.get_user(user_id)
            if not user:
                return _oauth_json_error("user_not_found", "User not found", status_code=404)
            user_attrs = user.attributes if hasattr(user, "attributes") else {}
            lock_until = _parse_iso_utc(user_attrs.get("mfa_totp_lockout_until"))
            if lock_until and _utcnow() < lock_until:
                return _oauth_json_error(
                    "slow_down",
                    "TOTP verification temporarily locked; try again later",
                    status_code=429,
                )

            verified = False
            backup_hashes = list(user_attrs.get("mfa_backup_codes_sha256") or [])

            if backup_code:
                matched = verify_backup_code(str(backup_code), backup_hashes)
                if matched:
                    verified = True
                    backup_hashes = [h for h in backup_hashes if h != matched]
            elif totp_code:
                secret = _get_totp_plain_secret(user_attrs, cfg)
                if not secret:
                    return _oauth_json_error("mfa_not_setup", "TOTP MFA not set up for this user")
                totp = pyotp.TOTP(secret)
                if totp.verify(str(totp_code), valid_window=1):
                    verified = True

            if not verified:
                delay_ms = int(getattr(cfg, "mfa_failure_delay_ms", 0) or 0)
                if delay_ms > 0:
                    time.sleep(min(delay_ms / 1000.0, 2.0))
                fails = int(user_attrs.get("mfa_totp_failed_attempts") or 0) + 1
                lock_iso = None
                if fails >= max_fail:
                    lock_iso = (_utcnow() + timedelta(seconds=lockout_sec)).isoformat()
                    fails = 0
                await user_lifecycle.update_user(
                    user_id,
                    {
                        "attributes": {
                            **user_attrs,
                            "mfa_totp_failed_attempts": fails,
                            "mfa_totp_lockout_until": lock_iso,
                        }
                    },
                )
                await audit_mfa_event(
                    auth,
                    "mfa.totp.verify.failed",
                    user_id=user_id,
                    attributes={"reason": "invalid_code", "via_backup": bool(backup_code)},
                )
                return _oauth_json_error("invalid_totp", "Invalid TOTP or backup code")

            pending = bool(user_attrs.get("mfa_totp_pending"))
            profile = getattr(cfg, "protocol_profile", "A") or "A"
            updates: dict[str, Any] = {
                **user_attrs,
                "mfa_totp_failed_attempts": 0,
                "mfa_totp_lockout_until": None,
                "mfa_enabled": True,
                "mfa_totp_pending": False,
            }
            if backup_hashes != list(user_attrs.get("mfa_backup_codes_sha256") or []):
                updates["mfa_backup_codes_sha256"] = backup_hashes
            plain_codes: list[str] | None = None
            if pending and require_backup_codes(profile):
                n = int(getattr(cfg, "mfa_backup_code_count", 10) or 10)
                plain_codes = generate_backup_codes(n)
                updates["mfa_backup_codes_sha256"] = [hash_backup_code(c) for c in plain_codes]

            if pending and user_attrs.get("mfa_totp_secret") and not user_attrs.get("mfa_totp_secret_enc"):
                try:
                    sec = user_attrs.get("mfa_totp_secret")
                    if sec:
                        updates["mfa_totp_secret_enc"] = encrypt_totp_secret(str(sec), cfg)
                except Exception:
                    pass
            updates.pop("mfa_totp_secret", None)

            await user_lifecycle.update_user(user_id, {"attributes": updates})

            await audit_mfa_event(
                auth,
                "mfa.totp.verify.completed",
                user_id=user_id,
                attributes={
                    "first_activation": pending,
                    "via_backup": bool(backup_code),
                },
            )

            response: dict[str, Any] = {"message": "Verified successfully", "verified": True, "mfa_enabled": True}
            if plain_codes:
                response["backup_codes"] = plain_codes
                response["message"] = "MFA enabled; store backup codes securely (shown once)."
            step_up = await _issue_step_up_token(request, auth, user_id)
            if step_up:
                response.update(step_up)
            return response
    except Exception as e:
        body, status = oauth_error_to_http(e)
        return JSONResponse(content=body, status_code=status)
