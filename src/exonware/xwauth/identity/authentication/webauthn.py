#!/usr/bin/env python3

"""

#exonware/xwauth.identity/src/exonware/xwauth.identity/authentication/webauthn.py

WebAuthn/Passkeys Authentication Implementation

Implements WebAuthn (FIDO2) authentication for passwordless login using

platform and cross-platform authenticators.

Company: eXonware.com

Author: eXonware Backend Team

Email: connect@exonware.com

Version: 0.0.1.4

Generation Date: 25-Jan-2026

"""



from __future__ import annotations



import hmac

import secrets

from datetime import datetime, timezone

from typing import Any



from exonware.xwsystem import get_logger



from exonware.xwauth.identity.base import ABaseAuth



from exonware.xwauth.identity.errors import XWAuthError, XWInvalidRequestError



from exonware.xwauth.identity.tokens.manager import TokenManager



from exonware.xwauth.identity.users.lifecycle import UserLifecycle

from .attestation_trust import build_pem_root_certs_bytes_by_fmt

from .challenge_store import IWebAuthnChallengeStore, WebAuthnChallengeStore

from .mfa_webauthn_audit import audit_webauthn_event

from .webauthn_credential_index import register_webauthn_credential_mapping



logger = get_logger(__name__)

# Try to import webauthn library

try:

    from webauthn import (

        generate_registration_options,

        verify_registration_response,

        generate_authentication_options,

        verify_authentication_response,

        options_to_json,

    )

    from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

    from webauthn.helpers.structs import (

        AuthenticatorSelectionCriteria,

        PublicKeyCredentialDescriptor,

        UserVerificationRequirement,

        AttestationConveyancePreference,

    )

    USE_WEBAUTHN = True

except ImportError:

    USE_WEBAUTHN = False

    logger.warning("python-webauthn library not installed. WebAuthn features will be limited.")





def _user_verification_from_config(value: str | None) -> Any:

    if not USE_WEBAUTHN:

        return None

    v = (value or "preferred").strip().lower()

    if v == "required":

        return UserVerificationRequirement.REQUIRED

    if v == "discouraged":

        return UserVerificationRequirement.DISCOURAGED

    return UserVerificationRequirement.PREFERRED





def _attestation_from_config(value: str | None) -> Any:

    if not USE_WEBAUTHN:

        return None

    v = (value or "none").strip().lower()

    if v == "direct":

        return AttestationConveyancePreference.DIRECT

    if v == "indirect":

        return AttestationConveyancePreference.INDIRECT

    return AttestationConveyancePreference.NONE





def _resident_key_from_config(value: str | None) -> Any:

    if not USE_WEBAUTHN:

        return None

    from webauthn.helpers.structs import ResidentKeyRequirement



    v = (value or "preferred").strip().lower()

    if v == "discouraged":

        return ResidentKeyRequirement.DISCOURAGED

    if v == "required":

        return ResidentKeyRequirement.REQUIRED

    return ResidentKeyRequirement.PREFERRED





def _credential_id_eq(a: str | None, b: str | None) -> bool:

    """Length-preserving constant-time compare for base64url credential ids."""

    if not a or not b:

        return False

    if len(a) != len(b):

        return False

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))





def _normalize_rp_id(rp_id: str | None) -> str | None:

    if not rp_id:

        return None

    s = str(rp_id).strip()

    return s.lower() if s else None





def _require_user_verification_bool(config: Any) -> bool:

    v = (getattr(config, "webauthn_user_verification", "preferred") or "preferred").strip().lower()

    return v == "required"





def _credential_id_preview(credential_id_b64: str) -> str:

    if len(credential_id_b64) <= 12:

        return "***"

    return f"{credential_id_b64[:8]}…{credential_id_b64[-4:]}"





class WebAuthnManager:

    """

    Manager for WebAuthn/Passkeys authentication.

    Handles passkey registration and authentication using WebAuthn API.

    """



    def __init__(

        self,

        auth: ABaseAuth,

        rp_name: str | None = None,

        rp_id: str | None = None,

        *,

        expected_origins: list[str] | None = None,

    ):

        self._auth = auth

        self._config = auth.config

        self._storage = auth.storage

        self._rp_name = rp_name or getattr(self._config, "webauthn_rp_name", "xwauth")

        self._rp_id = _normalize_rp_id(rp_id or getattr(self._config, "webauthn_rp_id", None))

        cfg_origin = getattr(self._config, "webauthn_origin", None)

        cfg_list = list(getattr(self._config, "webauthn_allowed_origins", None) or [])

        merged: list[str] = []

        for o in list(expected_origins or []) + cfg_list:

            if o and o not in merged:

                merged.append(str(o).rstrip("/"))

        if cfg_origin and cfg_origin not in merged:

            merged.insert(0, str(cfg_origin).rstrip("/"))

        self._expected_origins = merged

        self._user_verification = _user_verification_from_config(

            getattr(self._config, "webauthn_user_verification", "preferred")

        )

        self._attestation = _attestation_from_config(getattr(self._config, "webauthn_attestation", "none"))

        self._timeout_ms = int(getattr(self._config, "webauthn_timeout_ms", 60000) or 60000)

        logger.debug("WebAuthnManager initialized")



    def _challenge_store(self) -> IWebAuthnChallengeStore:

        store = getattr(self._auth, "_webauthn_challenge_store", None)

        if store is None:

            store = WebAuthnChallengeStore(

                default_ttl_seconds=float(getattr(self._config, "webauthn_challenge_ttl_seconds", 300) or 300),

            )

            setattr(self._auth, "_webauthn_challenge_store", store)

        return store  # type: ignore[return-value]



    def _primary_origin(self) -> str:

        if self._expected_origins:

            return self._expected_origins[0]

        allow = bool(getattr(self._config, "webauthn_allow_insecure_defaults", False))

        if allow:

            return "http://localhost:8000"

        raise XWInvalidRequestError(

            "WebAuthn origin allowlist is not configured",

            error_code="webauthn_misconfigured",

            error_description="Set webauthn_allowed_origins / app.state or webauthn_allow_insecure_defaults for dev",

        )



    async def _record_session_assurance(self, session_id: str | None, *, aal: str, amr: list[str]) -> None:

        if not session_id:

            return

        session_manager = getattr(self._auth, "_session_manager", None)

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



    async def generate_registration_options(

        self,

        user_id: str,

        user_email: str,

        user_name: str | None = None,

        authenticator_attachment: str | None = None,

    ) -> dict[str, Any]:

        if not USE_WEBAUTHN:

            raise XWAuthError(

                "WebAuthn library not installed",

                error_code="webauthn_not_available",

                suggestions=["Install python-webauthn: pip install webauthn"],

            )

        if not self._rp_id:

            raise XWInvalidRequestError(

                "webauthn_rp_id is required",

                error_code="webauthn_misconfigured",

                error_description="Configure webauthn_rp_id (or app.state.xwauth_rp_id)",

            )

        challenge = secrets.token_bytes(32)

        challenge_b64 = bytes_to_base64url(challenge)

        ttl = float(getattr(self._config, "webauthn_challenge_ttl_seconds", 300) or 300)

        handle = self._challenge_store().issue(

            challenge_b64url=challenge_b64,

            purpose="registration",

            user_id=user_id,

            ttl_seconds=ttl,

        )

        resident_key = _resident_key_from_config(getattr(self._config, "webauthn_resident_key", "preferred"))

        authenticator_selection = AuthenticatorSelectionCriteria(

            user_verification=self._user_verification or UserVerificationRequirement.PREFERRED,

            resident_key=resident_key,

        )

        if authenticator_attachment:

            if authenticator_attachment == "platform":

                authenticator_selection.authenticator_attachment = "platform"

            elif authenticator_attachment == "cross-platform":

                authenticator_selection.authenticator_attachment = "cross-platform"



        exclude_credentials: list[PublicKeyCredentialDescriptor] | None = None

        user_lifecycle = UserLifecycle(self._auth)

        existing_user = await user_lifecycle.get_user(user_id)

        if existing_user and existing_user.attributes.get("webauthn_credentials"):

            exclude_credentials = []

            for c in existing_user.attributes["webauthn_credentials"]:

                cid = c.get("credential_id")

                if not cid:

                    continue

                try:

                    exclude_credentials.append(

                        PublicKeyCredentialDescriptor(

                            id=base64url_to_bytes(cid),

                            type="public-key",

                        )

                    )

                except Exception:

                    continue

            if not exclude_credentials:

                exclude_credentials = None



        options = generate_registration_options(

            rp_id=self._rp_id,

            rp_name=self._rp_name,

            user_id=user_id.encode("utf-8"),

            user_name=user_name or user_email,

            user_display_name=user_name or user_email,

            challenge=challenge,

            timeout=self._timeout_ms,

            authenticator_selection=authenticator_selection,

            attestation=self._attestation or AttestationConveyancePreference.NONE,

            exclude_credentials=exclude_credentials,

        )

        options_dict = options_to_json(options)

        options_dict["webauthn_challenge_handle"] = handle

        logger.debug("Generated registration options for user: %s", user_id)

        return options_dict



    async def verify_registration(

        self,

        user_id: str,

        registration_response: dict[str, Any],

        *,

        challenge_handle: str | None = None,

    ) -> dict[str, Any]:

        if not USE_WEBAUTHN:

            raise XWAuthError(

                "WebAuthn library not installed",

                error_code="webauthn_not_available",

                suggestions=["Install python-webauthn: pip install webauthn"],

            )

        if not challenge_handle or not str(challenge_handle).strip():

            raise XWInvalidRequestError(

                "webauthn_challenge_handle is required",

                error_code="invalid_challenge",

                error_description="Pass the handle returned with registration options",

            )

        if not self._rp_id:

            raise XWInvalidRequestError(

                "webauthn_rp_id is required",

                error_code="webauthn_misconfigured",

            )

        store = self._challenge_store()

        h = str(challenge_handle).strip()

        try:

            ch_b64 = store.lookup(h, purpose="registration", user_id=user_id)

        except ValueError as e:

            raise XWInvalidRequestError(

                "Registration challenge not found, expired, or not valid for this user",

                error_code="invalid_challenge",

                error_description=str(e),

            ) from e

        challenge = base64url_to_bytes(ch_b64)

        origins = self._expected_origins or [self._primary_origin()]

        req_uv = _require_user_verification_bool(self._config)

        pem_list = list(getattr(self._config, "webauthn_trusted_attestation_ca_pem", None) or [])

        pem_map = build_pem_root_certs_bytes_by_fmt(pem_list)

        verification = None

        try:

            vreg_kw: dict[str, Any] = dict(

                credential=registration_response,

                expected_challenge=challenge,

                expected_rp_id=self._rp_id,

                expected_origin=origins,

                require_user_verification=req_uv,

            )

            if pem_map:

                vreg_kw["pem_root_certs_bytes_by_fmt"] = pem_map

            verification = verify_registration_response(**vreg_kw)

        except Exception as e:

            logger.error("WebAuthn registration verification failed: %s", e)

            raise XWInvalidRequestError(

                f"Registration verification failed: {e!s}",

                error_code="verification_failed",

                error_description="Failed to verify registration response",

            ) from e



        allow_sync = bool(getattr(self._config, "webauthn_allow_passkey_sync", True))

        if not allow_sync and getattr(verification, "credential_backed_up", False):

            store.invalidate(h)

            raise XWInvalidRequestError(

                "Synced passkeys are not allowed by policy",

                error_code="webauthn_synced_passkey_rejected",

                error_description="Set webauthn_allow_passkey_sync=True to permit iCloud/Google sync",

            )



        credential_id = bytes_to_base64url(verification.credential_id)

        public_key = bytes_to_base64url(verification.credential_public_key)

        user_lifecycle = UserLifecycle(self._auth)

        user = await user_lifecycle.get_user(user_id)

        if not user:

            store.invalidate(h)

            raise XWAuthError(

                "User not found",

                error_code="user_not_found",

                error_description=f"User {user_id} not found",

            )

        if "webauthn_credentials" not in user.attributes:

            user.attributes["webauthn_credentials"] = []

        for cred in user.attributes["webauthn_credentials"]:

            if _credential_id_eq(cred.get("credential_id"), credential_id):

                store.invalidate(h)

                raise XWInvalidRequestError(

                    "This passkey is already registered",

                    error_code="credential_duplicate",

                    error_description="Credential ID already exists for this user",

                )



        credential_data = {

            "credential_id": credential_id,

            "public_key": public_key,

            "counter": verification.sign_count,

            "aaguid": verification.aaguid,

            "attestation_format": str(verification.fmt),

            "user_verified": verification.user_verified,

            "credential_device_type": str(verification.credential_device_type),

            "credential_backed_up": verification.credential_backed_up,

            "resident_key_policy": (getattr(self._config, "webauthn_resident_key", "preferred") or "preferred").strip().lower(),

            "created_at": datetime.now(timezone.utc).isoformat(),

        }

        user.attributes["webauthn_credentials"].append(credential_data)

        await self._storage.save_user(user)

        register_webauthn_credential_mapping(self._auth, credential_id, user_id)

        store.invalidate(h)

        logger.debug("Stored WebAuthn credential for user: %s", user_id)

        await audit_webauthn_event(

            self._auth,

            "webauthn.register.completed",

            user_id=user_id,

            attributes={

                "credential_id_preview": _credential_id_preview(credential_id),

                "attestation_format": str(verification.fmt),

                "user_verified": verification.user_verified,

            },

        )

        return {

            "verified": True,

            "credential_id": credential_id,

        }



    async def generate_authentication_options(

        self,

        user_id: str | None = None,

        allow_credentials: list[dict[str, Any]] | None = None,

    ) -> dict[str, Any]:

        if not USE_WEBAUTHN:

            raise XWAuthError(

                "WebAuthn library not installed",

                error_code="webauthn_not_available",

                suggestions=["Install python-webauthn: pip install webauthn"],

            )

        if not self._rp_id:

            raise XWInvalidRequestError(

                "webauthn_rp_id is required",

                error_code="webauthn_misconfigured",

            )

        challenge = secrets.token_bytes(32)

        challenge_b64 = bytes_to_base64url(challenge)

        ttl = float(getattr(self._config, "webauthn_challenge_ttl_seconds", 300) or 300)

        handle = self._challenge_store().issue(

            challenge_b64url=challenge_b64,

            purpose="authentication",

            user_id=user_id,

            ttl_seconds=ttl,

        )

        credential_descriptors = None

        if allow_credentials:

            credential_descriptors = [

                PublicKeyCredentialDescriptor(

                    id=base64url_to_bytes(cred["id"]),

                    type="public-key",

                )

                for cred in allow_credentials

            ]

        options = generate_authentication_options(

            rp_id=self._rp_id,

            challenge=challenge,

            timeout=self._timeout_ms,

            allow_credentials=credential_descriptors,

            user_verification=self._user_verification or UserVerificationRequirement.PREFERRED,

        )

        options_dict = options_to_json(options)

        options_dict["webauthn_challenge_handle"] = handle

        logger.debug("Generated authentication options for user: %s", user_id or "anonymous")

        return options_dict



    async def verify_authentication(

        self,

        user_id: str,

        authentication_response: dict[str, Any],

        *,

        challenge_handle: str | None = None,

    ) -> dict[str, Any]:

        if not USE_WEBAUTHN:

            raise XWAuthError(

                "WebAuthn library not installed",

                error_code="webauthn_not_available",

                suggestions=["Install python-webauthn: pip install webauthn"],

            )

        if not challenge_handle or not str(challenge_handle).strip():

            raise XWInvalidRequestError(

                "webauthn_challenge_handle is required",

                error_code="invalid_challenge",

                error_description="Pass the handle returned with authentication options",

            )

        if not self._rp_id:

            raise XWInvalidRequestError(

                "webauthn_rp_id is required",

                error_code="webauthn_misconfigured",

            )

        store = self._challenge_store()

        h = str(challenge_handle).strip()

        try:

            ch_b64 = store.lookup(h, purpose="authentication", user_id=user_id)

        except ValueError as e:

            raise XWInvalidRequestError(

                "Authentication challenge not found, expired, or not valid for this user",

                error_code="invalid_challenge",

                error_description=str(e),

            ) from e

        challenge = base64url_to_bytes(ch_b64)

        user_lifecycle = UserLifecycle(self._auth)

        user = await user_lifecycle.get_user(user_id)

        if not user:

            raise XWAuthError(

                "User not found",

                error_code="user_not_found",

                error_description=f"User {user_id} not found",

            )

        credentials = user.attributes.get("webauthn_credentials", [])

        if not credentials:

            raise XWInvalidRequestError(

                "No WebAuthn credentials found for user",

                error_code="no_credentials",

                error_description="User has no registered passkeys",

            )

        credential_id_b64 = authentication_response.get("id")

        matching_credential = None

        for cred in credentials:

            if _credential_id_eq(cred.get("credential_id"), credential_id_b64):

                matching_credential = cred

                break

        if not matching_credential:

            raise XWInvalidRequestError(

                "Credential not found",

                error_code="invalid_credential",

                error_description="Credential ID not found for user",

            )

        prev_counter = int(matching_credential.get("counter") or 0)

        origins = self._expected_origins or [self._primary_origin()]

        req_uv = _require_user_verification_bool(self._config)

        try:

            verification = verify_authentication_response(

                credential=authentication_response,

                expected_challenge=challenge,

                expected_rp_id=self._rp_id,

                expected_origin=origins,

                credential_public_key=base64url_to_bytes(matching_credential["public_key"]),

                credential_current_sign_count=prev_counter,

                require_user_verification=req_uv,

            )

        except Exception as e:

            logger.error("WebAuthn authentication verification failed: %s", e)

            raise XWInvalidRequestError(

                f"Authentication verification failed: {e!s}",

                error_code="verification_failed",

                error_description="Failed to verify authentication response",

            ) from e



        new_count = int(verification.new_sign_count)

        if prev_counter > 0 and new_count <= prev_counter:

            raise XWInvalidRequestError(

                "Authenticator sign counter anomaly",

                error_code="webauthn_clone_detected",

                error_description="Possible cloned authenticator",

            )

        matching_credential["counter"] = new_count

        matching_credential["last_used_at"] = datetime.now(timezone.utc).isoformat()

        matching_credential["last_user_verified"] = verification.user_verified

        matching_credential["last_credential_backed_up"] = verification.credential_backed_up

        matching_credential["last_credential_device_type"] = str(verification.credential_device_type)

        await self._storage.save_user(user)

        store.invalidate(h)

        session_id: str | None = None

        session_manager = getattr(self._auth, "_session_manager", None)

        if session_manager is not None:

            try:

                session_id = await session_manager.create_session(user_id=user_id)

            except Exception:

                session_id = None

        token_manager = TokenManager(self._auth, use_jwt=True)

        amr = ["webauthn", "passkey"]

        access_token = await token_manager.generate_access_token(

            user_id=user_id,

            client_id="webauthn",

            scopes=["openid", "profile", "email"],

            session_id=session_id,

            additional_claims={"aal": "aal2", "amr": amr},

        )

        refresh_token = await token_manager.generate_refresh_token(

            user_id=user_id,

            client_id="webauthn",

        )

        await self._record_session_assurance(session_id, aal="aal2", amr=amr)

        logger.debug("WebAuthn authentication successful for user: %s", user_id)

        cid_prev = _credential_id_preview(str(credential_id_b64 or ""))

        await audit_webauthn_event(

            self._auth,

            "webauthn.login.completed",

            user_id=user_id,

            attributes={

                "credential_id_preview": cid_prev,

                "new_sign_count": new_count,

            },

        )

        return {

            "verified": True,

            "user_id": user_id,

            "access_token": access_token,

            "refresh_token": refresh_token,

            "token_type": "Bearer",

            "expires_in": self._config.access_token_lifetime,

            "session_id": session_id,

            "aal": "aal2",

            "amr": amr,

        }

