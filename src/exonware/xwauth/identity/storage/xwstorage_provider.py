#!/usr/bin/env python3
"""
xwauth storage adapter backed by xwstorage-compatible read/write APIs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from exonware.xwsystem import get_logger

from .mock import (
    MockAuditLog,
    MockAuthorizationCode,
    MockDeviceCode,
    MockSession,
    MockStorageProvider,
    MockToken,
    MockUser,
)

logger = get_logger(__name__)


class XWStorageProvider(MockStorageProvider):
    """
    xwstorage-backed implementation for xwauth IStorageProvider.

    Uses a single persisted state key to keep compatibility with lightweight
    xwstorage.connect connectors while preserving existing mock behavior.
    """

    STATE_KEY = "xwauth/state"

    def __init__(self, storage: Any):
        super().__init__()
        self._backend = storage
        self._loaded = False
        self._generic_entities: dict[str, dict[str, dict[str, Any]]] = {}

    async def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        try:
            payload = await self._backend.read(self.STATE_KEY)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            self._hydrate(payload)
        self._loaded = True

    def _serialize_datetime(self, value: Any) -> Any:
        if isinstance(value, datetime):
            return value.isoformat()
        return value

    def _deserialize_datetime(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            return datetime.fromisoformat(value)
        return datetime.now()

    def _user_to_dict(self, user: MockUser) -> dict[str, Any]:
        return {
            "id": user.id,
            "email": user.email,
            "phone": user.phone,
            "password_hash": user.password_hash,
            "attributes": dict(user.attributes),
        }

    def _session_to_dict(self, session: MockSession) -> dict[str, Any]:
        return {
            "id": session.id,
            "user_id": session.user_id,
            "expires_at": self._serialize_datetime(session.expires_at),
            "attributes": dict(session.attributes),
            "metadata": dict(session.metadata),
        }

    def _token_to_dict(self, token: MockToken) -> dict[str, Any]:
        return {
            "id": token.id,
            "user_id": token.user_id,
            "client_id": token.client_id,
            "token_type": token.token_type,
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "expires_at": self._serialize_datetime(token.expires_at),
            "scopes": list(token.scopes),
            "attributes": dict(token.attributes),
        }

    def _audit_to_dict(self, log: MockAuditLog) -> dict[str, Any]:
        return {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "timestamp": self._serialize_datetime(log.timestamp),
            "resource": log.resource,
            "attributes": dict(log.attributes),
            "context": dict(log.context),
        }

    def _authorization_code_to_dict(self, code: MockAuthorizationCode) -> dict[str, Any]:
        return {
            "code": code.code,
            "client_id": code.client_id,
            "redirect_uri": code.redirect_uri,
            "scopes": list(code.scopes),
            "code_challenge": code.code_challenge,
            "code_challenge_method": code.code_challenge_method,
            "expires_at": self._serialize_datetime(code.expires_at),
            "created_at": self._serialize_datetime(code.created_at),
            "user_id": code.user_id,
            "attributes": dict(code.attributes),
        }

    def _device_code_to_dict(self, code: MockDeviceCode) -> dict[str, Any]:
        return {
            "device_code": code.device_code,
            "user_code": code.user_code,
            "client_id": code.client_id,
            "scopes": list(code.scopes),
            "expires_at": self._serialize_datetime(code.expires_at),
            "created_at": self._serialize_datetime(code.created_at),
            "status": code.status,
            "user_id": code.user_id,
            "attributes": dict(code.attributes),
        }

    def _serialize_state(self) -> dict[str, Any]:
        return {
            "users": {uid: self._user_to_dict(user) for uid, user in self._users.items()},
            "users_by_email": dict(self._users_by_email),
            "users_by_phone": dict(self._users_by_phone),
            "users_by_provider": {
                f"{provider}|{provider_user_id}": uid
                for (provider, provider_user_id), uid in self._users_by_provider.items()
            },
            "sessions": {sid: self._session_to_dict(session) for sid, session in self._sessions.items()},
            "sessions_by_user": {uid: list(session_ids) for uid, session_ids in self._sessions_by_user.items()},
            "tokens": {tid: self._token_to_dict(token) for tid, token in self._tokens.items()},
            "tokens_by_access": dict(self._tokens_by_access),
            "tokens_by_refresh": dict(self._tokens_by_refresh),
            "tokens_by_user": {uid: list(token_ids) for uid, token_ids in self._tokens_by_user.items()},
            "audit_logs": [self._audit_to_dict(log) for log in self._audit_logs],
            "authorization_codes": {
                code: self._authorization_code_to_dict(item)
                for code, item in self._authorization_codes.items()
            },
            "device_codes": {
                code: self._device_code_to_dict(item)
                for code, item in self._device_codes.items()
            },
            "device_codes_by_user_code": dict(self._device_codes_by_user_code),
            "generic_entities": dict(self._generic_entities),
        }

    def _hydrate(self, payload: dict[str, Any]) -> None:
        users = payload.get("users", {})
        self._users = {
            uid: MockUser(**data)
            for uid, data in users.items()
            if isinstance(data, dict)
        }
        self._users_by_email = dict(payload.get("users_by_email", {}))
        self._users_by_phone = dict(payload.get("users_by_phone", {}))
        self._users_by_provider = {}
        for composite_key, uid in dict(payload.get("users_by_provider", {})).items():
            if "|" in composite_key:
                provider, provider_user_id = composite_key.split("|", 1)
                self._users_by_provider[(provider, provider_user_id)] = uid

        self._sessions = {}
        for sid, data in dict(payload.get("sessions", {})).items():
            if not isinstance(data, dict):
                continue
            self._sessions[sid] = MockSession(
                id=data.get("id", sid),
                user_id=data.get("user_id", ""),
                expires_at=self._deserialize_datetime(data.get("expires_at")),
                attributes=dict(data.get("attributes", {})),
                metadata=dict(data.get("metadata", {})),
            )
        self._sessions_by_user = {
            uid: list(session_ids)
            for uid, session_ids in dict(payload.get("sessions_by_user", {})).items()
        }

        self._tokens = {}
        for tid, data in dict(payload.get("tokens", {})).items():
            if not isinstance(data, dict):
                continue
            self._tokens[tid] = MockToken(
                id=data.get("id", tid),
                user_id=data.get("user_id"),
                client_id=data.get("client_id", ""),
                token_type=data.get("token_type", "Bearer"),
                access_token=data.get("access_token", ""),
                refresh_token=data.get("refresh_token"),
                expires_at=self._deserialize_datetime(data.get("expires_at")),
                scopes=list(data.get("scopes", [])),
                attributes=dict(data.get("attributes", {})),
            )
        self._tokens_by_access = dict(payload.get("tokens_by_access", {}))
        self._tokens_by_refresh = dict(payload.get("tokens_by_refresh", {}))
        self._tokens_by_user = {
            uid: list(token_ids)
            for uid, token_ids in dict(payload.get("tokens_by_user", {})).items()
        }

        self._audit_logs = []
        for item in list(payload.get("audit_logs", [])):
            if not isinstance(item, dict):
                continue
            self._audit_logs.append(
                MockAuditLog(
                    id=item.get("id", ""),
                    user_id=item.get("user_id"),
                    action=item.get("action", ""),
                    timestamp=self._deserialize_datetime(item.get("timestamp")),
                    resource=item.get("resource"),
                    attributes=dict(item.get("attributes", {})),
                    context=dict(item.get("context", {})),
                )
            )

        self._authorization_codes = {}
        for code, item in dict(payload.get("authorization_codes", {})).items():
            if not isinstance(item, dict):
                continue
            self._authorization_codes[code] = MockAuthorizationCode(
                code=item.get("code", code),
                client_id=item.get("client_id", ""),
                redirect_uri=item.get("redirect_uri", ""),
                scopes=list(item.get("scopes", [])),
                code_challenge=item.get("code_challenge"),
                code_challenge_method=item.get("code_challenge_method"),
                expires_at=self._deserialize_datetime(item.get("expires_at")),
                created_at=self._deserialize_datetime(item.get("created_at")),
                user_id=item.get("user_id"),
                attributes=dict(item.get("attributes", {})),
            )

        self._device_codes = {}
        for code, item in dict(payload.get("device_codes", {})).items():
            if not isinstance(item, dict):
                continue
            self._device_codes[code] = MockDeviceCode(
                device_code=item.get("device_code", code),
                user_code=item.get("user_code", ""),
                client_id=item.get("client_id", ""),
                scopes=list(item.get("scopes", [])),
                expires_at=self._deserialize_datetime(item.get("expires_at")),
                created_at=self._deserialize_datetime(item.get("created_at")),
                status=item.get("status", "pending"),
                user_id=item.get("user_id"),
                attributes=dict(item.get("attributes", {})),
            )
        self._device_codes_by_user_code = dict(payload.get("device_codes_by_user_code", {}))
        self._generic_entities = {
            entity_type: dict(items)
            for entity_type, items in dict(payload.get("generic_entities", {})).items()
        }

    async def _persist(self) -> None:
        try:
            await self._backend.write(self.STATE_KEY, self._serialize_state())
        except Exception as exc:
            logger.warning(f"Failed to persist xwauth storage state: {exc}")

    # --- IBasicProviderStorage ---
    async def save(self, entity_type: str, entity_id: str, data: dict[str, Any]) -> None:
        await self._ensure_loaded()
        self._generic_entities.setdefault(entity_type, {})[entity_id] = dict(data)
        await self._persist()

    async def get(self, entity_type: str, entity_id: str) -> dict[str, Any] | None:
        await self._ensure_loaded()
        return dict(self._generic_entities.get(entity_type, {}).get(entity_id, {})) or None

    async def get_by_field(self, entity_type: str, field: str, value: Any) -> dict[str, Any] | None:
        await self._ensure_loaded()
        for item in self._generic_entities.get(entity_type, {}).values():
            if isinstance(item, dict) and item.get(field) == value:
                return dict(item)
        return None

    async def update(self, entity_type: str, entity_id: str, updates: dict[str, Any]) -> None:
        await self._ensure_loaded()
        record = self._generic_entities.setdefault(entity_type, {}).setdefault(entity_id, {})
        record.update(dict(updates))
        await self._persist()

    async def delete(self, entity_type: str, entity_id: str) -> None:
        await self._ensure_loaded()
        self._generic_entities.setdefault(entity_type, {}).pop(entity_id, None)
        await self._persist()

    async def list(self, entity_type: str, filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        await self._ensure_loaded()
        results = list(self._generic_entities.get(entity_type, {}).values())
        if not filters:
            return [dict(item) for item in results if isinstance(item, dict)]
        filtered: list[dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            if all(item.get(key) == value for key, value in filters.items()):
                filtered.append(dict(item))
        return filtered

    # --- domain methods, persisted via base behavior ---
    async def save_user(self, user: Any) -> None:
        await self._ensure_loaded()
        await super().save_user(user)
        await self._persist()

    async def update_user(self, user_id: str, updates: dict[str, Any]) -> None:
        await self._ensure_loaded()
        await super().update_user(user_id, updates)
        await self._persist()

    async def delete_user(self, user_id: str) -> None:
        await self._ensure_loaded()
        await super().delete_user(user_id)
        await self._persist()

    async def get_user(self, user_id: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_user(user_id)

    async def get_user_by_email(self, email: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_user_by_email(email)

    async def get_user_by_phone(self, phone: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_user_by_phone(phone)

    async def find_user_by_provider(self, provider: str, provider_user_id: str) -> Any | None:
        await self._ensure_loaded()
        return await super().find_user_by_provider(provider, provider_user_id)

    async def list_users(self, filters: dict[str, Any] | None = None) -> list[Any]:
        await self._ensure_loaded()
        return await super().list_users(filters)

    async def save_session(self, session: Any) -> None:
        await self._ensure_loaded()
        await super().save_session(session)
        await self._persist()

    async def get_session(self, session_id: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_session(session_id)

    async def delete_session(self, session_id: str) -> None:
        await self._ensure_loaded()
        await super().delete_session(session_id)
        await self._persist()

    async def list_user_sessions(self, user_id: str) -> list[Any]:
        await self._ensure_loaded()
        return await super().list_user_sessions(user_id)

    async def save_token(self, token: Any) -> None:
        await self._ensure_loaded()
        await super().save_token(token)
        await self._persist()

    async def get_token(self, token_id: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_token(token_id)

    async def get_token_by_access_token(self, access_token: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_token_by_access_token(access_token)

    async def get_token_by_refresh_token(self, refresh_token: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_token_by_refresh_token(refresh_token)

    async def delete_token(self, token_id: str) -> None:
        await self._ensure_loaded()
        await super().delete_token(token_id)
        await self._persist()

    async def list_user_tokens(self, user_id: str) -> list[Any]:
        await self._ensure_loaded()
        return await super().list_user_tokens(user_id)

    async def save_audit_log(self, log: Any) -> None:
        await self._ensure_loaded()
        await super().save_audit_log(log)
        await self._persist()

    async def get_audit_logs(self, filters: dict[str, Any] | None = None) -> list[Any]:
        await self._ensure_loaded()
        return await super().get_audit_logs(filters)

    async def save_authorization_code(self, code: Any) -> None:
        await self._ensure_loaded()
        await super().save_authorization_code(code)
        await self._persist()

    async def get_authorization_code(self, code: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_authorization_code(code)

    async def delete_authorization_code(self, code: str) -> None:
        await self._ensure_loaded()
        await super().delete_authorization_code(code)
        await self._persist()

    async def save_device_code(self, device_code: Any) -> None:
        await self._ensure_loaded()
        await super().save_device_code(device_code)
        await self._persist()

    async def get_device_code(self, device_code: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_device_code(device_code)

    async def get_device_code_by_user_code(self, user_code: str) -> Any | None:
        await self._ensure_loaded()
        return await super().get_device_code_by_user_code(user_code)

    async def update_device_code_status(
        self,
        device_code: str,
        status: str,
        user_id: str | None = None,
    ) -> None:
        await self._ensure_loaded()
        await super().update_device_code_status(device_code, status, user_id=user_id)
        await self._persist()

    async def delete_device_code(self, device_code: str) -> None:
        await self._ensure_loaded()
        await super().delete_device_code(device_code)
        await self._persist()
