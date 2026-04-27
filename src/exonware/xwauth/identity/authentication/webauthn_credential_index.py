# exonware/xwauth.identity/authentication/webauthn_credential_index.py

"""

Maps WebAuthn credential_id (base64url) → user_id for discoverable / conditional passkey login.



Competitors keep a secondary index; we maintain an in-process map updated on successful

registration and rebuild from ``list_users`` on cache miss (suitable for dev / modest tenants;

large deployments should add a persistent index in storage).

"""



from __future__ import annotations



import hmac

from typing import Any



from exonware.xwsystem import get_logger



from exonware.xwauth.identity.users.lifecycle import UserLifecycle
logger = get_logger(__name__)



_ATTR = "_webauthn_credential_id_to_user_id"





def _redis_index(auth: Any):

    return getattr(auth, "_webauthn_credential_index_redis", None)





def _cred_id_eq(a: str | None, b: str | None) -> bool:

    if not a or not b or len(a) != len(b):

        return False

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))





def _index(auth: Any) -> dict[str, str]:

    idx = getattr(auth, _ATTR, None)

    if idx is None:

        idx = {}

        setattr(auth, _ATTR, idx)

    return idx





def register_webauthn_credential_mapping(auth: Any, credential_id_b64: str, user_id: str) -> None:

    """Record mapping after a successful registration (call after persist)."""

    cid = (credential_id_b64 or "").strip()

    uid = (user_id or "").strip()

    if not cid or not uid:

        return

    _index(auth)[cid] = uid

    r = _redis_index(auth)

    if r:

        try:

            r.set_mapping(cid, uid)

        except Exception:

            logger.warning("webauthn credential index redis set failed", exc_info=True)





def unregister_webauthn_credential_mapping(auth: Any, credential_id_b64: str) -> None:

    """Remove mapping when a passkey is deleted (storage + index)."""

    cid = (credential_id_b64 or "").strip()

    if not cid:

        return

    _index(auth).pop(cid, None)

    r = _redis_index(auth)

    if r:

        try:

            r.delete_mapping(cid)

        except Exception:

            logger.warning("webauthn credential index redis delete failed", exc_info=True)





async def rebuild_webauthn_credential_index(auth: Any) -> int:

    """

    Clear and repopulate the in-process ``credential_id → user_id`` map from storage.



    Call after bulk user import, storage failover, or multi-process deploy where each worker

    needs a warm index (competitors use persistent tables; this is the operational equivalent

    until storage exposes a dedicated index).

    """

    idx = _index(auth)

    idx.clear()

    try:

        users = await UserLifecycle(auth).list_users(None)

    except Exception:

        pairs: list[tuple[str, str]] = []

        r = _redis_index(auth)

        if r:

            try:

                r.replace_all(pairs)

            except Exception:

                logger.warning("webauthn credential index redis rebuild failed", exc_info=True)

        return 0

    pairs = []

    for u in users:

        attrs = u.attributes if hasattr(u, "attributes") else {}

        for c in attrs.get("webauthn_credentials") or []:

            stored = c.get("credential_id")

            s = str(stored).strip() if stored else ""

            if s:

                pairs.append((s, u.id))

                idx[s] = u.id

    r = _redis_index(auth)

    if r:

        try:

            r.replace_all(pairs)

        except Exception:

            logger.warning("webauthn credential index redis rebuild failed", exc_info=True)

    return len(pairs)





async def resolve_user_for_webauthn_credential(auth: Any, credential_id_b64: str | None) -> str | None:

    """

    Resolve user_id from authenticator credential id (discoverable assertion).



    Uses the in-memory index first, then scans users via ``UserLifecycle.list_users`` on miss.

    """

    cid = (credential_id_b64 or "").strip()

    if not cid:

        return None

    idx = _index(auth)

    hit = idx.get(cid)

    if hit:

        return hit

    r = _redis_index(auth)

    if r:

        try:

            ru = r.get_user(cid)

        except Exception:

            ru = None

            logger.warning("webauthn credential index redis get failed", exc_info=True)

        if ru:

            idx[cid] = ru

            return ru

    try:

        users = await UserLifecycle(auth).list_users(None)

    except Exception:

        return None

    for u in users:

        attrs = u.attributes if hasattr(u, "attributes") else {}

        for c in attrs.get("webauthn_credentials") or []:

            stored = c.get("credential_id")

            if stored and _cred_id_eq(stored, cid):

                idx[stored] = u.id

                if r:

                    try:

                        r.set_mapping(stored, u.id)

                    except Exception:

                        logger.warning("webauthn credential index redis set failed", exc_info=True)

                return u.id

    return None

