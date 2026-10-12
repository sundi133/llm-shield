"""Admin-operator sessions: who is signed in to the Admin Console, revocably.

The admin plane authenticates with a shared X-Admin-Key (SHIELD_ADMIN_KEY),
so every platform action is attributed to "the admin key" rather than a person.
This is the storage half of fixing that for operators: a session identifies a
human operator (from Votal's own IdP), carries their operator roles, and can be
destroyed. The X-Admin-Key stays as a break-glass credential.

Server-side, opaque id in the cookie `shield_admin_session`, like
storage.portal_sessions — but NOT tenant-scoped: an operator is not a tenant.

Keys:
    adminsession:{session_id}   → the session record
    adminsessions:{sub}         → [session_id, ...] for revoke-all / SLO

Nothing here runs on the guard path.

Spec: docs/specs/spec-sso-primary-login.md PR 5
"""
import logging
import os
import secrets
import time
from typing import Optional

from storage.tenant_store import kv_get, kv_set, kv_delete

logger = logging.getLogger("votal.admin_sessions")

DEFAULT_TTL_SECONDS = 8 * 60 * 60
_MAX_TTL_SECONDS = 30 * 24 * 60 * 60

_SESSION_PREFIX = "adminsession:"
_INDEX_PREFIX = "adminsessions:"

_COPIED_CLAIMS = ("sub", "email", "name", "issuer")


def session_ttl() -> int:
    """Absolute admin-session lifetime in seconds."""
    try:
        ttl = int(os.environ.get("SHIELD_ADMIN_SESSION_TTL", DEFAULT_TTL_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_TTL_SECONDS
    if ttl <= 0:
        return DEFAULT_TTL_SECONDS
    return min(ttl, _MAX_TTL_SECONDS)


def idle_timeout() -> int:
    """Seconds of inactivity before an admin session dies, or 0 for none."""
    try:
        return max(0, int(os.environ.get("SHIELD_ADMIN_SESSION_IDLE", "0")))
    except (TypeError, ValueError):
        return 0


def _now() -> int:
    return int(time.time())


def _index_key(sub: str) -> str:
    return f"{_INDEX_PREFIX}{sub}"


def create_session(claims: dict, *, roles: Optional[list] = None) -> str:
    """Create an admin-operator session and return its id.

    The id is generated HERE after the caller verified the token, never from a
    parameter (session fixation). Raises ValueError without a subject.
    """
    sub = str((claims or {}).get("sub") or "").strip()
    if not sub:
        raise ValueError("an admin session requires a subject")

    ttl = session_ttl()
    now = _now()
    session_id = secrets.token_urlsafe(32)

    record = {
        "kind": "admin_operator",
        "is_admin": True,
        "roles": [str(r) for r in (roles or [])],
        "created_at": now,
        "last_seen": now,
        "expires_at": now + ttl,
        # auth_time anchors step-up re-auth (EH-5, a later PR).
        "auth_time": now,
    }
    for claim in _COPIED_CLAIMS:
        record[claim] = str((claims or {}).get(claim) or "")

    kv_set(_SESSION_PREFIX + session_id, record, ttl=ttl)

    index_key = _index_key(sub)
    ids = [i for i in (kv_get(index_key) or []) if isinstance(i, str)]
    ids.append(session_id)
    kv_set(index_key, ids[-50:], ttl=ttl)

    return session_id


def get_session(session_id: str) -> Optional[dict]:
    """The session, or None if absent/expired/idle-timed-out."""
    if not session_id or not isinstance(session_id, str):
        return None

    record = kv_get(_SESSION_PREFIX + session_id)
    if not isinstance(record, dict):
        return None

    now = _now()
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, int) or now >= expires_at:
        revoke_session(session_id)
        return None

    idle = idle_timeout()
    if idle:
        last_seen = record.get("last_seen")
        if not isinstance(last_seen, int) or now - last_seen > idle:
            revoke_session(session_id)
            return None

    return record


def touch_session(session_id: str) -> None:
    """Record activity. A no-op unless an idle timeout is configured."""
    if not idle_timeout():
        return
    record = get_session(session_id)
    if not record:
        return
    record["last_seen"] = _now()
    remaining = record["expires_at"] - _now()
    if remaining > 0:
        kv_set(_SESSION_PREFIX + session_id, record, ttl=remaining)


def revoke_session(session_id: str) -> bool:
    """Destroy one admin session. True if there was one to destroy."""
    if not session_id:
        return False
    record = kv_get(_SESSION_PREFIX + session_id)
    kv_delete(_SESSION_PREFIX + session_id)

    if isinstance(record, dict):
        index_key = _index_key(record.get("sub", ""))
        ids = [i for i in (kv_get(index_key) or []) if i != session_id]
        if ids:
            kv_set(index_key, ids, ttl=session_ttl())
        else:
            kv_delete(index_key)
    return record is not None


def revoke_all_for_subject(sub: str) -> int:
    """Sign one operator out everywhere (deprovision / SLO). Count destroyed."""
    if not sub:
        return 0
    index_key = _index_key(sub)
    ids = [i for i in (kv_get(index_key) or []) if isinstance(i, str)]
    revoked = 0
    for session_id in ids:
        if kv_get(_SESSION_PREFIX + session_id) is not None:
            revoked += 1
        kv_delete(_SESSION_PREFIX + session_id)
    kv_delete(index_key)
    return revoked


def list_sessions_for_subject(sub: str) -> list:
    """Live sessions for one operator, newest last."""
    if not sub:
        return []
    ids = [i for i in (kv_get(_index_key(sub)) or []) if isinstance(i, str)]
    out = []
    for session_id in ids:
        record = get_session(session_id)
        if record:
            out.append({"session_id": session_id,
                        "created_at": record.get("created_at"),
                        "last_seen": record.get("last_seen"),
                        "expires_at": record.get("expires_at")})
    return out
