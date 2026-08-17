"""Portal sessions: who is signed in, and the ability to sign them out.

The tenant portal authenticates with a shared API key kept in browser storage,
so every administrative action is attributed to a tenant rather than a person.
This is the storage half of fixing that: a session identifies a human, and can
be destroyed.

Server-side, with an opaque id in the cookie, rather than a signed JWT. A
stateless session cannot be revoked, and "we removed their access" is the
question a security review asks immediately after "who did this". The cost is
one Redis GET per portal request, on the admin plane, where nothing is
latency-sensitive.

Keys:
    portalsession:{session_id}          → the session record
    portalsessions:{tenant_id}:{sub}    → [session_id, ...] for revoke-all

Nothing here runs on the guard path. `/guardrails/*`, `cap/mint` and
`tools/call` resolve tenants through resolve_tenant_by_api_key(), which this
module does not touch.

Spec: docs/spec-portal-sso.md PR 1
"""
import logging
import os
import secrets
import time
from typing import Optional

from storage.tenant_store import kv_get, kv_set, kv_delete

logger = logging.getLogger("votal.portal_sessions")

DEFAULT_TTL_SECONDS = 8 * 60 * 60

# An absolute cap, not a preference. A tenant that sets a year here has
# disabled session expiry while believing they configured it.
_MAX_TTL_SECONDS = 30 * 24 * 60 * 60

_SESSION_PREFIX = "portalsession:"
_INDEX_PREFIX = "portalsessions:"

# Copied into the session at login and never re-read from the IdP per request.
# A demotion therefore takes effect at the next login or at explicit revoke,
# bounded by the TTL. Re-reading groups per request would mean a JWKS-backed
# lookup on every portal call. Documented in the spec, section 7.
_COPIED_CLAIMS = ("sub", "email", "name", "issuer")


def session_ttl() -> int:
    """Absolute session lifetime in seconds."""
    try:
        ttl = int(os.environ.get("SHIELD_PORTAL_SESSION_TTL", DEFAULT_TTL_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_TTL_SECONDS
    if ttl <= 0:
        return DEFAULT_TTL_SECONDS
    return min(ttl, _MAX_TTL_SECONDS)


def idle_timeout() -> int:
    """Seconds of inactivity before a session dies, or 0 for no idle timeout.

    Off by default: it is what regulated deployments are asked for, and also
    what makes a portal log people out mid-task. The capability exists so the
    answer to the questionnaire is a configuration rather than a roadmap.
    """
    try:
        return max(0, int(os.environ.get("SHIELD_PORTAL_SESSION_IDLE", "0")))
    except (TypeError, ValueError):
        return 0


def _now() -> int:
    return int(time.time())


def _index_key(tenant_id: str, sub: str) -> str:
    return f"{_INDEX_PREFIX}{tenant_id}:{sub}"


def create_session(tenant_id: str, claims: dict, *, is_admin: bool) -> str:
    """Create a session and return its id.

    The id is generated HERE, after the caller has verified the token, and is
    never accepted from a parameter. That is what makes session fixation
    impossible rather than merely unlikely.

    Raises ValueError without a tenant or a subject: a session that identifies
    nobody is worse than no session, because it looks like attribution.
    """
    sub = str((claims or {}).get("sub") or "").strip()
    if not tenant_id or not sub:
        raise ValueError("a portal session requires both a tenant and a subject")

    ttl = session_ttl()
    now = _now()
    session_id = secrets.token_urlsafe(32)

    record = {
        "tenant_id": tenant_id,
        "is_admin": bool(is_admin),
        "created_at": now,
        "last_seen": now,
        # Authoritative. The Redis TTL below is a reclaim hint; the in-memory
        # fallback has no expiry at all, so without this a Redis-less
        # deployment would honour a session forever.
        "expires_at": now + ttl,
    }
    for claim in _COPIED_CLAIMS:
        record[claim] = str((claims or {}).get(claim) or "")

    kv_set(_SESSION_PREFIX + session_id, record, ttl=ttl)

    index_key = _index_key(tenant_id, sub)
    ids = [i for i in (kv_get(index_key) or []) if isinstance(i, str)]
    ids.append(session_id)
    kv_set(index_key, ids[-50:], ttl=ttl)   # bounded: one human, many logins

    return session_id


def get_session(session_id: str) -> Optional[dict]:
    """The session, or None if it is absent, expired or idle-timed-out.

    Expiry is checked against the record rather than trusted to the store, and
    an expired record is deleted on the way out so a Redis-less deployment does
    not accumulate them.
    """
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
    """Record activity. A no-op unless an idle timeout is configured.

    Guarded so the common case stays one read per request: writing last_seen on
    every call when nothing consumes it is a store write bought for nothing.
    """
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
    """Destroy one session. True if there was one to destroy.

    Also drops it from its subject's index; a stale id there would make
    revoke_all report a count that includes sessions already gone.
    """
    if not session_id:
        return False
    record = kv_get(_SESSION_PREFIX + session_id)
    kv_delete(_SESSION_PREFIX + session_id)

    if isinstance(record, dict):
        index_key = _index_key(record.get("tenant_id", ""), record.get("sub", ""))
        ids = [i for i in (kv_get(index_key) or []) if i != session_id]
        if ids:
            kv_set(index_key, ids, ttl=session_ttl())
        else:
            kv_delete(index_key)
    return record is not None


def revoke_all_for_subject(tenant_id: str, sub: str) -> int:
    """Sign one human out everywhere. Returns how many sessions were destroyed.

    This is the answer to "we removed their access", and the reason sessions
    are server-side at all.
    """
    if not tenant_id or not sub:
        return 0
    index_key = _index_key(tenant_id, sub)
    ids = [i for i in (kv_get(index_key) or []) if isinstance(i, str)]
    revoked = 0
    for session_id in ids:
        if kv_get(_SESSION_PREFIX + session_id) is not None:
            revoked += 1
        kv_delete(_SESSION_PREFIX + session_id)
    kv_delete(index_key)
    return revoked


def list_sessions_for_subject(tenant_id: str, sub: str) -> list:
    """Live sessions for one human, newest last. Expired entries are skipped."""
    if not tenant_id or not sub:
        return []
    ids = [i for i in (kv_get(_index_key(tenant_id, sub)) or [])
           if isinstance(i, str)]
    out = []
    for session_id in ids:
        record = get_session(session_id)
        if record:
            out.append({"session_id": session_id,
                        "created_at": record.get("created_at"),
                        "last_seen": record.get("last_seen"),
                        "expires_at": record.get("expires_at")})
    return out
