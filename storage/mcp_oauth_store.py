"""Per-route OAuth brokering state for upstream MCP servers.

Some MCP servers issue only short-lived OAuth tokens and have no API key at all
(`mcp.higgsfield.ai` is the reference case). Brokering means Shield completes the
authorization-code flow once, holds the refresh token, and keeps a valid access
token in the vault so the gateway's existing ``shield://`` header reference always
resolves. See docs/spec-mcp-oauth-brokering.md.

Two records, deliberately separate:

    mcp_oauth:{tenant_id}:{route}     the broker record — endpoints, client id,
                                      vault refs, status, expiry. No TTL.
    mcp_oauth:pending:{state}         one in-flight authorization, TTL-bounded.

**No secret material is stored here.** Access tokens, refresh tokens and client
secrets live in the vault (encrypted, bound to the upstream host); this record
holds only the *references* to them. The one exception is the pending record's
PKCE ``code_verifier``, which is short-lived by construction (§3.2 of the spec)
and worthless once the flow completes or its TTL expires.

The broker record exists separately from the vault because an expired refresh
token is not a missing secret — it is a *re-consent required* condition, and the
console has to be able to say which.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Optional

from storage.tenant_store import _fallback_store, _get_redis

#: How long an operator has to complete the browser redirect. Doubles as the CSRF
#: window: a `state` is single-use and dies with the record, so a replayed or
#: fabricated callback resolves to nothing.
PENDING_TTL_SECONDS = 600

#: Status values, operator-facing.
STATUS_PENDING = "pending"           # flow started, callback not yet received
STATUS_CONNECTED = "connected"       # usable access token in the vault
STATUS_NEEDS_CONSENT = "needs_consent"  # refresh rejected — a human must re-authorize
STATUS_ERROR = "error"               # transient failure; retried automatically


def _key(tenant_id: str, route: str) -> str:
    return f"mcp_oauth:{tenant_id}:{route}"


def _pending_key(state: str) -> str:
    return f"mcp_oauth:pending:{state}"


def _decode(raw: Any) -> Optional[dict]:
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except Exception:
        return None


# ── vault reference naming ───────────────────────────────────────────
#
# Derived, never stored as free text, so the refresh path cannot be pointed at a
# different route's secret by editing a record.

def access_ref(route: str) -> str:
    return f"oauth-{route}-access"


def refresh_ref(route: str) -> str:
    return f"oauth-{route}-refresh"


def client_secret_ref(route: str) -> str:
    return f"oauth-{route}-client"


# ── broker record ────────────────────────────────────────────────────

def set_broker(tenant_id: str, route: str, record: dict) -> dict:
    """Create/replace the broker record for (tenant, route)."""
    doc = dict(record)
    doc["route"] = route
    doc["tenant_id"] = tenant_id
    doc["updated_at"] = int(time.time())
    payload = json.dumps(doc)

    r = _get_redis()
    if r:
        r.set(_key(tenant_id, route), payload)
    else:
        _fallback_store[_key(tenant_id, route)] = payload
    return doc


def get_broker(tenant_id: str, route: str) -> Optional[dict]:
    r = _get_redis()
    key = _key(tenant_id, route)
    return _decode(r.get(key) if r else _fallback_store.get(key))


def delete_broker(tenant_id: str, route: str) -> bool:
    """Forget the brokering state. Returns True if a record existed.

    Callers must revoke upstream and delete the vault entries too — dropping only
    this record would leave a live delegation nobody can see or revoke.
    """
    existed = get_broker(tenant_id, route) is not None
    r = _get_redis()
    if r:
        r.delete(_key(tenant_id, route))
    else:
        _fallback_store.pop(_key(tenant_id, route), None)
    return existed


def update_status(tenant_id: str, route: str, status: str,
                  *, error: str = "", expires_at: Optional[int] = None,
                  mark_refreshed: bool = False) -> Optional[dict]:
    """Patch just the operational fields. Returns the updated record, or None.

    Separate from ``set_broker`` so the refresh loop cannot accidentally clobber
    endpoints or vault refs while recording an outcome.
    """
    rec = get_broker(tenant_id, route)
    if rec is None:
        return None
    rec["status"] = status
    rec["last_error"] = error
    if expires_at is not None:
        rec["expires_at"] = int(expires_at)
    if mark_refreshed:
        rec["last_refresh_at"] = int(time.time())
    return set_broker(tenant_id, route, rec)


def due_for_refresh(record: dict, *, margin_seconds: int, now: Optional[int] = None) -> bool:
    """Whether this route's access token should be refreshed now.

    Only ``connected`` routes are refreshed. ``needs_consent`` deliberately is
    not: the grant is gone and retrying cannot recover it, so a loop would hammer
    the provider forever and bury the one condition a human must act on.

    A record with no ``expires_at`` is treated as due — an unknown expiry is more
    safely handled by refreshing than by assuming validity.
    """
    if record.get("status") != STATUS_CONNECTED:
        return False
    now = int(now if now is not None else time.time())
    expires_at = record.get("expires_at")
    if not expires_at:
        return True
    return int(expires_at) - int(margin_seconds) <= now


def list_brokered_routes(tenant_id: str) -> list[str]:
    """Routes with brokering configured, for the refresh sweep and the console.

    Derived from the gateway's own route index rather than a second index of its
    own: a separate index could drift, and a route that no longer exists must not
    keep being refreshed.
    """
    from storage.mcp_gateway_store import list_upstreams

    out = []
    for cfg in list_upstreams(tenant_id):
        route = cfg.get("route")
        if route and get_broker(tenant_id, route) is not None:
            out.append(route)
    return sorted(out)


# ── pending authorization ────────────────────────────────────────────

def new_state() -> str:
    """An unguessable, single-use CSRF token. 256 bits of entropy."""
    return secrets.token_urlsafe(32)


def put_pending(state: str, tenant_id: str, route: str, code_verifier: str,
                redirect_uri: str) -> dict:
    """Record one in-flight authorization, keyed by ``state``.

    The tenant is stored HERE rather than passed back through the callback URL,
    because a query parameter is attacker-controlled: binding tenancy to the
    unguessable state is what stops a forged callback attaching a token to
    somebody else's route.
    """
    doc = {
        "state": state,
        "tenant_id": tenant_id,
        "route": route,
        "code_verifier": code_verifier,
        "redirect_uri": redirect_uri,
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + PENDING_TTL_SECONDS,
    }
    payload = json.dumps(doc)

    r = _get_redis()
    if r:
        r.set(_pending_key(state), payload, ex=PENDING_TTL_SECONDS)
    else:
        # The fallback store has no expiry, so the timestamp is authoritative and
        # take_pending() enforces it. Without that check a dev-mode state would
        # live forever, which is exactly the replay window the TTL exists to shut.
        _fallback_store[_pending_key(state)] = payload
    return doc


def take_pending(state: str) -> Optional[dict]:
    """Consume a pending record: returns it and deletes it, or None.

    Single-use by construction — the delete happens whether or not the caller
    goes on to succeed, so a leaked authorization code cannot be replayed against
    a still-valid state.
    """
    if not state:
        return None
    key = _pending_key(state)
    r = _get_redis()
    raw = r.get(key) if r else _fallback_store.get(key)
    rec = _decode(raw)

    if r:
        r.delete(key)
    else:
        _fallback_store.pop(key, None)

    if rec is None:
        return None
    if int(rec.get("expires_at") or 0) < int(time.time()):
        return None  # expired; already deleted above
    return rec
