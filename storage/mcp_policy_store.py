"""Per-tenant MCP policy profile store.

A **profile** is a named, reusable policy bundle SecOps authors once and binds to
many MCP servers, so a fleet is governed centrally instead of route by route.
Redis-backed with an in-memory fallback for dev/tests, mirroring
``storage/mcp_gateway_store.py``.

Keys:
    mcp_profile:{tenant_id}:{profile_id}          JSON profile
    mcp_profiles:{tenant_id}                      set/list of profile ids (index)
    mcp_profile:routes:{tenant_id}:{profile_id}   set/list of bound route names

The bound-route index exists so a profile write can fan out to every route that
uses it. It is maintained by the binding layer, not inferred by scanning routes:
a scan would be O(routes) on every profile write and would silently miss routes
whose config failed to decode.

This module stores policy only. It holds no upstream credentials, so nothing here
needs redaction — that stays the job of the upstream store's API layer.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from storage.tenant_store import _fallback_store, _get_redis


def _key(tenant_id: str, profile_id: str) -> str:
    return f"mcp_profile:{tenant_id}:{profile_id}"


def _index_key(tenant_id: str) -> str:
    return f"mcp_profiles:{tenant_id}"


def _routes_key(tenant_id: str, profile_id: str) -> str:
    return f"mcp_profile:routes:{tenant_id}:{profile_id}"


def _decode(raw: Any) -> Optional[dict]:
    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        return json.loads(raw)
    except Exception:
        return None


def _members(key: str) -> list[str]:
    """Read a set-valued index under either backend."""
    r = _get_redis()
    if r:
        raw = r.smembers(key) or set()
        return [m.decode() if isinstance(m, bytes) else m for m in raw]
    return json.loads(_fallback_store.get(key, "[]"))


def _add_member(key: str, value: str) -> None:
    r = _get_redis()
    if r:
        r.sadd(key, value)
        return
    idx = json.loads(_fallback_store.get(key, "[]"))
    if value not in idx:
        idx.append(value)
        _fallback_store[key] = json.dumps(idx)


def _remove_member(key: str, value: str) -> None:
    r = _get_redis()
    if r:
        r.srem(key, value)
        return
    idx = json.loads(_fallback_store.get(key, "[]"))
    if value in idx:
        idx.remove(value)
        _fallback_store[key] = json.dumps(idx)


# ── profiles ──────────────────────────────────────────────────────

def set_profile(tenant_id: str, profile_id: str, profile: dict) -> dict:
    """Create/replace a profile. Returns the stored document.

    ``updated_at`` is stamped here rather than by the caller because it is the
    revision token routes compare against to detect drift; a caller-supplied
    value could silently make a stale route look current.
    """
    doc = dict(profile)
    doc["profile_id"] = profile_id
    doc["tenant_id"] = tenant_id
    existing = get_profile(tenant_id, profile_id)
    doc["created_at"] = (existing or {}).get("created_at") or int(time.time())
    doc["updated_at"] = int(time.time())

    payload = json.dumps(doc)
    r = _get_redis()
    if r:
        r.set(_key(tenant_id, profile_id), payload)
    else:
        _fallback_store[_key(tenant_id, profile_id)] = payload
    _add_member(_index_key(tenant_id), profile_id)
    return doc


def get_profile(tenant_id: str, profile_id: str) -> Optional[dict]:
    r = _get_redis()
    key = _key(tenant_id, profile_id)
    raw = r.get(key) if r else _fallback_store.get(key)
    return _decode(raw)


def list_profiles(tenant_id: str) -> list[dict]:
    out = []
    for profile_id in sorted(_members(_index_key(tenant_id))):
        doc = get_profile(tenant_id, profile_id)
        if doc:
            out.append(doc)
    return out


def delete_profile(tenant_id: str, profile_id: str) -> bool:
    """Remove a profile and its bound-route index. Returns True if it existed.

    Callers must refuse this while routes are still bound (the API returns 409);
    the store stays mechanical so tests can construct any state they need.
    """
    existed = get_profile(tenant_id, profile_id) is not None
    r = _get_redis()
    if r:
        r.delete(_key(tenant_id, profile_id))
        r.delete(_routes_key(tenant_id, profile_id))
    else:
        _fallback_store.pop(_key(tenant_id, profile_id), None)
        _fallback_store.pop(_routes_key(tenant_id, profile_id), None)
    _remove_member(_index_key(tenant_id), profile_id)
    return existed


# ── bindings (route -> profile), indexed for fan-out ──────────────

def bind_route(tenant_id: str, profile_id: str, route: str) -> None:
    """Record that ``route`` uses ``profile_id``. Idempotent."""
    _add_member(_routes_key(tenant_id, profile_id), route)


def unbind_route(tenant_id: str, profile_id: str, route: str) -> None:
    """Drop a route from a profile's fan-out index. Idempotent."""
    _remove_member(_routes_key(tenant_id, profile_id), route)


def list_bound_routes(tenant_id: str, profile_id: str) -> list[str]:
    return sorted(_members(_routes_key(tenant_id, profile_id)))
