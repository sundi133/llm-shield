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

    ``rev`` is a monotonic per-profile counter and is what routes compare against
    to detect drift. Deliberately NOT a timestamp: ``updated_at`` has second
    granularity, so two edits in the same second would be indistinguishable and a
    stale route would look current; wall-clock also moves backwards under NTP
    correction. Both are stamped here rather than taken from the caller, since a
    caller-supplied revision could mask drift.
    """
    doc = dict(profile)
    doc["profile_id"] = profile_id
    doc["tenant_id"] = tenant_id
    existing = get_profile(tenant_id, profile_id)
    doc["created_at"] = (existing or {}).get("created_at") or int(time.time())
    doc["updated_at"] = int(time.time())
    doc["rev"] = int((existing or {}).get("rev") or 0) + 1

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


# ── effective policy (denormalized onto the route) ────────────────
#
# The guard path reads policy from the route document it ALREADY loads once per
# call (core/mcp/gateway.py::_load_cfg). Resolving a profile at call time would
# add a second Redis GET to every guarded call; computing on write instead keeps
# the hot path at its current round-trip count.
#
# The tenant layer is deliberately NOT merged in here. enforce_tool_call already
# has tenant_config in hand, so folding it in at enforcement time costs nothing
# and avoids having to re-fan-out the entire fleet whenever tenant config
# changes. What lands on the route is: profile <- route overrides.

#: Profile bookkeeping that describes the profile itself rather than the policy
#: it carries. Excluded so a route's effective_policy holds policy only.
_PROFILE_META = ("profile_id", "tenant_id", "created_at", "updated_at", "rev",
                 "description")


def compute_effective_policy(
    profile: Optional[dict], overrides: Optional[dict]
) -> dict:
    """Merge ``profile`` with per-route ``overrides``; overrides win.

    Uses the same deep-merge as the agentic control plane so nested guardrail
    config composes identically in both places (pinned by a coupling test).
    """
    from storage.agentic_control_plane import _deep_merge

    base = {k: v for k, v in (profile or {}).items() if k not in _PROFILE_META}
    return _deep_merge(base, overrides or {})


def stamp_effective_policy(
    cfg: dict, profile: Optional[dict], overrides: Optional[dict]
) -> dict:
    """Return a copy of ``cfg`` with effective_policy/effective_rev refreshed.

    ``effective_rev`` is the profile revision the policy was built from; a route
    whose rev differs from its profile's current ``rev`` has drifted (see
    ``is_drifted``). Pure — the caller persists.
    """
    out = dict(cfg)
    out["effective_policy"] = compute_effective_policy(profile, overrides)
    out["effective_rev"] = int((profile or {}).get("rev") or 0)
    return out


def is_drifted(cfg: dict, profile: Optional[dict]) -> bool:
    """Whether a route's denormalized policy is stale w.r.t. its profile.

    A route with no binding cannot drift. A bound route whose profile has since
    vanished counts as drifted: its stored policy no longer has a source.
    """
    if not cfg.get("profile_id"):
        return False
    if profile is None:
        return True
    return int(cfg.get("effective_rev") or 0) != int(profile.get("rev") or 0)


def recompute_route(tenant_id: str, route: str) -> Optional[dict]:
    """Rebuild one route's effective policy from its current binding. Persists
    and returns the updated config, or None if the route is gone."""
    from storage.mcp_gateway_store import get_upstream, set_upstream

    cfg = get_upstream(tenant_id, route)
    if cfg is None:
        return None
    profile_id = cfg.get("profile_id")
    profile = get_profile(tenant_id, profile_id) if profile_id else None
    if profile_id and profile is None:
        # Keep the last known-good policy rather than silently dropping a bound
        # route to no policy; is_drifted() surfaces it for the reconciler.
        return cfg
    updated = stamp_effective_policy(cfg, profile, cfg.get("overrides"))
    set_upstream(tenant_id, route, updated)
    return updated


def fanout_profile(tenant_id: str, profile_id: str) -> dict:
    """Push a profile change to every route bound to it.

    Returns ``{updated, missing, failed}``. Partial failure is reported rather
    than raised: one unwritable route must not abort the rest of the fleet, and
    anything left behind is detectable via ``is_drifted``.
    """
    updated, missing, failed = [], [], []
    for route in list_bound_routes(tenant_id, profile_id):
        try:
            if recompute_route(tenant_id, route) is None:
                missing.append(route)
            else:
                updated.append(route)
        except Exception:
            failed.append(route)
    return {"updated": updated, "missing": missing, "failed": failed}
