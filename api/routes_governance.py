"""Agent governance & access intelligence (read-only).

Phase 1 — Agent Inventory: merge the agent registry (what each agent *can*
do) with agents observed in traffic but never registered (shadow agents).

Phase 2 — Used-vs-Granted: diff the tools/resources an agent was *granted*
against what it has *actually* exercised (from the runtime auth-event buffer),
surfacing least-privilege candidates (granted-but-unused) and drift
(used-but-not-granted).

LATENCY: every endpoint here is a read-only aggregation over data already
written by the auth/registry paths (registry KV + agent_auth_stats). Nothing
in this module runs on the guard/inference path — no LLM call ever waits on it.
These are portal/query endpoints, safe to cache.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from api.routes_agents_registry import get_tenant_from_api_key, get_redis_data
from storage import agent_auth_stats as stats

router = APIRouter(prefix="/v1/governance", tags=["governance"])


def _granted_tools(entry: dict) -> list[str]:
    """Union of an agent's directly-granted tools and all role_permissions."""
    tools = set(entry.get("tools") or [])
    for perms in (entry.get("role_permissions") or {}).values():
        tools.update(perms or [])
    return sorted(tools)


def _activity_index(tenant_id: str) -> dict:
    """Per-agent activity derived from the recent auth-event buffer.

    Returns {agent_id: {last_seen, tools:set, resources:set, events:{ev:n}}}.
    Note: the buffer is bounded (recent activity, not full history).
    """
    idx: dict[str, dict] = {}
    for e in stats.get_recent(tenant_id, limit=stats.RECENT_BUFFER_MAX):
        aid = e.get("agent_id")
        if not aid:
            continue
        a = idx.setdefault(aid, {"last_seen": 0, "tools": set(), "resources": set(), "events": {}})
        ts = e.get("ts", 0) or 0
        if ts > a["last_seen"]:
            a["last_seen"] = ts
        if e.get("tool"):
            a["tools"].add(e["tool"])
        if e.get("resource"):
            a["resources"].add(e["resource"])
        ev = e.get("event", "?")
        a["events"][ev] = a["events"].get(ev, 0) + 1
    return idx


@router.get("/agents")
async def governance_agents(request: Request):
    """Phase 1 — Agent inventory: registered + observed (shadow) agents."""
    tenant_id = get_tenant_from_api_key(request)
    registered = get_redis_data(f"agents:{tenant_id}") or {}
    unregistered = (get_redis_data(f"unregistered:{tenant_id}") or {}).get("agents", {}) or {}
    activity = _activity_index(tenant_id)

    agents = []
    for aid, entry in registered.items():
        act = activity.get(aid, {})
        agents.append({
            "agent_id": aid,
            "name": entry.get("name", aid),
            "registered": True,
            "status": entry.get("status", "active"),
            "granted_tools": _granted_tools(entry),
            "allowed_resources": entry.get("allowed_resources", []) or [],
            "require_resource_scope": bool(entry.get("require_resource_scope", False)),
            "created_at": entry.get("created_at"),
            "updated_at": entry.get("updated_at"),
            "last_seen": act.get("last_seen", 0),
            "recent_tools_used": sorted(act.get("tools", set())),
        })

    for aid, meta in unregistered.items():
        if aid in registered:
            continue
        act = activity.get(aid, {})
        agents.append({
            "agent_id": aid,
            "name": aid,
            "registered": False,        # shadow agent — seen in traffic, never registered
            "status": "unregistered",
            "granted_tools": [],
            "allowed_resources": [],
            "require_resource_scope": False,
            "first_seen": (meta or {}).get("first_seen"),
            "last_seen": act.get("last_seen", (meta or {}).get("last_seen", 0)),
            "recent_tools_used": sorted(act.get("tools", set())),
        })

    agents.sort(key=lambda a: (not a["registered"], -(a.get("last_seen") or 0)))
    return {
        "tenant_id": tenant_id,
        "count": len(agents),
        "registered_count": sum(1 for a in agents if a["registered"]),
        "shadow_count": sum(1 for a in agents if not a["registered"]),
        "agents": agents,
    }


@router.get("/agents/{agent_id}/usage")
async def governance_agent_usage(agent_id: str, request: Request):
    """Phase 2 — Used-vs-granted for one agent (least-privilege + drift)."""
    tenant_id = get_tenant_from_api_key(request)
    registered = get_redis_data(f"agents:{tenant_id}") or {}
    entry = registered.get(agent_id)
    act = _activity_index(tenant_id).get(agent_id, {})

    granted = set(_granted_tools(entry)) if entry else set()
    used = set(act.get("tools", set()))

    return {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "registered": entry is not None,
        "granted_tools": sorted(granted),
        "used_tools": sorted(used),
        "unused_grants": sorted(granted - used),        # least-privilege: candidates to remove
        "used_not_granted": sorted(used - granted),     # drift / shadow tool use — investigate
        "allowed_resources": (entry or {}).get("allowed_resources", []) or [],
        "used_resources": sorted(act.get("resources", set())),
        "activity": act.get("events", {}),
        "last_seen": act.get("last_seen", 0),
        "window": f"recent activity (last {stats.RECENT_BUFFER_MAX} auth events)",
        "note": ("Usage is derived from the runtime auth-event buffer (bounded to recent "
                 "activity), not full history. Longer-retention usage analytics is roadmap."),
    }
