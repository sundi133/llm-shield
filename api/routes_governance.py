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

import secrets
import time

from fastapi import APIRouter, HTTPException, Request

from api.routes_agents_registry import get_tenant_from_api_key, get_redis_data, _save_agents
from storage import agent_auth_stats as stats
from storage.tenant_store import kv_get, kv_set

router = APIRouter(prefix="/v1/governance", tags=["governance"])

_MAX_NAME_LEN = 200


def _rev_index_key(tenant_id: str) -> str:
    return f"governance:reviews:{tenant_id}"


def _rev_key(tenant_id: str, campaign_id: str) -> str:
    return f"governance:reviews:{tenant_id}:{campaign_id}"


def _with_progress(c: dict) -> dict:
    """Annotate a campaign with decided/total (excluding informational drift rows)."""
    total = decided = 0
    for it in c.get("items", []):
        for ti in it.get("tools", []):
            if ti.get("recommendation") == "investigate":
                continue
            total += 1
            if ti.get("decision", "pending") != "pending":
                decided += 1
    out = dict(c)
    out["progress"] = {"decided": decided, "total": total}
    return out


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
            # Metadata only. A reviewer looking at 14 granted tools needs
            # somebody to ask; without this the campaign rubber-stamps.
            "owner": entry.get("owner", "") or "",
            "owner_contact": entry.get("owner_contact", "") or "",
            # [] means "runs anywhere", which is the pre-existing behaviour and
            # worth seeing at a glance once SHIELD_ENVIRONMENT is set.
            "environments": entry.get("environments", []) or [],
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


@router.get("/agents/unowned")
async def governance_unowned_agents(request: Request):
    """Registered agents with nobody accountable for them.

    The question that drives adoption of the owner field: "what in our estate
    has no owner". Shadow agents are excluded — they are unregistered by
    definition, and /agents already reports them separately.

    Registered here on purpose BEFORE /agents/{agent_id}/usage. The two do not
    actually collide (different segment counts), but keeping the literal route
    above the parameterised one is the habit that prevents the version of this
    that does.
    """
    tenant_id = get_tenant_from_api_key(request)
    registered = get_redis_data(f"agents:{tenant_id}") or {}

    unowned = [
        {"agent_id": aid,
         "name": (entry or {}).get("name", aid),
         "status": (entry or {}).get("status", "active"),
         "granted_tools": _granted_tools(entry or {}),
         "created_at": (entry or {}).get("created_at")}
        for aid, entry in registered.items()
        if not str((entry or {}).get("owner", "") or "").strip()
    ]
    unowned.sort(key=lambda a: len(a["granted_tools"]), reverse=True)

    return {
        "tenant_id": tenant_id,
        "unowned_count": len(unowned),
        "registered_count": len(registered),
        "agents": unowned,
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


# ── Phase 3 — access-review / certification campaigns ────────────────────
#
# Read/write on the portal path only (registry KV). The guard path
# (cap/mint, tools/call) is never touched, so guarded traffic has no added
# latency. Closing a campaign mutates the agent registry exactly as a manual
# agent edit does; cap-mint/RBAC read the registry, so revokes take effect on
# the next mint/check (live caps expire on their own, ≤60s).


def _build_items(tenant_id: str) -> list[dict]:
    """Snapshot current entitlements + recommendations (from used-vs-granted)."""
    registered = get_redis_data(f"agents:{tenant_id}") or {}
    activity = _activity_index(tenant_id)
    items: list[dict] = []
    for aid, entry in registered.items():
        granted = _granted_tools(entry)
        used = activity.get(aid, {}).get("tools", set())
        tools = [{
            "tool": t,
            # "review" (not "revoke") for no recent activity: a bounded usage
            # window means "not seen lately", not "provably dead" — surface it
            # for human review rather than overstating confidence. (A hard
            # "revoke" recommendation is reserved for unused-over-a-real-window,
            # which needs longer-retention usage — roadmap.)
            "recommendation": "review" if t not in used else "keep",
            "decision": "pending", "reviewer": None, "decided_at": None, "note": None,
        } for t in granted]
        for t in sorted(used - set(granted)):  # drift: used but not granted — informational
            tools.append({
                "tool": t, "recommendation": "investigate", "decision": "pending",
                "reviewer": None, "decided_at": None, "note": "used but not granted",
            })
        items.append({
            "agent_id": aid, "registered": True,
            "snapshot_tools": granted,
            "snapshot_resources": entry.get("allowed_resources", []) or [],
            "tools": tools,
        })
    return items


@router.post("/reviews")
async def create_review(request: Request):
    """Create an access-review campaign, pre-populated with recommendations."""
    tenant_id = get_tenant_from_api_key(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    name = (body.get("name") or "Access review").strip()[:_MAX_NAME_LEN]
    created_by = (body.get("reviewer") or request.headers.get("x-user-role") or "tenant").strip()[:128]
    now = int(time.time())
    campaign = {
        "campaign_id": f"rev-{now}-{secrets.token_hex(3)}",
        "name": name, "created_at": now, "created_by": created_by,
        "due_at": body.get("due_at"), "status": "open",
        "items": _build_items(tenant_id),
    }
    kv_set(_rev_key(tenant_id, campaign["campaign_id"]), campaign)
    idx = kv_get(_rev_index_key(tenant_id)) or {"campaigns": []}
    idx.setdefault("campaigns", []).append({
        "campaign_id": campaign["campaign_id"], "name": name, "status": "open",
        "created_at": now, "due_at": campaign["due_at"],
    })
    kv_set(_rev_index_key(tenant_id), idx)
    return {"campaign": _with_progress(campaign)}


@router.get("/reviews")
async def list_reviews(request: Request):
    tenant_id = get_tenant_from_api_key(request)
    idx = kv_get(_rev_index_key(tenant_id)) or {"campaigns": []}
    return {"tenant_id": tenant_id, "campaigns": idx.get("campaigns", [])}


@router.get("/reviews/{campaign_id}")
async def get_review(campaign_id: str, request: Request):
    tenant_id = get_tenant_from_api_key(request)
    campaign = kv_get(_rev_key(tenant_id, campaign_id))
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    return {"campaign": _with_progress(campaign)}


@router.post("/reviews/{campaign_id}/decisions")
async def submit_decisions(campaign_id: str, request: Request):
    """Record keep/revoke decisions: body {"decisions":[{agent_id,tool,decision,note}]}."""
    tenant_id = get_tenant_from_api_key(request)
    campaign = kv_get(_rev_key(tenant_id, campaign_id))
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    if campaign.get("status") != "open":
        raise HTTPException(status_code=409, detail="campaign is closed")
    try:
        body = await request.json()
    except Exception:
        body = {}
    reviewer = (body.get("reviewer") or request.headers.get("x-user-role") or "tenant").strip()[:128]
    dmap = {}
    for d in body.get("decisions", []) or []:
        if d.get("decision") in ("keep", "revoke"):
            dmap[(d.get("agent_id"), d.get("tool"))] = d
    now = int(time.time())
    for it in campaign["items"]:
        for ti in it["tools"]:
            d = dmap.get((it["agent_id"], ti["tool"]))
            if d:
                ti["decision"] = d["decision"]
                ti["reviewer"] = reviewer
                ti["decided_at"] = now
                ti["note"] = (d.get("note") or "")[:_MAX_NAME_LEN]
    kv_set(_rev_key(tenant_id, campaign_id), campaign)
    return {"campaign": _with_progress(campaign)}


@router.post("/reviews/{campaign_id}/close")
async def close_review(campaign_id: str, request: Request):
    """Close the campaign and APPLY revoke decisions to the registry (idempotent)."""
    tenant_id = get_tenant_from_api_key(request)
    campaign = kv_get(_rev_key(tenant_id, campaign_id))
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    if campaign.get("status") == "closed":
        return {"campaign": _with_progress(campaign),
                "applied_actions": campaign.get("applied_actions", []), "already_closed": True}

    agents = get_redis_data(f"agents:{tenant_id}") or {}
    applied: list[dict] = []
    now = int(time.time())
    for it in campaign["items"]:
        entry = agents.get(it["agent_id"])
        for ti in it["tools"]:
            if ti.get("decision") != "revoke" or ti.get("recommendation") == "investigate":
                continue
            tool = ti["tool"]
            if entry is None:
                applied.append({"agent_id": it["agent_id"], "tool": tool, "action": "skipped",
                                "reason": "agent no longer exists"})
                continue
            removed = False
            if tool in (entry.get("tools") or []):
                entry["tools"] = [t for t in entry["tools"] if t != tool]
                removed = True
            for role, perms in (entry.get("role_permissions") or {}).items():
                if tool in (perms or []):
                    entry["role_permissions"][role] = [t for t in perms if t != tool]
                    removed = True
            entry["updated_at"] = now
            applied.append({"agent_id": it["agent_id"], "tool": tool,
                            "action": "revoked" if removed else "skipped",
                            "reason": None if removed else "grant already absent"})
    _save_agents(tenant_id, agents)

    campaign["status"] = "closed"
    campaign["closed_at"] = now
    campaign["applied_actions"] = applied
    kv_set(_rev_key(tenant_id, campaign_id), campaign)
    idx = kv_get(_rev_index_key(tenant_id)) or {"campaigns": []}
    for c in idx.get("campaigns", []):
        if c.get("campaign_id") == campaign_id:
            c["status"] = "closed"
    kv_set(_rev_index_key(tenant_id), idx)
    return {"campaign": _with_progress(campaign), "applied_actions": applied}
