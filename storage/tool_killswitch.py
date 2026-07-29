"""Tool Kill Switch — instantly disable tools across all agents, or on one server.

Stores disabled tools in a Redis SET per tenant for O(1) lookups.
Provides immediate security response when a tool is compromised.

Two scopes share the set, distinguished by member shape:

    delete_record                  fleet-wide  — disabled on every MCP server
    higgsfield:generate_video      one route   — disabled on that server only

Bare members keep their original fleet-wide meaning forever, so every tool
disabled before route scoping existed is unaffected. A route id cannot contain
``:`` (storage.mcp_gateway_store.is_valid_route_name), which is what makes the
qualified form unambiguous.

Redis keys:
    killswitch:tools:{tenant_id}       → SET of disabled members
    killswitch:meta:{tenant_id}:{member} → JSON metadata for one member
"""

import json
import logging
import time
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.tool_killswitch")


def _member(tool_name: str, route: Optional[str] = None) -> str:
    """Set member for a tool, scoped to one route or fleet-wide."""
    return f"{route}:{tool_name}" if route else tool_name


def _members_present(key: str, candidates: list[str]) -> bool:
    """Whether ANY candidate is in the set, in one round trip where possible.

    SMISMEMBER lands both the fleet-wide and route-scoped lookups in a single
    call, keeping the guard path at the round-trip count it had when only the
    fleet-wide check existed. It needs Redis >= 6.2, so an older server falls
    back to one SISMEMBER per candidate — degrading in latency, never in
    correctness.
    """
    r = _get_redis()
    if r:
        try:
            flags = r.smismember(key, candidates)
            return any(bool(f) for f in (flags or []))
        except Exception:
            return any(bool(r.sismember(key, c)) for c in candidates)
    existing = json.loads(_fallback_store.get(key, "[]"))
    return any(c in existing for c in candidates)


def disable_tool(tenant_id: str, tool_name: str, reason: str = "", actor: str = "",
                 route: Optional[str] = None) -> dict:
    """Disable a tool for a tenant.

    Args:
        tenant_id: Tenant identifier
        tool_name: Tool to disable
        reason: Why the tool is being disabled
        actor: Who disabled it
        route: Restrict to one MCP server. Omit for fleet-wide (the original
            behavior) — during an incident an operator usually wants to isolate
            the compromised server, not every server exposing that tool name.

    Returns:
        Dict with disable metadata.
    """
    key = f"killswitch:tools:{tenant_id}"
    member = _member(tool_name, route)
    meta_key = f"killswitch:meta:{tenant_id}:{member}"

    meta = {
        "tool_name": tool_name,
        # Recorded rather than parsed back out of the member: a tool whose own
        # name contains ':' would otherwise be misread as route-scoped.
        "route": route,
        "disabled_at": int(time.time()),
        "reason": reason,
        "actor": actor,
    }

    r = _get_redis()
    if r:
        r.sadd(key, member)
        r.set(meta_key, json.dumps(meta))
    else:
        existing = _fallback_store.get(key, "[]")
        tools = json.loads(existing)
        if member not in tools:
            tools.append(member)
        _fallback_store[key] = json.dumps(tools)
        _fallback_store[meta_key] = json.dumps(meta)

    scope = f"on route '{route}'" if route else "fleet-wide"
    logger.warning(
        f"Tool DISABLED: {tool_name} ({scope}) for tenant {tenant_id} by {actor}: {reason}")
    return meta


def enable_tool(tenant_id: str, tool_name: str, route: Optional[str] = None) -> bool:
    """Re-enable a previously disabled tool.

    Args:
        tenant_id: Tenant identifier
        tool_name: Tool to re-enable
        route: Must match the scope it was disabled at. Re-enabling on one route
            deliberately does NOT lift a fleet-wide disable — that would turn a
            narrow "unblock this server" into a silent fleet-wide unblock.

    Returns:
        True if the tool was disabled and is now enabled, False if it wasn't disabled.
    """
    key = f"killswitch:tools:{tenant_id}"
    member = _member(tool_name, route)
    meta_key = f"killswitch:meta:{tenant_id}:{member}"

    r = _get_redis()
    if r:
        removed = r.srem(key, member)
        r.delete(meta_key)
        was_disabled = removed > 0 if isinstance(removed, int) else bool(removed)
    else:
        existing = _fallback_store.get(key, "[]")
        tools = json.loads(existing)
        if member in tools:
            tools.remove(member)
            _fallback_store[key] = json.dumps(tools)
            _fallback_store.pop(meta_key, None)
            was_disabled = True
        else:
            was_disabled = False

    if was_disabled:
        scope = f"on route '{route}'" if route else "fleet-wide"
        logger.info(f"Tool ENABLED: {tool_name} ({scope}) for tenant {tenant_id}")
    return was_disabled


def is_tool_disabled(tenant_id: str, tool_name: str,
                     route: Optional[str] = None) -> bool:
    """Check if a tool is currently disabled. O(1) lookup.

    Args:
        tenant_id: Tenant identifier
        tool_name: Tool to check
        route: The MCP server the call is going to. When given, a fleet-wide
            disable AND a disable scoped to that route both block — the two are
            checked together in one round trip.

    Returns:
        True if disabled, False if enabled.
    """
    key = f"killswitch:tools:{tenant_id}"
    candidates = [tool_name]
    if route:
        candidates.append(_member(tool_name, route))
    return _members_present(key, candidates)


def list_disabled_tools(tenant_id: str) -> list[dict]:
    """List all disabled tools for a tenant with metadata.

    Returns:
        List of dicts with tool_name, route, disabled_at, reason, actor.
        ``route`` is None for a fleet-wide disable.
    """
    key = f"killswitch:tools:{tenant_id}"

    r = _get_redis()
    if r:
        members = r.smembers(key) or set()
        member_names = [m.decode() if isinstance(m, bytes) else m for m in members]
    else:
        existing = _fallback_store.get(key, "[]")
        member_names = json.loads(existing)

    results = []
    for member in sorted(member_names):
        meta_key = f"killswitch:meta:{tenant_id}:{member}"
        if r:
            meta_json = r.get(meta_key)
        else:
            meta_json = _fallback_store.get(meta_key)

        if meta_json:
            meta = json.loads(meta_json)
            # Entries written before route scoping have no 'route' key; they were
            # fleet-wide by definition.
            meta.setdefault("route", None)
            results.append(meta)
        else:
            # No metadata (expired or written out of band). Fall back to reading
            # the scope off the member. Safe because a route id cannot contain
            # ':', so a split can only mis-attribute a tool whose own name does —
            # and that case still reports the right tool_name below.
            route, sep, tool = member.partition(":")
            results.append({
                "tool_name": tool if sep else member,
                "route": route if sep else None,
                "disabled_at": 0, "reason": "", "actor": "",
            })

    return results
