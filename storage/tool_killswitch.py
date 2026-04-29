"""Tool Kill Switch — instantly disable tools globally across all agents.

Stores disabled tools in a Redis SET per tenant for O(1) lookups.
Provides immediate security response when a tool is compromised.

Redis keys:
    killswitch:tools:{tenant_id}  → SET of disabled tool names
"""

import json
import logging
import time
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.tool_killswitch")


def disable_tool(tenant_id: str, tool_name: str, reason: str = "", actor: str = "") -> dict:
    """Disable a tool globally for a tenant.

    Args:
        tenant_id: Tenant identifier
        tool_name: Tool to disable
        reason: Why the tool is being disabled
        actor: Who disabled it

    Returns:
        Dict with disable metadata.
    """
    key = f"killswitch:tools:{tenant_id}"
    meta_key = f"killswitch:meta:{tenant_id}:{tool_name}"

    meta = {
        "tool_name": tool_name,
        "disabled_at": int(time.time()),
        "reason": reason,
        "actor": actor,
    }

    r = _get_redis()
    if r:
        r.sadd(key, tool_name)
        r.set(meta_key, json.dumps(meta))
    else:
        existing = _fallback_store.get(key, "[]")
        tools = json.loads(existing)
        if tool_name not in tools:
            tools.append(tool_name)
        _fallback_store[key] = json.dumps(tools)
        _fallback_store[meta_key] = json.dumps(meta)

    logger.warning(f"Tool DISABLED: {tool_name} for tenant {tenant_id} by {actor}: {reason}")
    return meta


def enable_tool(tenant_id: str, tool_name: str) -> bool:
    """Re-enable a previously disabled tool.

    Args:
        tenant_id: Tenant identifier
        tool_name: Tool to re-enable

    Returns:
        True if the tool was disabled and is now enabled, False if it wasn't disabled.
    """
    key = f"killswitch:tools:{tenant_id}"
    meta_key = f"killswitch:meta:{tenant_id}:{tool_name}"

    r = _get_redis()
    if r:
        removed = r.srem(key, tool_name)
        r.delete(meta_key)
        was_disabled = removed > 0 if isinstance(removed, int) else bool(removed)
    else:
        existing = _fallback_store.get(key, "[]")
        tools = json.loads(existing)
        if tool_name in tools:
            tools.remove(tool_name)
            _fallback_store[key] = json.dumps(tools)
            _fallback_store.pop(meta_key, None)
            was_disabled = True
        else:
            was_disabled = False

    if was_disabled:
        logger.info(f"Tool ENABLED: {tool_name} for tenant {tenant_id}")
    return was_disabled


def is_tool_disabled(tenant_id: str, tool_name: str) -> bool:
    """Check if a tool is currently disabled. O(1) lookup.

    Args:
        tenant_id: Tenant identifier
        tool_name: Tool to check

    Returns:
        True if disabled, False if enabled.
    """
    key = f"killswitch:tools:{tenant_id}"

    r = _get_redis()
    if r:
        return bool(r.sismember(key, tool_name))
    else:
        existing = _fallback_store.get(key, "[]")
        tools = json.loads(existing)
        return tool_name in tools


def list_disabled_tools(tenant_id: str) -> list[dict]:
    """List all disabled tools for a tenant with metadata.

    Returns:
        List of dicts with tool_name, disabled_at, reason, actor.
    """
    key = f"killswitch:tools:{tenant_id}"

    r = _get_redis()
    if r:
        members = r.smembers(key) or set()
        tool_names = [m.decode() if isinstance(m, bytes) else m for m in members]
    else:
        existing = _fallback_store.get(key, "[]")
        tool_names = json.loads(existing)

    results = []
    for tool_name in sorted(tool_names):
        meta_key = f"killswitch:meta:{tenant_id}:{tool_name}"
        if r:
            meta_json = r.get(meta_key)
        else:
            meta_json = _fallback_store.get(meta_key)

        if meta_json:
            results.append(json.loads(meta_json))
        else:
            results.append({"tool_name": tool_name, "disabled_at": 0, "reason": "", "actor": ""})

    return results
