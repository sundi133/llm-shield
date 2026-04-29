"""Taint store — manages sensitivity labels and data flow graphs per session.

Tracks which tool calls produced sensitive data and how that data propagates
through subsequent tool calls in the same session.

Uses StateStore for fast in-memory access and Redis for persistence.
"""

import json
import logging
import time
from typing import Optional

from storage.state_store import agentic_state
from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.taint_store")

_DEFAULT_TTL = 3600  # 1 hour session taint lifetime


def record_taint(
    session_id: str,
    tool_call_id: str,
    tool_name: str,
    sensitivity_tags: list[str],
    tenant_id: str = "",
    ttl: float = _DEFAULT_TTL,
) -> dict:
    """Record sensitivity tags for a tool call output.

    Called after tool output sanitization detects sensitive data.

    Args:
        session_id: Session identifier
        tool_call_id: Unique ID for this tool call
        tool_name: Name of the tool that produced the output
        sensitivity_tags: List of sensitivity tags (e.g., ["SSN", "PII"])
        tenant_id: Tenant identifier for Redis persistence
        ttl: Time-to-live in seconds

    Returns:
        The stored taint record.
    """
    record = {
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "sensitivity_tags": sensitivity_tags,
        "recorded_at": time.time(),
        "source": "detected",
    }

    # Store in StateStore (fast, in-memory)
    key = f"taint:{session_id}:labels:{tool_call_id}"
    agentic_state.set(key, record, ttl=ttl)

    # Also store in Redis for durability
    if tenant_id:
        redis_key = f"taint:{tenant_id}:{session_id}:labels"
        r = _get_redis()
        if r:
            try:
                r.hset(redis_key, tool_call_id, json.dumps(record))
                r.expire(redis_key, int(ttl))
            except Exception as e:
                logger.warning(f"Failed to persist taint label to Redis: {e}")
        else:
            fb_key = f"taint:{tenant_id}:{session_id}:labels"
            existing = _fallback_store.get(fb_key, "{}")
            labels = json.loads(existing)
            labels[tool_call_id] = record
            _fallback_store[fb_key] = json.dumps(labels)

    logger.debug(f"Taint recorded: session={session_id} tool_call={tool_call_id} tags={sensitivity_tags}")
    return record


def get_taint_labels(session_id: str, tool_call_id: str) -> Optional[dict]:
    """Get taint labels for a specific tool call.

    Returns:
        Taint record dict or None if no taint.
    """
    key = f"taint:{session_id}:labels:{tool_call_id}"
    return agentic_state.get(key)


def get_session_taints(session_id: str, tenant_id: str = "") -> dict[str, dict]:
    """Get all taint labels for a session.

    Returns:
        Dict mapping tool_call_id → taint record.
    """
    # Try StateStore first (covers recent taints)
    prefix = f"taint:{session_id}:labels:"
    keys = agentic_state.keys(prefix)
    results = {}
    for k in keys:
        tool_call_id = k.replace(prefix, "")
        record = agentic_state.get(k)
        if record:
            results[tool_call_id] = record

    # If empty and tenant_id provided, try Redis/fallback
    if not results and tenant_id:
        r = _get_redis()
        if r:
            try:
                redis_key = f"taint:{tenant_id}:{session_id}:labels"
                all_labels = r.hgetall(redis_key)
                for tcid, data in all_labels.items():
                    if isinstance(tcid, bytes):
                        tcid = tcid.decode()
                    if isinstance(data, bytes):
                        data = data.decode()
                    results[tcid] = json.loads(data)
            except Exception:
                pass
        else:
            fb_key = f"taint:{tenant_id}:{session_id}:labels"
            existing = _fallback_store.get(fb_key, "{}")
            results = json.loads(existing)

    return results


def record_flow_edge(
    session_id: str,
    from_tool_call_id: str,
    to_tool_call_id: str,
    propagated_tags: list[str],
    ttl: float = _DEFAULT_TTL,
) -> None:
    """Record a data flow edge: data from one tool call feeds into another.

    Args:
        session_id: Session identifier
        from_tool_call_id: Source tool call
        to_tool_call_id: Destination tool call
        propagated_tags: Tags being propagated
        ttl: Time-to-live
    """
    graph_key = f"taint:{session_id}:graph"
    graph = agentic_state.get(graph_key) or {}

    if from_tool_call_id not in graph:
        graph[from_tool_call_id] = []

    graph[from_tool_call_id].append({
        "to": to_tool_call_id,
        "tags": propagated_tags,
        "timestamp": time.time(),
    })

    agentic_state.set(graph_key, graph, ttl=ttl)


def get_taint_graph(session_id: str) -> dict:
    """Get the full taint flow graph for a session.

    Returns:
        Adjacency list: {source_tool_call_id: [{to, tags, timestamp}, ...]}
    """
    graph_key = f"taint:{session_id}:graph"
    return agentic_state.get(graph_key) or {}


def get_inherited_tags(session_id: str, input_sources: list[str]) -> list[str]:
    """Get all sensitivity tags inherited from input sources.

    Walks the taint labels for each input source and collects all tags.

    Args:
        session_id: Session identifier
        input_sources: List of tool_call_ids whose outputs feed the current tool

    Returns:
        Deduplicated list of inherited sensitivity tags.
    """
    all_tags = set()
    for source_id in input_sources:
        record = get_taint_labels(session_id, source_id)
        if record:
            all_tags.update(record.get("sensitivity_tags", []))
    return sorted(all_tags)
