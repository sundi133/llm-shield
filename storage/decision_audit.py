"""Runtime Decision Audit — logs every guardrail enforcement decision.

Unlike admin_audit (which tracks policy CRUD), this tracks runtime enforcement:
"tool X was blocked for user Y at time Z because of policy P"

Critical for SOC2 compliance and incident investigation.

Redis keys:
    decisions:{tenant_id}  → LIST of decision entries (capped at 50k)
    decisions:global       → LIST of all decisions (capped at 200k)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.decision_audit")

_MAX_ENTRIES_PER_TENANT = 50000
_MAX_GLOBAL_ENTRIES = 200000


def log_decision(
    tenant_id: str,
    action: str,
    guardrail: str,
    agent_key: str = "",
    tool_name: Optional[str] = None,
    user_role: Optional[str] = None,
    session_id: Optional[str] = None,
    reason: str = "",
    source_ip: str = "",
    metadata: Optional[dict] = None,
) -> dict:
    """Log a guardrail enforcement decision.

    Args:
        tenant_id: Tenant identifier
        action: Decision action (block, warn, pass, log)
        guardrail: Guardrail name that made the decision
        agent_key: Agent that triggered the check
        tool_name: Tool being checked (if applicable)
        user_role: Role of the user
        session_id: Session identifier
        reason: Human-readable reason for the decision
        source_ip: Source IP of the request
        metadata: Additional context (guardrail details, params, etc.)

    Returns:
        The stored decision entry.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "action": action,
        "guardrail": guardrail,
        "agent_key": agent_key,
        "tool_name": tool_name,
        "user_role": user_role,
        "session_id": session_id,
        "reason": reason,
        "source_ip": source_ip,
        "metadata": metadata or {},
    }
    entry_json = json.dumps(entry)

    r = _get_redis()
    if r:
        try:
            # Push to tenant-specific list
            tenant_key = f"decisions:{tenant_id}"
            r.lpush(tenant_key, entry_json)
            r.ltrim(tenant_key, 0, _MAX_ENTRIES_PER_TENANT - 1)

            # Push to global list
            r.lpush("decisions:global", entry_json)
            r.ltrim("decisions:global", 0, _MAX_GLOBAL_ENTRIES - 1)
        except Exception as e:
            logger.warning(f"Failed to write decision audit entry: {e}")
    else:
        # Fallback store (for dev/testing)
        tenant_key = f"decisions:{tenant_id}"
        existing = _fallback_store.get(tenant_key, "[]")
        entries = json.loads(existing)
        entries.insert(0, entry)
        entries = entries[:_MAX_ENTRIES_PER_TENANT]
        _fallback_store[tenant_key] = json.dumps(entries)

        global_entries = json.loads(_fallback_store.get("decisions:global", "[]"))
        global_entries.insert(0, entry)
        global_entries = global_entries[:_MAX_GLOBAL_ENTRIES]
        _fallback_store["decisions:global"] = json.dumps(global_entries)

    return entry


def query_decisions(
    tenant_id: Optional[str] = None,
    action: Optional[str] = None,
    guardrail: Optional[str] = None,
    agent_key: Optional[str] = None,
    tool_name: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query decision audit log with filters.

    Args:
        tenant_id: Filter by tenant (uses tenant list; None uses global)
        action: Filter by action (block, warn, pass)
        guardrail: Filter by guardrail name
        agent_key: Filter by agent key
        tool_name: Filter by tool name
        since: ISO timestamp - only entries after this time
        until: ISO timestamp - only entries before this time
        limit: Max results to return
        offset: Skip first N matching results

    Returns:
        List of matching decision entries (newest first).
    """
    key = f"decisions:{tenant_id}" if tenant_id else "decisions:global"

    r = _get_redis()
    if r:
        try:
            # Fetch extra to account for filtering
            fetch_count = (offset + limit) * 4
            raw = r.lrange(key, 0, fetch_count - 1)
        except Exception as e:
            logger.error(f"Decision audit query failed: {e}")
            return []
    else:
        raw_json = _fallback_store.get(key, "[]")
        all_entries = json.loads(raw_json)
        raw = [json.dumps(e) for e in all_entries[:((offset + limit) * 4)]]

    results = []
    skipped = 0

    for item in raw:
        if isinstance(item, bytes):
            item = item.decode()
        entry = json.loads(item) if isinstance(item, str) else item

        # Apply filters
        if action and entry.get("action") != action:
            continue
        if guardrail and entry.get("guardrail") != guardrail:
            continue
        if agent_key and entry.get("agent_key") != agent_key:
            continue
        if tool_name and entry.get("tool_name") != tool_name:
            continue
        if since and entry.get("timestamp", "") < since:
            continue
        if until and entry.get("timestamp", "") > until:
            continue

        # Handle offset
        if skipped < offset:
            skipped += 1
            continue

        results.append(entry)
        if len(results) >= limit:
            break

    return results
