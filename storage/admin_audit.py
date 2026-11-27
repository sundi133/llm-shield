"""Admin audit log — tracks all administrative actions for compliance.

Stores entries in Redis as a list per tenant and a global list.
Each entry records who, what, when, and the before/after state.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from storage.tenant_store import _get_redis

logger = logging.getLogger("votal.admin_audit")

_MAX_ENTRIES_PER_TENANT = 10000
_MAX_GLOBAL_ENTRIES = 100000


def log_admin_action(
    action: str,
    actor: str,
    tenant_id: Optional[str] = None,
    source_ip: str = "",
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    metadata: Optional[dict] = None,
) -> dict:
    """Record an administrative action.

    Args:
        action: The action performed (create_tenant, update_tenant, delete_tenant, etc.)
        actor: The admin user/key that performed the action
        tenant_id: Affected tenant (None for global actions)
        source_ip: Source IP of the admin request
        before: State before the change (for updates/deletes)
        after: State after the change (for creates/updates)
        metadata: Extra context (e.g., request body)

    Returns:
        The stored audit entry.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "actor": actor,
        "tenant_id": tenant_id,
        "source_ip": source_ip,
        "before": before,
        "after": after,
        "metadata": metadata or {},
    }
    entry_json = json.dumps(entry)

    r = _get_redis()
    if r:
        try:
            # Push to global audit list
            r.lpush("admin_audit:global", entry_json)
            r.ltrim("admin_audit:global", 0, _MAX_GLOBAL_ENTRIES - 1)

            # Push to per-tenant list if applicable
            if tenant_id:
                tenant_key = f"admin_audit:tenant:{tenant_id}"
                r.lpush(tenant_key, entry_json)
                r.ltrim(tenant_key, 0, _MAX_ENTRIES_PER_TENANT - 1)
        except Exception as e:
            logger.warning(f"Failed to write admin audit entry: {e}")

    # Tamper-evident chain (opt-in, off-thread so callers are never blocked).
    try:
        from storage import audit_chain
        audit_chain.enqueue(
            f"admin_audit:{tenant_id}" if tenant_id else "admin_audit:global", entry
        )
    except Exception:
        pass

    logger.info(f"Admin action: {action} by {actor} on tenant={tenant_id}")
    return entry


def query_admin_audit(
    tenant_id: Optional[str] = None,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query admin audit log with optional filters."""
    r = _get_redis()
    if not r:
        return []

    try:
        key = f"admin_audit:tenant:{tenant_id}" if tenant_id else "admin_audit:global"
        raw = r.lrange(key, offset, offset + limit * 4)  # fetch extra for filtering

        results = []
        for item in raw:
            entry = json.loads(item)
            if action and entry.get("action") != action:
                continue
            if actor and entry.get("actor") != actor:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results
    except Exception as e:
        logger.error(f"Admin audit query failed: {e}")
        return []


def guardrail_states(config: Optional[dict]) -> dict:
    """{stage: {guardrail: {enabled, action[, enabled_policies]}}} for the
    audit. Names alone could not answer "was it switched on?": a save that
    turned custom_policy_input on or off logged identical before/after lists."""
    out: dict = {}
    for stage in ("input_guardrails", "output_guardrails"):
        states = {}
        for name, g in ((config or {}).get(stage) or {}).items():
            if not isinstance(g, dict):
                continue
            st = {"enabled": bool(g.get("enabled", True)), "action": g.get("action")}
            policies = (g.get("settings") or {}).get("policies")
            if isinstance(policies, list):
                st["enabled_policies"] = sum(1 for p in policies
                                             if isinstance(p, dict) and p.get("enabled", True))
            states[name] = st
        out[stage] = states
    return out


def guardrail_changes(before: dict, after: dict) -> list:
    """What a save changed: added, removed, or a different enabled / action /
    enabled-policy count, per guardrail."""
    changes = []
    for stage in ("input_guardrails", "output_guardrails"):
        b, a = before.get(stage) or {}, after.get(stage) or {}
        for name in sorted(set(b) | set(a)):
            if name not in a:
                changes.append({"stage": stage, "guardrail": name, "change": "removed"})
            elif name not in b:
                changes.append({"stage": stage, "guardrail": name, "change": "added", **a[name]})
            elif a[name] != b[name]:
                changes.append({"stage": stage, "guardrail": name, "change": "updated",
                                "before": b[name], "after": a[name]})
    return changes

def guardrail_audit(before_config: Optional[dict], after_config: Optional[dict]) -> dict:
    """Audit metadata for a policy save: each guardrail's state before and
    after, and what changed. Merge into ``metadata``."""
    b, a = guardrail_states(before_config), guardrail_states(after_config)
    return {"guardrails_before": b, "guardrails_after": a, "changes": guardrail_changes(b, a)}
