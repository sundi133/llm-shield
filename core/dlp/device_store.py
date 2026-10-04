"""Storage for the tenant's device DLP policy (docs/specs/device-dlp-agent.md §5.1).

  dlp_policy:{tenant_id}   one JSON value {policy, updated_at, updated_by}, no TTL

Reads validate again, so a hand-edited or corrupt record is reported, never
shipped to laptops. Through storage.tenant_store.kv_get/kv_set, which fall back
to memory without Redis (dev and tests).
"""

from __future__ import annotations

import time
from typing import Optional

from core.dlp.device_policy import default_policy, validate_policy


def _key(tenant_id: str) -> str:
    return f"dlp_policy:{tenant_id}"


def get_record(tenant_id: str) -> Optional[dict]:
    """{policy, updated_at, updated_by} as stored, or None. Raises PolicyError
    if the stored policy no longer validates."""
    from storage.tenant_store import kv_get
    rec = kv_get(_key(tenant_id))
    if not isinstance(rec, dict):
        return None
    return {**rec, "policy": validate_policy(rec.get("policy"))}


def get_policy(tenant_id: str) -> dict:
    """The tenant's policy, or the defaults when none has been saved."""
    rec = get_record(tenant_id)
    return rec["policy"] if rec else default_policy()


def save_policy(tenant_id: str, policy: dict, actor: str = "") -> dict:
    from storage.tenant_store import kv_set
    normalized = validate_policy(policy)
    kv_set(_key(tenant_id), {"policy": normalized, "updated_at": int(time.time()),
                             "updated_by": actor[:200]})
    from core.dlp import agent_hooks, agent_os_events
    agent_hooks.invalidate(tenant_id)
    agent_os_events.invalidate(tenant_id)
    return normalized
