"""Policy store backed by Redis for tenant-specific data protection policies.

Stores custom data protection policies, patterns, and role-based access rules.
Uses the same Redis/fallback pattern as tenant_store.

Redis keys:
    policy:{tenant_id}:{policy_id}    → JSON policy config
    policies:{tenant_id}             → SET of policy IDs for tenant
"""

import json
import logging
import time
from typing import Optional, List, Dict, Any

from storage.tenant_store import _get_redis, _cache_get, _cache_set, _cache_delete, _fallback_store

logger = logging.getLogger("votal.policy_store")


def create_policy(tenant_id: str, policy_id: str, policy_config: dict) -> dict:
    """Create a new data protection policy for a tenant.

    Args:
        tenant_id: Tenant identifier
        policy_id: Unique policy identifier within tenant
        policy_config: Policy configuration dict containing:
            - name: Display name
            - patterns: List of regex patterns with data types and sensitivity
            - roles: Role-based access control mapping
            - created_at: Timestamp

    Returns:
        The stored policy config.
    """
    policy_config.setdefault("policy_id", policy_id)
    policy_config.setdefault("tenant_id", tenant_id)
    policy_config.setdefault("created_at", int(time.time()))
    policy_config.setdefault("updated_at", int(time.time()))

    policy_json = json.dumps(policy_config)
    policy_key = f"policy:{tenant_id}:{policy_id}"
    policies_key = f"policies:{tenant_id}"

    r = _get_redis()
    if r:
        r.set(policy_key, policy_json)
        r.sadd(policies_key, policy_id)
    else:
        _fallback_store[policy_key] = policy_json
        # For fallback, simulate SET with a JSON array
        existing_set = _fallback_store.get(policies_key, "[]")
        policy_ids = json.loads(existing_set)
        if policy_id not in policy_ids:
            policy_ids.append(policy_id)
        _fallback_store[policies_key] = json.dumps(policy_ids)

    _cache_set(policy_key, policy_config)
    logger.info(f"Created policy: {tenant_id}:{policy_id}")
    return policy_config


def get_policy(tenant_id: str, policy_id: str) -> Optional[dict]:
    """Get a specific policy by tenant ID and policy ID."""
    policy_key = f"policy:{tenant_id}:{policy_id}"

    # Check cache first
    cached = _cache_get(policy_key)
    if cached:
        return cached

    r = _get_redis()
    if r:
        data = r.get(policy_key)
    else:
        data = _fallback_store.get(policy_key)

    if not data:
        return None

    policy_config = json.loads(data)
    _cache_set(policy_key, policy_config)
    return policy_config


def list_policies(tenant_id: str) -> List[dict]:
    """List all policies for a tenant."""
    policies_key = f"policies:{tenant_id}"

    r = _get_redis()
    if r:
        policy_ids = r.smembers(policies_key) or []
        policy_ids = [pid.decode() if isinstance(pid, bytes) else pid for pid in policy_ids]
    else:
        policy_ids_json = _fallback_store.get(policies_key, "[]")
        policy_ids = json.loads(policy_ids_json)

    policies = []
    for policy_id in policy_ids:
        policy = get_policy(tenant_id, policy_id)
        if policy:
            policies.append(policy)

    return policies


def update_policy(tenant_id: str, policy_id: str, updates: dict) -> Optional[dict]:
    """Update an existing policy (merge, not replace).

    Args:
        tenant_id: Tenant identifier
        policy_id: Policy to update
        updates: Fields to merge into existing config

    Returns:
        Updated policy config, or None if policy not found.
    """
    policy = get_policy(tenant_id, policy_id)
    if policy is None:
        return None

    # Merge updates into existing config
    policy.update(updates)
    policy["updated_at"] = int(time.time())

    policy_json = json.dumps(policy)
    policy_key = f"policy:{tenant_id}:{policy_id}"

    r = _get_redis()
    if r:
        r.set(policy_key, policy_json)
    else:
        _fallback_store[policy_key] = policy_json

    _cache_set(policy_key, policy)
    logger.info(f"Updated policy: {tenant_id}:{policy_id}")
    return policy


def delete_policy(tenant_id: str, policy_id: str, soft: bool = True) -> bool:
    """Delete a policy (soft delete by default).

    Args:
        tenant_id: Tenant identifier
        policy_id: Policy to delete
        soft: If True, marks deleted_at; if False, removes completely

    Returns:
        True if deleted, False if not found.
    """
    if soft:
        # Soft delete - just mark deleted_at
        updates = {"deleted_at": int(time.time())}
        result = update_policy(tenant_id, policy_id, updates)
        return result is not None
    else:
        # Hard delete - remove completely
        policy_key = f"policy:{tenant_id}:{policy_id}"
        policies_key = f"policies:{tenant_id}"

        # Check if exists
        if not get_policy(tenant_id, policy_id):
            return False

        r = _get_redis()
        if r:
            r.delete(policy_key)
            r.srem(policies_key, policy_id)
        else:
            _fallback_store.pop(policy_key, None)
            # Remove from set
            existing_set = _fallback_store.get(policies_key, "[]")
            policy_ids = json.loads(existing_set)
            if policy_id in policy_ids:
                policy_ids.remove(policy_id)
            _fallback_store[policies_key] = json.dumps(policy_ids)

        _cache_delete(policy_key)
        logger.info(f"Hard deleted policy: {tenant_id}:{policy_id}")
        return True


def get_tenant_policies(tenant_id: str, include_deleted: bool = False) -> List[dict]:
    """Get all policies for a tenant with filtering options.

    Args:
        tenant_id: Tenant identifier
        include_deleted: If False (default), excludes soft-deleted policies

    Returns:
        List of policy configs.
    """
    policies = list_policies(tenant_id)

    if not include_deleted:
        policies = [p for p in policies if not p.get("deleted_at")]

    # Sort by creation time (newest first)
    policies.sort(key=lambda p: p.get("created_at", 0), reverse=True)
    return policies


def clear_policy_cache(tenant_id: str, policy_id: str = None):
    """Clear policy cache entries.

    Args:
        tenant_id: Tenant identifier
        policy_id: Specific policy ID, or None to clear all for tenant
    """
    if policy_id:
        _cache_delete(f"policy:{tenant_id}:{policy_id}")
    else:
        # Clear all policies for tenant
        policies = list_policies(tenant_id)
        for policy in policies:
            _cache_delete(f"policy:{tenant_id}:{policy['policy_id']}")


def test_policy_against_content(policy_config: dict, content: str, user_role: str) -> dict:
    """Test a policy against sample content without storing.

    Args:
        policy_config: Policy configuration to test
        content: Sample content to test against
        user_role: Role of the user accessing the content

    Returns:
        Dict with classification results and applied actions.
    """
    import re

    classifications = []

    # Apply patterns
    for pattern_def in policy_config.get("patterns", []):
        regex = pattern_def.get("regex")
        data_type = pattern_def.get("type")
        sensitivity = pattern_def.get("sensitivity", "medium")

        if re.search(regex, content, re.IGNORECASE):
            matches = list(re.finditer(regex, content, re.IGNORECASE))
            for match in matches:
                classifications.append({
                    "data_type": data_type,
                    "sensitivity": sensitivity,
                    "match": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "pattern": regex
                })

    # Check role permissions
    policy_decisions = {}
    roles = policy_config.get("roles", {})
    user_perms = roles.get(user_role, {})

    for classification in classifications:
        data_type = classification["data_type"]
        action = user_perms.get(data_type, "block")  # Default to block

        key = f"{data_type}_{classification['start']}"
        policy_decisions[key] = {
            "action": action,
            "classification": classification
        }

    # Apply redaction
    processed_content = content
    blocked_items = []
    redacted_items = []
    final_action = "allow"

    # Sort by position (reverse order to maintain string positions)
    sorted_decisions = sorted(
        policy_decisions.items(),
        key=lambda x: x[1]["classification"]["start"],
        reverse=True
    )

    for key, decision in sorted_decisions:
        action = decision["action"]
        classification = decision["classification"]

        if action == "block":
            blocked_items.append({
                "data_type": classification["data_type"],
                "match": classification["match"]
            })
            final_action = "block"
        elif action == "redact":
            start = classification["start"]
            end = classification["end"]
            data_type = classification["data_type"]

            redaction_text = f"[{data_type.upper()}_REDACTED]"
            processed_content = processed_content[:start] + redaction_text + processed_content[end:]

            redacted_items.append({
                "data_type": classification["data_type"],
                "original": classification["match"],
                "redacted_as": redaction_text
            })

            if final_action == "allow":
                final_action = "redact"

    return {
        "final_action": final_action,
        "processed_content": processed_content if final_action != "block" else "[CONTENT BLOCKED DUE TO POLICY]",
        "classifications": classifications,
        "policy_decisions": policy_decisions,
        "blocked_items": blocked_items,
        "redacted_items": redacted_items
    }