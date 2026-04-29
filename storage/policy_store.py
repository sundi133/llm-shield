"""Policy store backed by Redis for tenant-specific policies.

Stores:
- Data protection policies (PII patterns, role-based access)
- Agent/tool policies (tool registration, role-based tool access, data sanitization)
- Tool call validation rules and LLM validation settings

Uses the same Redis/fallback pattern as tenant_store.

Redis keys:
    policy:{tenant_id}:{policy_id}    → JSON policy config
    policies:{tenant_id}             → SET of policy IDs for tenant
    agents:{tenant_id}               → JSON agent registry config
    tool_policies:{tenant_id}        → JSON tool-specific policies
"""

import json
import logging
import time
from typing import Optional, List, Dict, Any

from storage.tenant_store import _get_redis, _cache_get, _cache_set, _cache_delete, _fallback_store

logger = logging.getLogger("votal.policy_store")


_MAX_VERSIONS = 50  # maximum version history per policy


def _save_policy_version(tenant_id: str, policy_id: str, policy_snapshot: dict) -> int:
    """Save a policy snapshot as a version entry.

    Args:
        tenant_id: Tenant identifier
        policy_id: Policy identifier
        policy_snapshot: Full policy state to snapshot

    Returns:
        The version number assigned.
    """
    versions_key = f"policy_versions:{tenant_id}:{policy_id}"

    # Determine version number
    r = _get_redis()
    if r:
        current_len = r.llen(versions_key) or 0
    else:
        existing = _fallback_store.get(versions_key, "[]")
        current_len = len(json.loads(existing))

    version_number = current_len + 1
    version_entry = {
        "version": version_number,
        "snapshot": policy_snapshot,
        "versioned_at": int(time.time()),
    }
    version_json = json.dumps(version_entry)

    if r:
        r.rpush(versions_key, version_json)
        # Cap at max versions (remove oldest)
        excess = r.llen(versions_key) - _MAX_VERSIONS
        if excess > 0:
            for _ in range(excess):
                r.lpop(versions_key)
    else:
        existing = _fallback_store.get(versions_key, "[]")
        versions = json.loads(existing)
        versions.append(version_entry)
        if len(versions) > _MAX_VERSIONS:
            versions = versions[-_MAX_VERSIONS:]
        _fallback_store[versions_key] = json.dumps(versions)

    return version_number


def list_policy_versions(tenant_id: str, policy_id: str, limit: int = 20) -> list[dict]:
    """List version history for a policy (newest first).

    Args:
        tenant_id: Tenant identifier
        policy_id: Policy identifier
        limit: Max versions to return

    Returns:
        List of version entries with version number, snapshot, and timestamp.
    """
    versions_key = f"policy_versions:{tenant_id}:{policy_id}"

    r = _get_redis()
    if r:
        raw = r.lrange(versions_key, 0, -1) or []
        versions = []
        for item in raw:
            if isinstance(item, bytes):
                item = item.decode()
            versions.append(json.loads(item))
    else:
        existing = _fallback_store.get(versions_key, "[]")
        versions = json.loads(existing)

    # Return newest first, limited
    versions.reverse()
    return versions[:limit]


def get_policy_version(tenant_id: str, policy_id: str, version: int) -> Optional[dict]:
    """Get a specific version snapshot.

    Args:
        tenant_id: Tenant identifier
        policy_id: Policy identifier
        version: Version number (1-based)

    Returns:
        Version entry dict or None.
    """
    versions = list_policy_versions(tenant_id, policy_id, limit=_MAX_VERSIONS)
    for v in versions:
        if v.get("version") == version:
            return v
    return None


def rollback_policy(tenant_id: str, policy_id: str, version: int) -> Optional[dict]:
    """Rollback a policy to a previous version.

    Creates a new version entry for the rollback action, then restores the old state.

    Args:
        tenant_id: Tenant identifier
        policy_id: Policy identifier
        version: Version number to rollback to

    Returns:
        The restored policy config, or None if version not found.
    """
    target_version = get_policy_version(tenant_id, policy_id, version)
    if not target_version:
        return None

    snapshot = target_version["snapshot"]

    # Save current state as a version before rollback
    current = get_policy(tenant_id, policy_id)
    if current:
        _save_policy_version(tenant_id, policy_id, current)

    # Restore the snapshot
    snapshot["updated_at"] = int(time.time())
    snapshot["rolled_back_from_version"] = version

    policy_json = json.dumps(snapshot)
    policy_key = f"policy:{tenant_id}:{policy_id}"

    r = _get_redis()
    if r:
        r.set(policy_key, policy_json)
    else:
        _fallback_store[policy_key] = policy_json

    _cache_set(policy_key, snapshot)
    logger.info(f"Rolled back policy {tenant_id}:{policy_id} to version {version}")
    return snapshot


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

    # Save initial version
    _save_policy_version(tenant_id, policy_id, policy_config)

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

    # Save current state as a version before update
    _save_policy_version(tenant_id, policy_id, dict(policy))

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


# ============================================================================
# Agent and Tool Policy Management
# ============================================================================

def register_agent(tenant_id: str, agent_config: dict) -> dict:
    """Register an agent with its available tools and role-based access.

    Args:
        tenant_id: Tenant identifier
        agent_config: Agent configuration dict containing:
            - agent_id: Unique agent identifier
            - name: Display name
            - description: Agent description
            - tools: List of tool names this agent can use
            - role_permissions: Dict mapping roles to allowed tools

    Returns:
        The stored agent config.
    """
    agent_config.setdefault("created_at", int(time.time()))
    agent_config.setdefault("updated_at", int(time.time()))

    agents_key = f"agents:{tenant_id}"

    r = _get_redis()
    if r:
        # Get existing agents or create new dict
        existing = r.get(agents_key)
        agents = json.loads(existing) if existing else {}

        # Add/update agent
        agents[agent_config["agent_id"]] = agent_config

        # Store back
        r.set(agents_key, json.dumps(agents))
    else:
        existing = _fallback_store.get(agents_key)
        agents = json.loads(existing) if existing else {}
        agents[agent_config["agent_id"]] = agent_config
        _fallback_store[agents_key] = json.dumps(agents)

    logger.info(f"Registered agent {agent_config['agent_id']} for tenant {tenant_id}")
    return agent_config


def get_agent_registry(tenant_id: str) -> dict:
    """Get all registered agents for a tenant."""
    agents_key = f"agents:{tenant_id}"

    r = _get_redis()
    if r:
        data = r.get(agents_key)
    else:
        data = _fallback_store.get(agents_key)

    return json.loads(data) if data else {}


def set_tool_policies(tenant_id: str, tool_policies: dict) -> dict:
    """Set tool-specific policies for data sanitization and LLM validation.

    Args:
        tenant_id: Tenant identifier
        tool_policies: Dict mapping tool names to policy configs:
            {
                "patient_lookup": {
                    "data_sanitization": {
                        "redact_ssn": True,
                        "mask_phone": True,
                        "patterns": [...]
                    },
                    "llm_validation": {
                        "enabled": True,
                        "prompt": "Validate if this request is appropriate for {user_role}",
                        "confidence_threshold": 0.7
                    },
                    "role_restrictions": {
                        "admin": "allow",
                        "member": "allow",
                        "patient": "block"
                    }
                }
            }

    Returns:
        The stored tool policies.
    """
    tool_policies["updated_at"] = int(time.time())

    policies_key = f"tool_policies:{tenant_id}"

    r = _get_redis()
    if r:
        r.set(policies_key, json.dumps(tool_policies))
    else:
        _fallback_store[policies_key] = json.dumps(tool_policies)

    logger.info(f"Updated tool policies for tenant {tenant_id}")
    return tool_policies


def get_tool_policies(tenant_id: str) -> dict:
    """Get all tool-specific policies for a tenant."""
    policies_key = f"tool_policies:{tenant_id}"

    r = _get_redis()
    if r:
        data = r.get(policies_key)
    else:
        data = _fallback_store.get(policies_key)

    return json.loads(data) if data else {}


def check_tool_authorization(tenant_id: str, agent_id: str, tool_name: str, user_role: str) -> dict:
    """Check if a user role is authorized to use a specific tool via an agent.

    Args:
        tenant_id: Tenant identifier
        agent_id: Agent identifier
        tool_name: Tool name
        user_role: User's role (admin, member, patient, etc.)

    Returns:
        {
            "allowed": bool,
            "reason": str,
            "agent_config": dict,
            "tool_policy": dict
        }
    """
    # Get agent registry
    agents = get_agent_registry(tenant_id)
    if agent_id not in agents:
        return {
            "allowed": False,
            "reason": f"Agent {agent_id} not registered for tenant {tenant_id}",
            "agent_config": None,
            "tool_policy": None
        }

    agent_config = agents[agent_id]

    # Check if agent has access to this tool
    if tool_name not in agent_config.get("tools", []):
        return {
            "allowed": False,
            "reason": f"Tool {tool_name} not available for agent {agent_id}",
            "agent_config": agent_config,
            "tool_policy": None
        }

    # Check role-based permissions for agent
    role_permissions = agent_config.get("role_permissions", {})
    allowed_tools = role_permissions.get(user_role, [])

    if tool_name not in allowed_tools:
        return {
            "allowed": False,
            "reason": f"Role {user_role} not authorized for tool {tool_name}",
            "agent_config": agent_config,
            "tool_policy": None
        }

    # Get tool-specific policies
    tool_policies = get_tool_policies(tenant_id)
    tool_policy = tool_policies.get(tool_name, {})

    # Check tool-level role restrictions
    role_restrictions = tool_policy.get("role_restrictions", {})
    tool_action = role_restrictions.get(user_role, "allow")

    if tool_action == "block":
        return {
            "allowed": False,
            "reason": f"Tool policy blocks {user_role} from using {tool_name}",
            "agent_config": agent_config,
            "tool_policy": tool_policy
        }

    return {
        "allowed": True,
        "reason": "Authorized",
        "agent_config": agent_config,
        "tool_policy": tool_policy
    }