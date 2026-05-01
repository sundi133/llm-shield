"""Storage operations for tenant-specific custom policies.

Custom policies are LLM-based policies defined by tenants in natural language.
Max 10 policies per tenant, stored in Redis with versioning.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from storage.tenant_store import _get_redis

logger = logging.getLogger(__name__)

# Redis key patterns
TENANT_POLICIES_KEY = "custom_policies:tenant:{tenant_id}"
POLICY_KEY = "custom_policy:{tenant_id}:{policy_id}"
POLICY_INDEX_KEY = "custom_policies:index"

MAX_POLICIES_PER_TENANT = 10


def save_custom_policy(
    tenant_id: str,
    policy_data: Dict,
    created_by: str = "system"
) -> Dict:
    """Save a new custom policy for a tenant."""
    try:
        redis = _get_redis()

        # Validate required fields
        required_fields = ["name", "description", "prompt", "action"]
        for field in required_fields:
            if field not in policy_data:
                raise ValueError(f"Missing required field: {field}")

        # Validate action
        valid_actions = ["pass", "warn", "redact", "block"]
        if policy_data["action"] not in valid_actions:
            raise ValueError(f"Invalid action. Must be one of: {valid_actions}")

        # Check tenant policy limit
        existing_policies = get_tenant_custom_policies(tenant_id, enabled_only=False)
        if len(existing_policies) >= MAX_POLICIES_PER_TENANT:
            raise ValueError(f"Maximum {MAX_POLICIES_PER_TENANT} policies per tenant exceeded")

        # Generate policy ID and set defaults
        policy_id = str(uuid.uuid4())
        now = datetime.utcnow()

        policy = {
            "policy_id": policy_id,
            "tenant_id": tenant_id,
            "name": policy_data["name"],
            "description": policy_data["description"],
            "prompt": policy_data["prompt"],
            "action": policy_data["action"],
            "enabled": policy_data.get("enabled", True),
            "confidence_threshold": policy_data.get("confidence_threshold", 0.8),
            "priority": policy_data.get("priority", 100),
            "created_at": now.isoformat(),
            "created_by": created_by,
            "updated_at": now.isoformat(),
            "updated_by": created_by,
            "version": 1
        }

        # Store individual policy
        policy_key = POLICY_KEY.format(tenant_id=tenant_id, policy_id=policy_id)
        redis.setex(policy_key, 86400 * 30, json.dumps(policy))  # 30 day TTL

        # Add to tenant's policy list
        tenant_key = TENANT_POLICIES_KEY.format(tenant_id=tenant_id)
        redis.sadd(tenant_key, policy_id)
        redis.expire(tenant_key, 86400 * 30)  # 30 day TTL

        # Update global index for monitoring
        redis.hset(POLICY_INDEX_KEY, f"{tenant_id}:{policy_id}", now.isoformat())

        logger.info(f"Created custom policy {policy_id} for tenant {tenant_id}")
        return policy

    except Exception as e:
        logger.error(f"Error saving custom policy for tenant {tenant_id}: {e}")
        raise


def get_custom_policy(tenant_id: str, policy_id: str) -> Optional[Dict]:
    """Get a specific custom policy by ID."""
    try:
        redis = _get_redis()
        policy_key = POLICY_KEY.format(tenant_id=tenant_id, policy_id=policy_id)

        policy_data = redis.get(policy_key)
        if not policy_data:
            return None

        policy = json.loads(policy_data)

        # Verify tenant ownership
        if policy.get("tenant_id") != tenant_id:
            logger.warning(f"Tenant {tenant_id} attempted to access policy {policy_id} owned by {policy.get('tenant_id')}")
            return None

        return policy

    except Exception as e:
        logger.error(f"Error retrieving custom policy {policy_id} for tenant {tenant_id}: {e}")
        return None


def get_tenant_custom_policies(tenant_id: str, enabled_only: bool = True) -> List[Dict]:
    """Get all custom policies for a tenant."""
    try:
        redis = _get_redis()
        tenant_key = TENANT_POLICIES_KEY.format(tenant_id=tenant_id)

        policy_ids = redis.smembers(tenant_key)
        if not policy_ids:
            return []

        policies = []
        for policy_id in policy_ids:
            policy = get_custom_policy(tenant_id, policy_id.decode())
            if policy:
                if not enabled_only or policy.get("enabled", True):
                    policies.append(policy)

        # Sort by priority (lower number = higher priority)
        policies.sort(key=lambda p: p.get("priority", 100))

        return policies

    except Exception as e:
        logger.error(f"Error retrieving custom policies for tenant {tenant_id}: {e}")
        return []


def update_custom_policy(
    tenant_id: str,
    policy_id: str,
    updates: Dict,
    updated_by: str = "system"
) -> Optional[Dict]:
    """Update an existing custom policy."""
    try:
        # Get existing policy
        policy = get_custom_policy(tenant_id, policy_id)
        if not policy:
            return None

        # Validate updates
        if "action" in updates:
            valid_actions = ["pass", "warn", "redact", "block"]
            if updates["action"] not in valid_actions:
                raise ValueError(f"Invalid action. Must be one of: {valid_actions}")

        # Apply updates
        policy.update(updates)
        policy["updated_at"] = datetime.utcnow().isoformat()
        policy["updated_by"] = updated_by
        policy["version"] = policy.get("version", 1) + 1

        # Save updated policy
        redis = _get_redis()
        policy_key = POLICY_KEY.format(tenant_id=tenant_id, policy_id=policy_id)
        redis.setex(policy_key, 86400 * 30, json.dumps(policy))

        logger.info(f"Updated custom policy {policy_id} for tenant {tenant_id}")
        return policy

    except Exception as e:
        logger.error(f"Error updating custom policy {policy_id} for tenant {tenant_id}: {e}")
        raise


def delete_custom_policy(tenant_id: str, policy_id: str) -> bool:
    """Delete a custom policy."""
    try:
        # Verify policy exists and belongs to tenant
        policy = get_custom_policy(tenant_id, policy_id)
        if not policy:
            return False

        redis = _get_redis()

        # Remove from tenant's policy list
        tenant_key = TENANT_POLICIES_KEY.format(tenant_id=tenant_id)
        redis.srem(tenant_key, policy_id)

        # Delete individual policy
        policy_key = POLICY_KEY.format(tenant_id=tenant_id, policy_id=policy_id)
        redis.delete(policy_key)

        # Remove from global index
        redis.hdel(POLICY_INDEX_KEY, f"{tenant_id}:{policy_id}")

        logger.info(f"Deleted custom policy {policy_id} for tenant {tenant_id}")
        return True

    except Exception as e:
        logger.error(f"Error deleting custom policy {policy_id} for tenant {tenant_id}: {e}")
        return False


def enable_custom_policy(tenant_id: str, policy_id: str) -> bool:
    """Enable a custom policy."""
    result = update_custom_policy(tenant_id, policy_id, {"enabled": True})
    return result is not None


def disable_custom_policy(tenant_id: str, policy_id: str) -> bool:
    """Disable a custom policy."""
    result = update_custom_policy(tenant_id, policy_id, {"enabled": False})
    return result is not None


def get_policy_stats(tenant_id: str) -> Dict:
    """Get statistics about tenant's custom policies."""
    try:
        policies = get_tenant_custom_policies(tenant_id, enabled_only=False)

        stats = {
            "total_policies": len(policies),
            "enabled_policies": len([p for p in policies if p.get("enabled", True)]),
            "disabled_policies": len([p for p in policies if not p.get("enabled", True)]),
            "max_allowed": MAX_POLICIES_PER_TENANT,
            "remaining_slots": MAX_POLICIES_PER_TENANT - len(policies),
            "actions": {}
        }

        # Count by action type
        for policy in policies:
            action = policy.get("action", "unknown")
            stats["actions"][action] = stats["actions"].get(action, 0) + 1

        return stats

    except Exception as e:
        logger.error(f"Error getting policy stats for tenant {tenant_id}: {e}")
        return {
            "total_policies": 0,
            "enabled_policies": 0,
            "disabled_policies": 0,
            "max_allowed": MAX_POLICIES_PER_TENANT,
            "remaining_slots": MAX_POLICIES_PER_TENANT,
            "actions": {}
        }


def validate_policy_prompt(prompt: str) -> Dict:
    """Validate that a policy prompt is well-formed."""
    try:
        validation_result = {
            "valid": True,
            "issues": [],
            "suggestions": []
        }

        # Basic validation checks
        if not prompt or not prompt.strip():
            validation_result["valid"] = False
            validation_result["issues"].append("Policy prompt cannot be empty")
            return validation_result

        if len(prompt) < 20:
            validation_result["issues"].append("Policy prompt is very short - consider adding more detail")

        if len(prompt) > 2000:
            validation_result["issues"].append("Policy prompt is very long - consider breaking into multiple policies")

        # Check for common patterns that might not work well with LLM evaluation
        problematic_patterns = [
            ("exact match", "contains exact phrases like"),
            ("regex", "uses regex patterns"),
            ("case sensitive", "requires case-sensitive matching")
        ]

        prompt_lower = prompt.lower()
        for pattern, description in problematic_patterns:
            if pattern in prompt_lower:
                validation_result["suggestions"].append(
                    f"Policy {description} - consider using more natural language descriptions"
                )

        return validation_result

    except Exception as e:
        logger.error(f"Error validating policy prompt: {e}")
        return {
            "valid": False,
            "issues": [f"Validation error: {str(e)}"],
            "suggestions": []
        }