"""Storage operations for tenant-specific custom policies.

Custom policies are LLM-based policies defined by tenants in natural language.
Stored within the existing tenant guardrail configuration structure.
Max 10 policies per tenant per stage (input/output).
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from storage.tenant_store import get_tenant, set_tenant_policies

logger = logging.getLogger(__name__)

MAX_POLICIES_PER_STAGE = 10


def _persist_policy_stage(tenant_id: str, tenant_config: Dict, stage: str) -> None:
    """Persist only the guardrail stage touched by a custom policy change."""
    if stage == "input":
        set_tenant_policies(
            tenant_id,
            input_guardrails=tenant_config.get("input_guardrails", {}),
        )
    elif stage == "output":
        set_tenant_policies(
            tenant_id,
            output_guardrails=tenant_config.get("output_guardrails", {}),
        )
    else:
        raise ValueError("stage must be 'input' or 'output'")


def _ensure_custom_policy_guardrail(tenant_config: Dict, stage: str) -> Dict:
    """Ensure custom policy guardrail exists in tenant config."""
    guardrail_key = f"custom_policy_{stage}"
    stage_key = f"{stage}_guardrails"

    if stage_key not in tenant_config:
        tenant_config[stage_key] = {}

    if guardrail_key not in tenant_config[stage_key]:
        tenant_config[stage_key][guardrail_key] = {
            "enabled": True,
            "action": "pass",  # Custom policies manage their own actions
            "settings": {
                "policies": []
            }
        }

    return tenant_config


def save_custom_policy(
    tenant_id: str,
    policy_data: Dict,
    created_by: str = "system",
    stage: str = "input"
) -> Dict:
    """Save a new custom policy for a tenant."""
    try:
        # Validate required fields
        required_fields = ["name", "description", "prompt", "action"]
        for field in required_fields:
            if field not in policy_data:
                raise ValueError(f"Missing required field: {field}")

        # Validate action
        valid_actions = ["pass", "warn", "redact", "block"]
        if policy_data["action"] not in valid_actions:
            raise ValueError(f"Invalid action. Must be one of: {valid_actions}")

        # Get tenant config
        tenant_config = get_tenant(tenant_id)
        if not tenant_config:
            raise ValueError(f"Tenant {tenant_id} not found")

        # Ensure custom policy guardrail exists
        tenant_config = _ensure_custom_policy_guardrail(tenant_config, stage)

        # Get existing policies
        guardrail_key = f"custom_policy_{stage}"
        existing_policies = tenant_config[f"{stage}_guardrails"][guardrail_key]["settings"]["policies"]

        # Check policy limit
        if len(existing_policies) >= MAX_POLICIES_PER_STAGE:
            raise ValueError(f"Maximum {MAX_POLICIES_PER_STAGE} policies per {stage} stage exceeded")

        # Generate policy ID and set defaults
        policy_id = str(uuid.uuid4())
        now = datetime.utcnow()

        policy = {
            "policy_id": policy_id,
            "name": policy_data["name"],
            "description": policy_data["description"],
            "prompt": policy_data["prompt"],
            "action": policy_data["action"],
            "stage": stage,
            "enabled": policy_data.get("enabled", True),
            "confidence_threshold": policy_data.get("confidence_threshold", 0.8),
            "priority": policy_data.get("priority", 100),
            "created_at": now.isoformat(),
            "created_by": created_by,
            "updated_at": now.isoformat(),
            "updated_by": created_by,
            "version": 1
        }

        # Add policy to the list
        existing_policies.append(policy)

        # Sort by priority (lower number = higher priority)
        existing_policies.sort(key=lambda p: p.get("priority", 100))

        # Save back to tenant config
        _persist_policy_stage(tenant_id, tenant_config, stage)

        logger.info(f"Created custom {stage} policy {policy_id} for tenant {tenant_id}")
        return policy

    except Exception as e:
        logger.error(f"Error saving custom policy for tenant {tenant_id}: {e}")
        raise


def get_custom_policy(tenant_id: str, policy_id: str, stage: Optional[str] = None) -> Optional[Dict]:
    """Get a specific custom policy by ID."""
    try:
        tenant_config = get_tenant(tenant_id)
        if not tenant_config:
            return None

        # Search both stages if stage not specified
        stages_to_search = [stage] if stage else ["input", "output"]

        for search_stage in stages_to_search:
            guardrail_key = f"custom_policy_{search_stage}"
            stage_key = f"{search_stage}_guardrails"

            if (stage_key in tenant_config and
                guardrail_key in tenant_config[stage_key] and
                "settings" in tenant_config[stage_key][guardrail_key]):

                policies = tenant_config[stage_key][guardrail_key]["settings"].get("policies", [])
                for policy in policies:
                    if policy.get("policy_id") == policy_id:
                        return policy

        return None

    except Exception as e:
        logger.error(f"Error retrieving custom policy {policy_id} for tenant {tenant_id}: {e}")
        return None


def get_tenant_custom_policies(tenant_id: str, enabled_only: bool = True, stage: Optional[str] = None) -> List[Dict]:
    """Get all custom policies for a tenant."""
    try:
        tenant_config = get_tenant(tenant_id)
        if not tenant_config:
            return []

        all_policies = []
        stages_to_check = [stage] if stage else ["input", "output"]

        for check_stage in stages_to_check:
            guardrail_key = f"custom_policy_{check_stage}"
            stage_key = f"{check_stage}_guardrails"

            if (stage_key in tenant_config and
                guardrail_key in tenant_config[stage_key] and
                "settings" in tenant_config[stage_key][guardrail_key]):

                policies = tenant_config[stage_key][guardrail_key]["settings"].get("policies", [])
                for policy in policies:
                    if not enabled_only or policy.get("enabled", True):
                        # Ensure stage is set
                        if "stage" not in policy:
                            policy["stage"] = check_stage
                        all_policies.append(policy)

        # Sort by priority (lower number = higher priority)
        all_policies.sort(key=lambda p: p.get("priority", 100))

        return all_policies

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
        # Get tenant config
        tenant_config = get_tenant(tenant_id)
        if not tenant_config:
            return None

        # Find the policy and its stage
        policy_found = False
        target_stage = None

        for stage in ["input", "output"]:
            guardrail_key = f"custom_policy_{stage}"
            stage_key = f"{stage}_guardrails"

            if (stage_key in tenant_config and
                guardrail_key in tenant_config[stage_key] and
                "settings" in tenant_config[stage_key][guardrail_key]):

                policies = tenant_config[stage_key][guardrail_key]["settings"]["policies"]
                for i, policy in enumerate(policies):
                    if policy.get("policy_id") == policy_id:
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

                        # Re-sort by priority
                        policies.sort(key=lambda p: p.get("priority", 100))

                        policy_found = True
                        target_stage = stage
                        break

            if policy_found:
                break

        if not policy_found:
            return None

        # Save updated config
        _persist_policy_stage(tenant_id, tenant_config, target_stage)

        logger.info(f"Updated custom {target_stage} policy {policy_id} for tenant {tenant_id}")
        return get_custom_policy(tenant_id, policy_id, target_stage)

    except Exception as e:
        logger.error(f"Error updating custom policy {policy_id} for tenant {tenant_id}: {e}")
        raise


def delete_custom_policy(tenant_id: str, policy_id: str) -> bool:
    """Delete a custom policy."""
    try:
        # Get tenant config
        tenant_config = get_tenant(tenant_id)
        if not tenant_config:
            return False

        # Find and remove the policy
        policy_found = False
        target_stage = None

        for stage in ["input", "output"]:
            guardrail_key = f"custom_policy_{stage}"
            stage_key = f"{stage}_guardrails"

            if (stage_key in tenant_config and
                guardrail_key in tenant_config[stage_key] and
                "settings" in tenant_config[stage_key][guardrail_key]):

                policies = tenant_config[stage_key][guardrail_key]["settings"]["policies"]
                for i, policy in enumerate(policies):
                    if policy.get("policy_id") == policy_id:
                        policies.pop(i)
                        policy_found = True
                        target_stage = stage
                        break

            if policy_found:
                break

        if not policy_found:
            return False

        # Save updated config
        _persist_policy_stage(tenant_id, tenant_config, target_stage)

        logger.info(f"Deleted custom {target_stage} policy {policy_id} for tenant {tenant_id}")
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
        all_policies = get_tenant_custom_policies(tenant_id, enabled_only=False)
        input_policies = get_tenant_custom_policies(tenant_id, enabled_only=False, stage="input")
        output_policies = get_tenant_custom_policies(tenant_id, enabled_only=False, stage="output")

        stats = {
            "total_policies": len(all_policies),
            "enabled_policies": len([p for p in all_policies if p.get("enabled", True)]),
            "disabled_policies": len([p for p in all_policies if not p.get("enabled", True)]),
            "input_policies": len(input_policies),
            "output_policies": len(output_policies),
            "max_allowed_per_stage": MAX_POLICIES_PER_STAGE,
            "remaining_input_slots": MAX_POLICIES_PER_STAGE - len(input_policies),
            "remaining_output_slots": MAX_POLICIES_PER_STAGE - len(output_policies),
            "actions": {}
        }

        # Count by action type
        for policy in all_policies:
            action = policy.get("action", "unknown")
            stats["actions"][action] = stats["actions"].get(action, 0) + 1

        return stats

    except Exception as e:
        logger.error(f"Error getting policy stats for tenant {tenant_id}: {e}")
        return {
            "total_policies": 0,
            "enabled_policies": 0,
            "disabled_policies": 0,
            "input_policies": 0,
            "output_policies": 0,
            "max_allowed_per_stage": MAX_POLICIES_PER_STAGE,
            "remaining_input_slots": MAX_POLICIES_PER_STAGE,
            "remaining_output_slots": MAX_POLICIES_PER_STAGE,
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