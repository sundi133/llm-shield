"""Cross-Tenant Policy Inheritance — merge parent policies with child policies.

Rules:
- Parent policies are included as baseline
- Child policies with same policy_id override parent
- Child cannot weaken parent restrictions (block → allow is not permitted)
- Priority: child policies override parent; if conflict, stricter wins
"""

import logging
from typing import Optional

from storage.tenant_store import get_tenant_parent, get_tenant_ancestors
from storage.policy_store import get_tenant_policies

logger = logging.getLogger("votal.policy_inheritance")

# Action strictness ordering (higher index = stricter)
_ACTION_STRICTNESS = {"allow": 0, "redact": 1, "mask": 2, "block": 3}


def get_effective_policies(tenant_id: str) -> list[dict]:
    """Get the effective policy set for a tenant, including inherited policies.

    Merges parent policies with child policies. If a child has a policy with
    the same policy_id as a parent, validates it doesn't weaken parent restrictions.

    Args:
        tenant_id: Tenant identifier

    Returns:
        List of effective policy configs (merged parent + child).
    """
    ancestors = get_tenant_ancestors(tenant_id)

    if not ancestors:
        # No parent — just return own policies
        return get_tenant_policies(tenant_id, include_deleted=False)

    # Collect policies from all ancestors (root first)
    inherited_policies = {}  # policy_id → policy_config
    for ancestor_id in reversed(ancestors):
        for policy in get_tenant_policies(ancestor_id, include_deleted=False):
            pid = policy.get("policy_id")
            if pid:
                policy_copy = dict(policy)
                policy_copy["inherited_from"] = ancestor_id
                inherited_policies[pid] = policy_copy

    # Get child's own policies
    child_policies = get_tenant_policies(tenant_id, include_deleted=False)
    child_by_id = {p.get("policy_id"): p for p in child_policies}

    # Merge: child overrides parent IF it doesn't weaken
    effective = []
    seen_ids = set()

    for pid, parent_policy in inherited_policies.items():
        if pid in child_by_id:
            # Child has override — validate it doesn't weaken
            child_policy = child_by_id[pid]
            is_valid, reason = validate_child_policy(parent_policy, child_policy)
            if is_valid:
                effective.append(child_policy)
            else:
                # Child tried to weaken — use parent policy instead
                parent_policy["inheritance_override_rejected"] = reason
                effective.append(parent_policy)
                logger.warning(
                    f"Tenant {tenant_id} policy {pid} override rejected: {reason}. "
                    f"Using parent ({parent_policy.get('inherited_from')}) policy."
                )
        else:
            # No child override — inherit parent
            effective.append(parent_policy)
        seen_ids.add(pid)

    # Add child-only policies (not overriding parent)
    for pid, child_policy in child_by_id.items():
        if pid not in seen_ids:
            effective.append(child_policy)

    # Sort by priority
    effective.sort(key=lambda p: p.get("priority", 100))
    return effective


def validate_child_policy(parent_policy: dict, child_policy: dict) -> tuple[bool, str]:
    """Validate that a child policy does not weaken parent restrictions.

    A child policy weakens a parent if:
    - It changes a role's action from a stricter to a less strict action
      (e.g., block → allow, redact → allow)
    - It disables a policy that the parent has enabled

    Args:
        parent_policy: The inherited parent policy config
        child_policy: The child's override policy config

    Returns:
        (is_valid, reason) — True if child doesn't weaken parent.
    """
    # Check 1: Child cannot disable a parent-enabled policy
    if parent_policy.get("enabled", True) and not child_policy.get("enabled", True):
        return False, "Cannot disable an inherited policy"

    # Check 2: Child cannot weaken role permissions
    parent_roles = parent_policy.get("roles", {})
    child_roles = child_policy.get("roles", {})

    for role_name, parent_perms in parent_roles.items():
        child_perms = child_roles.get(role_name, {})
        for data_type, parent_action in parent_perms.items():
            child_action = child_perms.get(data_type)
            if child_action is None:
                continue  # Child doesn't override this specific permission

            parent_strictness = _ACTION_STRICTNESS.get(parent_action, 0)
            child_strictness = _ACTION_STRICTNESS.get(child_action, 0)

            if child_strictness < parent_strictness:
                return (
                    False,
                    f"Role '{role_name}' action for '{data_type}' weakened: "
                    f"parent={parent_action} → child={child_action}"
                )

    return True, ""
