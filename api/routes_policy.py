"""Policy management API routes — Create, read, update, delete data protection policies."""

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import time

from storage.policy_store import (
    create_policy,
    get_policy,
    update_policy,
    delete_policy,
    get_tenant_policies,
    test_policy_against_content,
    clear_policy_cache
)
from storage.tenant_store import get_tenant
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/shield/policies", tags=["policies"])


def _actor_from_request(request: Request) -> str:
    """Extract admin actor identity from headers."""
    import hashlib
    # Try different header formats
    key = (
        request.headers.get("X-Admin-Key") or
        request.headers.get("X-API-Key") or
        request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    if not key:
        return "unknown"
    return f"user:{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else ""


class PolicyPattern(BaseModel):
    regex: str = Field(..., description="Regular expression pattern to match")
    type: str = Field(..., description="Data type (e.g., 'medical', 'financial', 'pii')")
    sensitivity: str = Field(..., description="Sensitivity level", pattern="^(low|medium|high|critical)$")
    replacement: Optional[str] = Field("[REDACTED]", description="Text to replace matches with")


class PolicyConfig(BaseModel):
    policy_id: str = Field(..., description="Unique policy identifier")
    name: str = Field(..., description="Human-readable policy name")
    description: Optional[str] = Field(None, description="Policy description")
    patterns: List[PolicyPattern] = Field(..., description="List of data patterns to detect")
    roles: Dict[str, Dict[str, str]] = Field(..., description="Role permissions mapping")
    enabled: bool = Field(True, description="Whether policy is active")
    priority: int = Field(100, description="Policy priority (lower = higher priority)")


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    patterns: Optional[List[PolicyPattern]] = None
    roles: Optional[Dict[str, Dict[str, str]]] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None


class TestPolicyRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant ID for context")
    policy: PolicyConfig = Field(..., description="Policy to test")
    test_content: str = Field(..., description="Sample content to test against")
    test_user_role: str = Field(..., description="Role to test permissions with")


@router.get("/{tenant_id}")
async def list_tenant_policies(
    tenant_id: str,
    include_deleted: bool = Query(False, description="Include soft-deleted policies")
):
    """List all data protection policies for a tenant."""
    # Verify tenant exists
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    policies = get_tenant_policies(tenant_id, include_deleted=include_deleted)
    return {
        "tenant_id": tenant_id,
        "policies": policies,
        "count": len(policies)
    }


@router.post("/{tenant_id}")
async def create_tenant_policy(tenant_id: str, request: Request, policy: PolicyConfig):
    """Create a new data protection policy for a tenant."""
    # Verify tenant exists
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    # Check if policy already exists
    existing = get_policy(tenant_id, policy.policy_id)
    if existing and not existing.get("deleted_at"):
        raise HTTPException(
            status_code=409,
            detail=f"Policy '{policy.policy_id}' already exists for tenant '{tenant_id}'"
        )

    # Create policy
    policy_config = policy.model_dump()
    created_policy = create_policy(tenant_id, policy.policy_id, policy_config)

    # Log admin action
    log_admin_action(
        action="create_policy",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={
            "policy_id": policy.policy_id,
            "name": policy.name,
            "pattern_count": len(policy.patterns),
            "role_count": len(policy.roles)
        }
    )

    return {
        "status": "created",
        "tenant_id": tenant_id,
        "policy": created_policy
    }


@router.get("/{tenant_id}/{policy_id}")
async def get_tenant_policy(tenant_id: str, policy_id: str):
    """Get a specific policy by tenant ID and policy ID."""
    policy = get_policy(tenant_id, policy_id)
    if not policy:
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_id}' not found for tenant '{tenant_id}'"
        )

    # Hide soft-deleted policies unless explicitly requested
    if policy.get("deleted_at") and not policy.get("include_deleted"):
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_id}' not found for tenant '{tenant_id}'"
        )

    return policy


@router.put("/{tenant_id}/{policy_id}")
async def update_tenant_policy(
    tenant_id: str,
    policy_id: str,
    request: Request,
    updates: PolicyUpdateRequest
):
    """Update an existing data protection policy."""
    # Check if policy exists
    existing = get_policy(tenant_id, policy_id)
    if not existing or existing.get("deleted_at"):
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_id}' not found for tenant '{tenant_id}'"
        )

    # Update policy
    updates_dict = updates.model_dump(exclude_none=True)
    updated_policy = update_policy(tenant_id, policy_id, updates_dict)

    # Log admin action
    log_admin_action(
        action="update_policy",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        before={
            "name": existing.get("name"),
            "enabled": existing.get("enabled"),
            "pattern_count": len(existing.get("patterns", []))
        },
        after={
            "name": updated_policy.get("name"),
            "enabled": updated_policy.get("enabled"),
            "pattern_count": len(updated_policy.get("patterns", []))
        },
        metadata={"updated_fields": list(updates_dict.keys())}
    )

    # Clear cache to ensure changes take effect
    clear_policy_cache(tenant_id, policy_id)

    return {
        "status": "updated",
        "tenant_id": tenant_id,
        "policy": updated_policy
    }


@router.delete("/{tenant_id}/{policy_id}")
async def delete_tenant_policy(
    tenant_id: str,
    policy_id: str,
    request: Request,
    hard: bool = Query(False, description="If true, permanently delete; otherwise soft delete")
):
    """Delete a data protection policy."""
    # Check if policy exists
    existing = get_policy(tenant_id, policy_id)
    if not existing:
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_id}' not found for tenant '{tenant_id}'"
        )

    # Delete policy
    success = delete_policy(tenant_id, policy_id, soft=not hard)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete policy")

    # Log admin action
    log_admin_action(
        action="delete_policy_hard" if hard else "delete_policy_soft",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        before={
            "policy_id": policy_id,
            "name": existing.get("name"),
            "enabled": existing.get("enabled")
        }
    )

    # Clear cache
    clear_policy_cache(tenant_id, policy_id)

    return {
        "status": "deleted",
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "hard": hard
    }


@router.post("/test")
async def test_policy(test_request: TestPolicyRequest):
    """Test a policy against sample content without storing it."""
    try:
        result = test_policy_against_content(
            policy_config=test_request.policy.model_dump(),
            content=test_request.test_content,
            user_role=test_request.test_user_role
        )

        return {
            "tenant_id": test_request.tenant_id,
            "policy_id": test_request.policy.policy_id,
            "test_role": test_request.test_user_role,
            "test_content": test_request.test_content,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Policy test failed: {str(e)}")


@router.post("/{tenant_id}/bulk")
async def bulk_create_policies(tenant_id: str, request: Request, policies: List[PolicyConfig]):
    """Create multiple policies at once for a tenant."""
    # Verify tenant exists
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    created_policies = []
    errors = []

    for policy in policies:
        try:
            # Check if policy already exists
            existing = get_policy(tenant_id, policy.policy_id)
            if existing and not existing.get("deleted_at"):
                errors.append(f"Policy '{policy.policy_id}' already exists")
                continue

            # Create policy
            policy_config = policy.model_dump()
            created_policy = create_policy(tenant_id, policy.policy_id, policy_config)
            created_policies.append(created_policy)

        except Exception as e:
            errors.append(f"Failed to create policy '{policy.policy_id}': {str(e)}")

    # Log bulk action
    log_admin_action(
        action="bulk_create_policies",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={
            "requested_count": len(policies),
            "created_count": len(created_policies),
            "error_count": len(errors)
        }
    )

    return {
        "status": "completed",
        "tenant_id": tenant_id,
        "created": created_policies,
        "errors": errors,
        "summary": {
            "requested": len(policies),
            "created": len(created_policies),
            "failed": len(errors)
        }
    }


@router.post("/{tenant_id}/cache/clear")
async def clear_tenant_policy_cache(tenant_id: str, request: Request):
    """Clear all policy cache entries for a tenant."""
    # Verify tenant exists
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    # Clear cache for all policies
    clear_policy_cache(tenant_id)

    log_admin_action(
        action="clear_policy_cache",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request)
    )

    return {
        "status": "cleared",
        "tenant_id": tenant_id,
        "message": "Policy cache cleared for tenant"
    }