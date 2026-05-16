"""Policy management API routes — Create, read, update, delete data protection policies."""

import json
import time

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

from enum import Enum

from storage.policy_store import (
    create_policy,
    get_policy,
    update_policy,
    delete_policy,
    get_tenant_policies,
    test_policy_against_content,
    clear_policy_cache,
    list_policy_versions,
    get_policy_version,
    rollback_policy,
    get_agent_registry,
    get_tool_policies,
    register_agent,
    set_tool_policies,
)
from storage.tenant_store import get_tenant, _fallback_store
from storage.admin_audit import log_admin_action
from storage.custom_policies import get_tenant_custom_policies
from storage.tenant_store import set_tenant_policies, _get_redis

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


# ============================================================================
# Policy Versioning Endpoints
# ============================================================================


@router.get("/{tenant_id}/{policy_id}/versions")
async def list_versions(
    tenant_id: str,
    policy_id: str,
    limit: int = Query(20, ge=1, le=50, description="Max versions to return"),
):
    """List version history for a policy (newest first)."""
    policy = get_policy(tenant_id, policy_id)
    if not policy:
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_id}' not found for tenant '{tenant_id}'"
        )

    versions = list_policy_versions(tenant_id, policy_id, limit=limit)
    return {
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "versions": versions,
        "count": len(versions),
    }


@router.get("/{tenant_id}/{policy_id}/versions/{version}")
async def get_version(tenant_id: str, policy_id: str, version: int):
    """Get a specific version snapshot of a policy."""
    version_entry = get_policy_version(tenant_id, policy_id, version)
    if not version_entry:
        raise HTTPException(
            status_code=404,
            detail=f"Version {version} not found for policy '{policy_id}'"
        )

    return {
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "version": version_entry,
    }


class RollbackRequest(BaseModel):
    version: int = Field(..., description="Version number to rollback to")


@router.post("/{tenant_id}/{policy_id}/rollback")
async def rollback_policy_endpoint(
    tenant_id: str, policy_id: str, body: RollbackRequest, request: Request
):
    """Rollback a policy to a previous version."""
    # Check policy exists
    existing = get_policy(tenant_id, policy_id)
    if not existing:
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_id}' not found for tenant '{tenant_id}'"
        )

    restored = rollback_policy(tenant_id, policy_id, body.version)
    if not restored:
        raise HTTPException(
            status_code=404,
            detail=f"Version {body.version} not found for policy '{policy_id}'"
        )

    log_admin_action(
        action="rollback_policy",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        before={"policy_id": policy_id, "version_before": "current"},
        after={"policy_id": policy_id, "rolled_back_to_version": body.version},
    )

    clear_policy_cache(tenant_id, policy_id)

    return {
        "status": "rolled_back",
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "rolled_back_to_version": body.version,
        "policy": restored,
    }


# ============================================================================
# Policy Export/Import Endpoints
# ============================================================================


class ImportConflictMode(str, Enum):
    skip = "skip"
    overwrite = "overwrite"
    error = "error"


class PolicyBundle(BaseModel):
    version: str = Field("1.0", description="Bundle format version")
    tenant_id: str = Field(..., description="Source tenant ID")
    exported_at: Optional[str] = Field(None, description="ISO timestamp of export")
    policies: List[Dict[str, Any]] = Field(default_factory=list)
    agent_configs: Dict[str, Any] = Field(default_factory=dict)
    tool_policies: Dict[str, Any] = Field(default_factory=dict)
    data_policies: Dict[str, Any] = Field(default_factory=dict)
    tenant_guardrails: Dict[str, Any] = Field(default_factory=dict)
    custom_policies: List[Dict[str, Any]] = Field(default_factory=list)


@router.get("/{tenant_id}/bundle/export")
async def export_policies(tenant_id: str):
    """Export all policies, agent configs, and tool policies as a single bundle.

    Use this for policy-as-code workflows: export → commit to git → import via CI/CD.
    """
    from datetime import datetime, timezone

    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    policies = get_tenant_policies(tenant_id, include_deleted=False)
    agents = get_agent_registry(tenant_id)
    tool_pols = get_tool_policies(tenant_id)
    tenant_guardrails = {
        "input_guardrails": tenant.get("input_guardrails", {}),
        "output_guardrails": tenant.get("output_guardrails", {}),
    }
    custom_policies = get_tenant_custom_policies(tenant_id, enabled_only=False)
    r = _get_redis()
    raw_data_policies = r.get(f"data_policies:{tenant_id}") if r else None
    data_policies = {}
    if raw_data_policies:
        data_policies = raw_data_policies if isinstance(raw_data_policies, dict) else json.loads(raw_data_policies)
    elif not r:
        fallback_raw = _fallback_store.get(f"data_policies:{tenant_id}")
        if fallback_raw:
            data_policies = json.loads(fallback_raw)

    bundle = {
        "version": "1.0",
        "tenant_id": tenant_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "policies": policies,
        "agent_configs": agents,
        "tool_policies": tool_pols,
        "data_policies": data_policies,
        "tenant_guardrails": tenant_guardrails,
        "custom_policies": custom_policies,
    }

    return bundle


@router.post("/{tenant_id}/bundle/import")
async def import_policies(
    tenant_id: str,
    request: Request,
    bundle: PolicyBundle,
    conflict_mode: ImportConflictMode = Query("error", description="How to handle conflicts"),
):
    """Import a policy bundle into a tenant.

    Conflict modes:
    - skip: Skip policies that already exist
    - overwrite: Overwrite existing policies
    - error: Return error if any policy already exists
    """
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    imported = []
    skipped = []
    errors = []

    # Import policies
    for policy_data in bundle.policies:
        pid = policy_data.get("policy_id")
        if not pid:
            errors.append("Policy missing policy_id field")
            continue

        existing = get_policy(tenant_id, pid)
        if existing and not existing.get("deleted_at"):
            if conflict_mode == ImportConflictMode.error:
                raise HTTPException(
                    status_code=409,
                    detail=f"Policy '{pid}' already exists. Use conflict_mode=skip or overwrite."
                )
            elif conflict_mode == ImportConflictMode.skip:
                skipped.append(pid)
                continue
            elif conflict_mode == ImportConflictMode.overwrite:
                # Update existing
                policy_data.pop("created_at", None)
                update_policy(tenant_id, pid, policy_data)
                imported.append(pid)
                continue

        # Create new
        policy_data["tenant_id"] = tenant_id
        create_policy(tenant_id, pid, policy_data)
        imported.append(pid)

    # Import agent configs
    agents_imported = 0
    for agent_id, agent_config in bundle.agent_configs.items():
        agent_config["agent_id"] = agent_id
        register_agent(tenant_id, agent_config)
        agents_imported += 1

    # Import tool policies
    tool_policies_imported = False
    if bundle.tool_policies:
        set_tool_policies(tenant_id, bundle.tool_policies)
        tool_policies_imported = True

    # Import live tenant guardrails used by the tenant portal UI
    tenant_guardrails_imported = False
    if bundle.tenant_guardrails:
        set_tenant_policies(
            tenant_id,
            input_guardrails=bundle.tenant_guardrails.get("input_guardrails"),
            output_guardrails=bundle.tenant_guardrails.get("output_guardrails"),
        )
        tenant_guardrails_imported = True

    # Import custom guardrail policies stored within tenant guardrails
    custom_policies_imported = 0
    if bundle.custom_policies:
        grouped_custom = {"input": [], "output": []}
        for policy in bundle.custom_policies:
            stage = policy.get("stage", "input")
            if stage in grouped_custom:
                grouped_custom[stage].append(policy)

        tenant_cfg = get_tenant(tenant_id) or {}
        for stage, policies_for_stage in grouped_custom.items():
            if not policies_for_stage:
                continue
            stage_key = f"{stage}_guardrails"
            guardrail_key = f"custom_policy_{stage}"
            tenant_cfg.setdefault(stage_key, {})
            existing_guardrail = tenant_cfg[stage_key].get(guardrail_key, {})
            tenant_cfg[stage_key][guardrail_key] = {
                "enabled": existing_guardrail.get("enabled", True),
                "action": existing_guardrail.get("action", "pass"),
                "settings": {
                    **existing_guardrail.get("settings", {}),
                    "policies": sorted(policies_for_stage, key=lambda p: p.get("priority", 100)),
                },
            }
            custom_policies_imported += len(policies_for_stage)
        set_tenant_policies(
            tenant_id,
            input_guardrails=tenant_cfg.get("input_guardrails"),
            output_guardrails=tenant_cfg.get("output_guardrails"),
        )

    # Import per-tool data policies from the Tool Policies > Data Policies UI
    data_policies_imported = False
    if bundle.data_policies:
        r = _get_redis()
        if r:
            r.set(f"data_policies:{tenant_id}", json.dumps(bundle.data_policies))
        else:
            _fallback_store[f"data_policies:{tenant_id}"] = json.dumps(bundle.data_policies)
        data_policies_imported = True

    log_admin_action(
        action="import_policies",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={
            "policies_imported": len(imported),
            "policies_skipped": len(skipped),
            "agents_imported": agents_imported,
            "tool_policies_imported": tool_policies_imported,
            "data_policies_imported": data_policies_imported,
            "tenant_guardrails_imported": tenant_guardrails_imported,
            "custom_policies_imported": custom_policies_imported,
            "conflict_mode": conflict_mode.value,
        },
    )

    return {
        "status": "completed",
        "tenant_id": tenant_id,
        "summary": {
            "policies_imported": len(imported),
            "policies_skipped": len(skipped),
            "agents_imported": agents_imported,
            "tool_policies_imported": tool_policies_imported,
            "data_policies_imported": data_policies_imported,
            "tenant_guardrails_imported": tenant_guardrails_imported,
            "custom_policies_imported": custom_policies_imported,
            "errors": errors,
        },
        "imported_policy_ids": imported,
        "skipped_policy_ids": skipped,
    }
