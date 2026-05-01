"""API routes for tenant custom policy management."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field, validator

from core.auth import get_tenant_from_request
from storage.admin_audit import log_admin_action
from storage.custom_policies import (
    save_custom_policy,
    get_custom_policy,
    get_tenant_custom_policies,
    update_custom_policy,
    delete_custom_policy,
    enable_custom_policy,
    disable_custom_policy,
    get_policy_stats,
    validate_policy_prompt,
    MAX_POLICIES_PER_TENANT,
)

router = APIRouter(prefix="/v1/tenant/me/custom-policies", tags=["tenant-custom-policies"])


def _tenant_id(request: Request) -> str:
    """Extract tenant ID from request."""
    return get_tenant_from_request(request)


def _audit_log(request: Request, action: str, tenant_id: str, metadata: dict = None):
    """Log admin action for audit trail."""
    log_admin_action(
        action=action,
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata=metadata or {},
    )


class CustomPolicyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Policy name")
    description: str = Field(..., min_length=1, max_length=500, description="Policy description")
    prompt: str = Field(..., min_length=20, max_length=2000, description="Natural language policy definition")
    action: str = Field(..., description="Action to take when policy is violated")
    enabled: Optional[bool] = Field(True, description="Whether policy is enabled")
    confidence_threshold: Optional[float] = Field(0.8, ge=0.5, le=1.0, description="Minimum confidence for violation")
    priority: Optional[int] = Field(100, ge=1, le=1000, description="Policy priority (lower = higher priority)")

    @validator("action")
    def validate_action(cls, v):
        valid_actions = ["pass", "warn", "redact", "block"]
        if v not in valid_actions:
            raise ValueError(f"Action must be one of: {valid_actions}")
        return v

    @validator("name")
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError("Policy name cannot be empty or whitespace only")
        return v.strip()

    @validator("prompt")
    def validate_prompt(cls, v):
        if not v.strip():
            raise ValueError("Policy prompt cannot be empty or whitespace only")
        return v.strip()


class CustomPolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, min_length=1, max_length=500)
    prompt: Optional[str] = Field(None, min_length=20, max_length=2000)
    action: Optional[str] = Field(None)
    enabled: Optional[bool] = Field(None)
    confidence_threshold: Optional[float] = Field(None, ge=0.5, le=1.0)
    priority: Optional[int] = Field(None, ge=1, le=1000)

    @validator("action")
    def validate_action(cls, v):
        if v is not None:
            valid_actions = ["pass", "warn", "redact", "block"]
            if v not in valid_actions:
                raise ValueError(f"Action must be one of: {valid_actions}")
        return v


class ValidatePromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=2000)


@router.get("/")
async def list_custom_policies(
    request: Request,
    enabled_only: bool = Query(False, description="Only return enabled policies")
):
    """List all custom policies for the tenant."""
    tenant_id = _tenant_id(request)

    policies = get_tenant_custom_policies(tenant_id, enabled_only=enabled_only)
    stats = get_policy_stats(tenant_id)

    return {
        "tenant_id": tenant_id,
        "policies": policies,
        "stats": stats
    }


@router.get("/stats")
async def get_custom_policy_stats(request: Request):
    """Get statistics about tenant's custom policies."""
    tenant_id = _tenant_id(request)
    stats = get_policy_stats(tenant_id)

    return {
        "tenant_id": tenant_id,
        "stats": stats
    }


@router.post("/")
async def create_custom_policy(request: Request, body: CustomPolicyRequest):
    """Create a new custom policy."""
    tenant_id = _tenant_id(request)

    try:
        # Validate the policy prompt
        validation = validate_policy_prompt(body.prompt)
        if not validation["valid"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Policy prompt validation failed",
                    "issues": validation["issues"],
                    "suggestions": validation["suggestions"]
                }
            )

        # Create the policy
        policy = save_custom_policy(
            tenant_id=tenant_id,
            policy_data=body.dict(),
            created_by=f"tenant:{tenant_id}"
        )

        _audit_log(
            request,
            "create_custom_policy",
            tenant_id,
            {"policy_id": policy["policy_id"], "policy_name": policy["name"]}
        )

        return {
            "status": "created",
            "policy": policy,
            "validation": validation
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create policy: {str(e)}")


@router.get("/{policy_id}")
async def get_custom_policy_by_id(request: Request, policy_id: str):
    """Get a specific custom policy by ID."""
    tenant_id = _tenant_id(request)

    policy = get_custom_policy(tenant_id, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {
        "tenant_id": tenant_id,
        "policy": policy
    }


@router.put("/{policy_id}")
async def update_custom_policy_by_id(
    request: Request,
    policy_id: str,
    body: CustomPolicyUpdateRequest
):
    """Update an existing custom policy."""
    tenant_id = _tenant_id(request)

    # Check if policy exists
    existing_policy = get_custom_policy(tenant_id, policy_id)
    if not existing_policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    try:
        # Validate prompt if it's being updated
        if body.prompt:
            validation = validate_policy_prompt(body.prompt)
            if not validation["valid"]:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Policy prompt validation failed",
                        "issues": validation["issues"],
                        "suggestions": validation["suggestions"]
                    }
                )

        # Update the policy
        updates = body.dict(exclude_none=True)
        updated_policy = update_custom_policy(
            tenant_id=tenant_id,
            policy_id=policy_id,
            updates=updates,
            updated_by=f"tenant:{tenant_id}"
        )

        if not updated_policy:
            raise HTTPException(status_code=404, detail="Policy not found")

        _audit_log(
            request,
            "update_custom_policy",
            tenant_id,
            {
                "policy_id": policy_id,
                "policy_name": updated_policy["name"],
                "updated_fields": list(updates.keys())
            }
        )

        return {
            "status": "updated",
            "policy": updated_policy
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update policy: {str(e)}")


@router.delete("/{policy_id}")
async def delete_custom_policy_by_id(request: Request, policy_id: str):
    """Delete a custom policy."""
    tenant_id = _tenant_id(request)

    # Get policy name for audit log
    existing_policy = get_custom_policy(tenant_id, policy_id)
    if not existing_policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    success = delete_custom_policy(tenant_id, policy_id)
    if not success:
        raise HTTPException(status_code=404, detail="Policy not found")

    _audit_log(
        request,
        "delete_custom_policy",
        tenant_id,
        {"policy_id": policy_id, "policy_name": existing_policy["name"]}
    )

    return {
        "status": "deleted",
        "policy_id": policy_id
    }


@router.post("/{policy_id}/enable")
async def enable_custom_policy_by_id(request: Request, policy_id: str):
    """Enable a custom policy."""
    tenant_id = _tenant_id(request)

    success = enable_custom_policy(tenant_id, policy_id)
    if not success:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = get_custom_policy(tenant_id, policy_id)
    _audit_log(
        request,
        "enable_custom_policy",
        tenant_id,
        {"policy_id": policy_id, "policy_name": policy["name"] if policy else "unknown"}
    )

    return {
        "status": "enabled",
        "policy_id": policy_id
    }


@router.post("/{policy_id}/disable")
async def disable_custom_policy_by_id(request: Request, policy_id: str):
    """Disable a custom policy."""
    tenant_id = _tenant_id(request)

    success = disable_custom_policy(tenant_id, policy_id)
    if not success:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = get_custom_policy(tenant_id, policy_id)
    _audit_log(
        request,
        "disable_custom_policy",
        tenant_id,
        {"policy_id": policy_id, "policy_name": policy["name"] if policy else "unknown"}
    )

    return {
        "status": "disabled",
        "policy_id": policy_id
    }


@router.post("/validate-prompt")
async def validate_custom_policy_prompt(request: Request, body: ValidatePromptRequest):
    """Validate a policy prompt before creating/updating a policy."""
    tenant_id = _tenant_id(request)

    validation = validate_policy_prompt(body.prompt)

    return {
        "tenant_id": tenant_id,
        "prompt": body.prompt,
        "validation": validation
    }


@router.get("/limits/info")
async def get_policy_limits(request: Request):
    """Get information about custom policy limits and constraints."""
    tenant_id = _tenant_id(request)

    return {
        "tenant_id": tenant_id,
        "limits": {
            "max_policies_per_tenant": MAX_POLICIES_PER_TENANT,
            "min_prompt_length": 20,
            "max_prompt_length": 2000,
            "min_name_length": 1,
            "max_name_length": 100,
            "min_description_length": 1,
            "max_description_length": 500,
            "valid_actions": ["pass", "warn", "redact", "block"],
            "confidence_threshold_range": {"min": 0.5, "max": 1.0},
            "priority_range": {"min": 1, "max": 1000}
        }
    }