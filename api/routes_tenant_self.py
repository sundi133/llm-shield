"""Tenant self-service API — read + edit access for a tenant to manage their policies.

Uses the request.state.tenant_id set by ShieldMiddleware (resolved from API key).
Tenants can view and update their own guardrail policies. They cannot modify
RBAC, quota, plan, or API keys — those are admin-only.
"""

from typing import Optional
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field, validator

from storage.tenant_store import get_tenant, update_tenant, set_tenant_policies, _get_redis
from storage.tenant_models import GuardrailPolicy
from storage.rate_limiter import get_usage
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
    MAX_POLICIES_PER_STAGE,
)

router = APIRouter(prefix="/v1/tenant", tags=["tenant-self"])


class TenantSelfUpdateRequest(BaseModel):
    """Fields a tenant is allowed to modify on their own config."""
    input_guardrails: Optional[dict[str, GuardrailPolicy]] = None
    output_guardrails: Optional[dict[str, GuardrailPolicy]] = None


class CustomPolicyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Policy name")
    description: str = Field(..., min_length=1, max_length=500, description="Policy description")
    prompt: str = Field(..., min_length=20, max_length=2000, description="Natural language policy definition")
    action: str = Field(..., description="Action to take when policy is violated")
    stage: str = Field("input", description="Policy stage: input or output")
    enabled: Optional[bool] = Field(True, description="Whether policy is enabled")
    confidence_threshold: Optional[float] = Field(0.8, ge=0.5, le=1.0, description="Minimum confidence for violation")
    priority: Optional[int] = Field(100, ge=1, le=1000, description="Policy priority (lower = higher priority)")

    @validator("stage")
    def validate_stage(cls, v):
        valid_stages = ["input", "output"]
        if v not in valid_stages:
            raise ValueError(f"Stage must be one of: {valid_stages}")
        return v

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
    stage: Optional[str] = Field(None)
    enabled: Optional[bool] = Field(None)
    confidence_threshold: Optional[float] = Field(None, ge=0.5, le=1.0)
    priority: Optional[int] = Field(None, ge=1, le=1000)

    @validator("stage")
    def validate_stage(cls, v):
        if v is not None:
            valid_stages = ["input", "output"]
            if v not in valid_stages:
                raise ValueError(f"Stage must be one of: {valid_stages}")
        return v

    @validator("action")
    def validate_action(cls, v):
        if v is not None:
            valid_actions = ["pass", "warn", "redact", "block"]
            if v not in valid_actions:
                raise ValueError(f"Action must be one of: {valid_actions}")
        return v


class ValidatePromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=2000)


def _require_tenant(request: Request) -> str:
    """Ensure request has a resolved tenant, else reject."""
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(
            status_code=401,
            detail="Tenant API key required to access /v1/tenant/* endpoints",
        )
    return tenant_id


@router.get("/me")
async def get_my_tenant(request: Request):
    """Return the current tenant's config (sanitized — no internal fields)."""
    tenant_id = _require_tenant(request)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")

    agents_from_registry = []
    try:
        import json as _json
        r = _get_redis()
        if r:
            raw = r.get(f"agents:{tenant_id}")
            if raw:
                agents_from_registry = list(_json.loads(raw).keys())
    except Exception:
        pass

    return {
        "tenant_id": config.get("tenant_id"),
        "name": config.get("name"),
        "plan": config.get("plan"),
        "input_guardrails": list(config.get("input_guardrails", {}).keys()),
        "output_guardrails": list(config.get("output_guardrails", {}).keys()),
        "quota": config.get("quota"),
        "agents": agents_from_registry,
    }


@router.get("/me/usage")
async def get_my_usage(request: Request):
    """Return the current tenant's usage against quota."""
    tenant_id = _require_tenant(request)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")

    usage = get_usage(tenant_id)
    quota = config.get("quota") or {}
    max_min = quota.get("max_requests_per_minute") or 1
    max_day = quota.get("max_requests_per_day") or 1
    return {
        "tenant_id": tenant_id,
        "plan": config.get("plan"),
        "usage": usage,
        "quota": quota,
        "pct_of_minute_limit": round(100 * (usage.get("requests_this_minute", 0)) / max_min, 1),
        "pct_of_daily_limit": round(100 * (usage.get("requests_today", 0)) / max_day, 1),
    }


@router.get("/me/policies")
async def get_my_policies(request: Request):
    """Return the tenant's current input + output guardrail policies (full detail) including custom policies."""
    tenant_id = _require_tenant(request)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Get custom policies from both stages
    custom_input_policies = get_tenant_custom_policies(tenant_id, enabled_only=False, stage="input")
    custom_output_policies = get_tenant_custom_policies(tenant_id, enabled_only=False, stage="output")

    return {
        "tenant_id": tenant_id,
        "input_guardrails": config.get("input_guardrails", {}),
        "output_guardrails": config.get("output_guardrails", {}),
        "custom_policies": {
            "input": custom_input_policies,
            "output": custom_output_policies,
            "total": len(custom_input_policies) + len(custom_output_policies)
        }
    }


@router.put("/me/policies")
async def update_my_policies(request: Request, body: TenantSelfUpdateRequest):
    """Tenant updates their own input/output guardrail policies.

    Tenants cannot modify RBAC, quota, plan, or API keys via this route.
    Changes are logged in the admin audit with actor=tenant:<id>.
    """
    tenant_id = _require_tenant(request)
    existing = get_tenant(tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Tenant not found")

    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Full replace (not merge) so removed guardrails are actually deleted
    config = set_tenant_policies(
        tenant_id,
        input_guardrails=updates.get("input_guardrails"),
        output_guardrails=updates.get("output_guardrails"),
    )

    log_admin_action(
        action="tenant_self_update_policies",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        before={"input_guardrails": list((existing.get("input_guardrails") or {}).keys()),
                "output_guardrails": list((existing.get("output_guardrails") or {}).keys())},
        after={"input_guardrails": list((config.get("input_guardrails") or {}).keys()),
               "output_guardrails": list((config.get("output_guardrails") or {}).keys())},
        metadata={"updated_fields": list(updates.keys())},
    )

    return {
        "status": "updated",
        "tenant_id": tenant_id,
        "input_guardrails": config.get("input_guardrails", {}),
        "output_guardrails": config.get("output_guardrails", {}),
    }


@router.get("/me/audit")
async def get_my_audit_log(request: Request, limit: int = 50):
    """Return recent admin audit entries scoped to this tenant."""
    tenant_id = _require_tenant(request)
    from storage.admin_audit import query_admin_audit
    entries = query_admin_audit(tenant_id=tenant_id, limit=limit)
    return {"tenant_id": tenant_id, "entries": entries}


# ───────────────────────────────────────────────────────────────────
# Tenant-managed API keys
#
# Tenants can create and revoke their own keys. The plaintext key is
# shown ONLY once at creation time — we only store the SHA-256 hash,
# so neither we nor the tenant can recover a lost key; they must
# create a new one.
# ───────────────────────────────────────────────────────────────────


def _new_key(tenant_id: str) -> str:
    """Generate a new random API key with a tenant-prefixed format."""
    import secrets
    return f"{tenant_id}_{secrets.token_urlsafe(32)}"


def _key_preview(api_key: str) -> str:
    """Show first 8 and last 4 chars of a key for display."""
    if len(api_key) < 16:
        return "****"
    return f"{api_key[:8]}...{api_key[-4:]}"


@router.get("/me/api-keys")
async def list_my_api_keys(request: Request):
    """List hashed API keys mapped to the current tenant.

    Returns only hash prefixes — the plaintext keys are never stored.
    """
    tenant_id = _require_tenant(request)
    from storage.tenant_store import _get_redis, _fallback_store

    r = _get_redis()
    results = []
    if r:
        cursor = 0
        while True:
            try:
                cursor, keys = r.scan(cursor, match="apikey:*", count=100)
            except Exception:
                break
            for key in keys:
                try:
                    if r.get(key) == tenant_id:
                        hash_part = key.split(":", 1)[1] if ":" in key else key
                        results.append({
                            "hash_prefix": hash_part[:12] + "...",
                            "created": None,  # not tracked per-key currently
                        })
                except Exception:
                    continue
            if cursor == 0:
                break
    else:
        for k, v in _fallback_store.items():
            if k.startswith("apikey:") and v == tenant_id:
                hash_part = k.split(":", 1)[1]
                results.append({
                    "hash_prefix": hash_part[:12] + "...",
                    "created": None,
                })

    return {"tenant_id": tenant_id, "api_keys": results, "count": len(results)}


@router.post("/me/api-keys")
async def create_my_api_key(request: Request, body: dict = None):
    """Create a new API key for the current tenant.

    The plaintext key is returned ONLY in this response. Store it
    immediately — it cannot be recovered later.

    Optional body: {"custom_key": "my-custom-value"} to provide your
    own key value instead of generating one (discouraged — less secure).
    """
    tenant_id = _require_tenant(request)
    existing = get_tenant(tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Limit keys per tenant to prevent abuse
    from storage.tenant_store import add_api_key, _get_redis, _fallback_store
    r = _get_redis()
    existing_count = 0
    if r:
        try:
            cursor = 0
            while True:
                cursor, keys = r.scan(cursor, match="apikey:*", count=100)
                for k in keys:
                    if r.get(k) == tenant_id:
                        existing_count += 1
                if cursor == 0:
                    break
        except Exception:
            pass
    else:
        existing_count = sum(
            1 for k, v in _fallback_store.items()
            if k.startswith("apikey:") and v == tenant_id
        )

    if existing_count >= 10:
        raise HTTPException(
            status_code=429,
            detail="API key limit reached (max 10 per tenant). Revoke unused keys first.",
        )

    # Generate or accept a custom key
    custom_key = (body or {}).get("custom_key") if body else None
    api_key = custom_key.strip() if custom_key else _new_key(tenant_id)

    if len(api_key) < 16:
        raise HTTPException(status_code=400, detail="API key must be at least 16 characters")

    add_api_key(tenant_id, api_key)

    log_admin_action(
        action="tenant_create_api_key",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"key_preview": _key_preview(api_key)},
    )

    return {
        "status": "created",
        "tenant_id": tenant_id,
        "api_key": api_key,  # shown ONCE
        "preview": _key_preview(api_key),
        "warning": "Store this key immediately — it cannot be retrieved later.",
    }


@router.delete("/me/api-keys")
async def revoke_my_api_key(request: Request, body: dict):
    """Revoke an API key owned by the current tenant.

    Body: {"api_key": "plaintext-key-to-revoke"}

    The caller must supply the plaintext key (not the hash) so we
    can compute the hash and verify it maps to this tenant.
    """
    tenant_id = _require_tenant(request)
    api_key = (body or {}).get("api_key", "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="'api_key' is required")

    # Verify the key belongs to this tenant before revoking
    from storage.tenant_store import resolve_tenant_by_api_key, remove_api_key
    owner = resolve_tenant_by_api_key(api_key)
    if owner != tenant_id:
        raise HTTPException(
            status_code=403,
            detail="API key does not belong to this tenant or is invalid",
        )

    # Prevent self-lockout: don't let a tenant revoke the key they're using
    caller_key = request.headers.get("X-API-Key", "") or ""
    if caller_key and caller_key.strip() == api_key:
        raise HTTPException(
            status_code=400,
            detail="Cannot revoke the API key you are currently using. Create a new key first, switch to it, then revoke this one.",
        )

    remove_api_key(api_key)

    log_admin_action(
        action="tenant_revoke_api_key",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"key_preview": _key_preview(api_key)},
    )

    return {"status": "revoked", "tenant_id": tenant_id, "preview": _key_preview(api_key)}


# ---------------------------------------------------------------------------
# Tool Definitions — tenant-specific OpenAI-format tool schemas
# ---------------------------------------------------------------------------

@router.get("/me/tools")
async def get_my_tools(request: Request):
    """Return the tenant's registered tool definitions (full OpenAI-format schemas).

    These are the tools available for agentic chat and Deep Agent integration.
    Each tool has a name, description, and parameter schema.
    """
    tenant_id = _require_tenant(request)

    import json as _json
    r = _get_redis()
    raw = r.get(f"tool_definitions:{tenant_id}") if r else None
    tools = _json.loads(raw) if raw else []

    config = get_tenant(tenant_id)
    allowlist = (config or {}).get("input_guardrails", {}).get("tool_allowlist", {}).get("settings", {})

    return {
        "tenant_id": tenant_id,
        "tools": tools,
        "tool_names": [t["function"]["name"] for t in tools if "function" in t],
        "per_role": allowlist.get("per_role", {}),
        "per_agent": allowlist.get("per_agent", {}),
    }


@router.put("/me/tools")
async def set_my_tools(request: Request):
    """Register or replace the tenant's tool definitions.

    Body: { "tools": [ { "type": "function", "function": { "name": "...", ... } }, ... ] }

    These are OpenAI-format tool schemas used by /v1/shield/chat/agent
    and the Deep Agent integration.
    """
    import json as _json
    tenant_id = _require_tenant(request)
    body = await request.json()
    tools = body.get("tools", [])

    for t in tools:
        if "function" not in t or "name" not in t.get("function", {}):
            raise HTTPException(status_code=422, detail="Each tool must have function.name")

    r = _get_redis()
    if r:
        r.set(f"tool_definitions:{tenant_id}", _json.dumps(tools))
    else:
        from storage.tenant_store import _fallback_store
        _fallback_store[f"tool_definitions:{tenant_id}"] = _json.dumps(tools)

    log_admin_action(
        action="tenant_set_tool_definitions",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata={"tool_count": len(tools), "names": [t["function"]["name"] for t in tools]},
    )

    return {
        "status": "ok",
        "tenant_id": tenant_id,
        "tool_count": len(tools),
        "tool_names": [t["function"]["name"] for t in tools],
    }


@router.get("/me/agents")
async def get_my_agents(request: Request):
    """Return the tenant's full agent registry with roles and tool mappings."""
    import json as _json
    tenant_id = _require_tenant(request)

    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")

    allowlist = config.get("input_guardrails", {}).get("tool_allowlist", {}).get("settings", {})

    r = _get_redis()
    agents_raw = r.get(f"agents:{tenant_id}") if r else None
    agent_registry = _json.loads(agents_raw) if agents_raw else {}

    return {
        "tenant_id": tenant_id,
        "per_agent": allowlist.get("per_agent", {}),
        "per_role": allowlist.get("per_role", {}),
        "agent_registry": agent_registry,
    }


# ==================== CUSTOM POLICIES - UNIFIED UNDER /policies ====================

def _audit_log(request: Request, action: str, tenant_id: str, metadata: dict = None):
    """Log admin action for audit trail."""
    log_admin_action(
        action=action,
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata=metadata or {},
    )


@router.post("/me/policies/custom")
async def create_custom_policy(request: Request, body: CustomPolicyRequest):
    """Create a new custom policy within the tenant's guardrail configuration."""
    tenant_id = _require_tenant(request)

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

        # Create the policy within the tenant's guardrail config
        policy = save_custom_policy(
            tenant_id=tenant_id,
            policy_data=body.dict(),
            created_by=f"tenant:{tenant_id}",
            stage=body.stage
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


@router.get("/me/policies/custom/{policy_id}")
async def get_custom_policy_by_id(request: Request, policy_id: str):
    """Get a specific custom policy by ID."""
    tenant_id = _require_tenant(request)

    policy = get_custom_policy(tenant_id, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {
        "tenant_id": tenant_id,
        "policy": policy
    }


@router.put("/me/policies/custom/{policy_id}")
async def update_custom_policy_by_id(request: Request, policy_id: str, body: CustomPolicyUpdateRequest):
    """Update an existing custom policy."""
    tenant_id = _require_tenant(request)

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


@router.delete("/me/policies/custom/{policy_id}")
async def delete_custom_policy_by_id(request: Request, policy_id: str):
    """Delete a custom policy."""
    tenant_id = _require_tenant(request)

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


@router.post("/me/policies/custom/{policy_id}/enable")
async def enable_custom_policy_by_id(request: Request, policy_id: str):
    """Enable a custom policy."""
    tenant_id = _require_tenant(request)

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


@router.post("/me/policies/custom/{policy_id}/disable")
async def disable_custom_policy_by_id(request: Request, policy_id: str):
    """Disable a custom policy."""
    tenant_id = _require_tenant(request)

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


@router.post("/me/policies/custom/validate")
async def validate_custom_policy_prompt(request: Request, body: ValidatePromptRequest):
    """Validate a policy prompt before creating/updating a policy."""
    tenant_id = _require_tenant(request)

    validation = validate_policy_prompt(body.prompt)

    return {
        "tenant_id": tenant_id,
        "prompt": body.prompt,
        "validation": validation
    }


@router.get("/me/policies/custom")
async def list_custom_policies(request: Request, enabled_only: bool = Query(False, description="Only return enabled policies")):
    """List all custom policies for the tenant."""
    tenant_id = _require_tenant(request)

    policies = get_tenant_custom_policies(tenant_id, enabled_only=enabled_only)
    stats = get_policy_stats(tenant_id)

    return {
        "tenant_id": tenant_id,
        "policies": policies,
        "stats": stats
    }


@router.get("/me/policies/limits")
async def get_policy_limits(request: Request):
    """Get information about custom policy limits and constraints."""
    tenant_id = _require_tenant(request)

    return {
        "tenant_id": tenant_id,
        "limits": {
            "max_policies_per_stage": MAX_POLICIES_PER_STAGE,
            "valid_stages": ["input", "output"],
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
