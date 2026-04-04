"""Tenant management API — CRUD for multi-tenant guardrail configs."""

from fastapi import APIRouter, HTTPException

from storage.tenant_store import (
    create_tenant,
    get_tenant,
    update_tenant,
    delete_tenant,
    list_tenants,
    add_api_key,
    remove_api_key,
)

router = APIRouter(prefix="/v1/admin/tenants", tags=["tenants"])


@router.get("")
async def list_all_tenants():
    """List all tenants with summary info."""
    return {"tenants": list_tenants()}


@router.post("")
async def create_new_tenant(body: dict):
    """Create a new tenant.

    Example:
    {
        "tenant_id": "acme",
        "name": "Acme Corp",
        "plan": "enterprise",
        "api_keys": ["acme-key-abc123"],
        "input_guardrails": {
            "pii_detection": {"enabled": true, "action": "block", "settings": {"entities": ["US_SSN"], "score_threshold": 0.6}},
            "adversarial_detection": {"enabled": true, "action": "block", "settings": {"confidence_threshold": 0.7}}
        },
        "output_guardrails": {
            "pii_leakage": {"enabled": true, "action": "block", "settings": {"pii_types": ["SSN"], "auto_redact": true}},
            "tone_enforcement": {"enabled": true, "action": "warn", "settings": {"brand_voice_description": "Professional"}}
        },
        "rbac": {
            "roles": {
                "acme-support": {
                    "allowed_tools": ["search_knowledge_base"],
                    "denied_tools": ["execute_sql"],
                    "max_tokens_per_request": 2048,
                    "rate_limit": "60/min",
                    "data_clearance": "internal"
                }
            },
            "agents": {
                "acme-bot-1": "acme-support"
            }
        }
    }
    """
    tenant_id = body.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="'tenant_id' is required")

    # Check if tenant already exists
    existing = get_tenant(tenant_id)
    if existing:
        raise HTTPException(status_code=409, detail=f"Tenant '{tenant_id}' already exists")

    api_keys = body.pop("api_keys", [])
    config = create_tenant(tenant_id, body, api_keys)

    return {"status": "created", "tenant_id": tenant_id, "config": config}


@router.get("/{tenant_id}")
async def get_tenant_config(tenant_id: str):
    """Get a tenant's full config."""
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return config


@router.put("/{tenant_id}")
async def update_tenant_config(tenant_id: str, body: dict):
    """Update a tenant's config (merges with existing).

    Example — update input guardrails only:
    {
        "input_guardrails": {
            "toxicity": {"enabled": true, "action": "warn", "settings": {"threshold": 0.7}}
        }
    }
    """
    config = update_tenant(tenant_id, body)
    if not config:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return {"status": "updated", "tenant_id": tenant_id, "config": config}


@router.delete("/{tenant_id}")
async def delete_tenant_config(tenant_id: str):
    """Delete a tenant and all its API keys."""
    existing = get_tenant(tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    delete_tenant(tenant_id)
    return {"status": "deleted", "tenant_id": tenant_id}


@router.post("/{tenant_id}/api-keys")
async def add_tenant_api_key(tenant_id: str, body: dict):
    """Add an API key for a tenant.

    Example: {"api_key": "new-key-xyz"}
    """
    existing = get_tenant(tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    api_key = body.get("api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="'api_key' is required")

    add_api_key(tenant_id, api_key)
    return {"status": "added", "tenant_id": tenant_id}


@router.delete("/{tenant_id}/api-keys")
async def remove_tenant_api_key(tenant_id: str, body: dict):
    """Remove an API key for a tenant.

    Example: {"api_key": "old-key-to-remove"}
    """
    api_key = body.get("api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="'api_key' is required")

    remove_api_key(api_key)
    return {"status": "removed", "tenant_id": tenant_id}
