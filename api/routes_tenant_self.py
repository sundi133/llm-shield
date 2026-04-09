"""Tenant self-service API — read + edit access for a tenant to manage their policies.

Uses the request.state.tenant_id set by ShieldMiddleware (resolved from API key).
Tenants can view and update their own guardrail policies. They cannot modify
RBAC, quota, plan, or API keys — those are admin-only.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from storage.tenant_store import get_tenant, update_tenant, set_tenant_policies, _get_redis
from storage.tenant_models import GuardrailPolicy, KNOWN_GUARDRAIL_NAMES
from storage.rate_limiter import get_usage
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/tenant", tags=["tenant-self"])


class TenantSelfUpdateRequest(BaseModel):
    """Fields a tenant is allowed to modify on their own config."""
    input_guardrails: Optional[dict[str, GuardrailPolicy]] = None
    output_guardrails: Optional[dict[str, GuardrailPolicy]] = None


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
    """Return the tenant's current input + output guardrail policies (full detail)."""
    tenant_id = _require_tenant(request)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {
        "tenant_id": tenant_id,
        "input_guardrails": config.get("input_guardrails", {}),
        "output_guardrails": config.get("output_guardrails", {}),
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

    for section in ("input_guardrails", "output_guardrails"):
        guardrails = updates.get(section, {})
        unknown = set(guardrails.keys()) - KNOWN_GUARDRAIL_NAMES
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown guardrail(s) in {section}: {', '.join(sorted(unknown))}. "
                       f"Valid names: {', '.join(sorted(KNOWN_GUARDRAIL_NAMES))}",
            )

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
