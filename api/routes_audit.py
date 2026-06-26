"""Audit log query routes for LLM Shield."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from core.auth import _extract_api_key, _validate_key
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield", tags=["audit"])


def _resolve_audit_scope(request: Request) -> Optional[str]:
    """Resolve which tenant's audit log the caller is authorized to read.

    Closes a cross-tenant disclosure (QA auth-008): the audit log is keyed
    by ``audit:{tenant_id}`` (+ ``audit:global``), but these routes used to
    query global scope for any caller. Scoping rules:

    - **Tenant-scoped key** (``request.state.tenant_id`` set by the auth
      middleware) -> that tenant only; a client-supplied ``tenant_id`` is
      ignored so a tenant key can never read another tenant or global.
    - **Master / global key** (valid against ``cfg.auth.api_keys``, no tenant
      bound) -> ``None`` here, meaning the caller may read global / any tenant
      (preserves the admin-portal cross-tenant view).
    - **Otherwise** -> 401.

    When auth is disabled or unconfigured the deployment is a trusted/dev
    environment and global scope is allowed (preserves prior local behavior).
    """
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
    if tenant_id:
        return tenant_id

    import config.schema as _cfg

    cfg = getattr(_cfg, "config", None)
    if cfg is None or not getattr(cfg.auth, "enabled", False) or not cfg.auth.api_keys:
        # Auth disabled/misconfigured -> trusted environment, global allowed.
        return None

    api_key = _extract_api_key(request)
    if api_key and _validate_key(api_key, cfg.auth.api_keys):
        return None  # master/global key -> may read global / any tenant

    raise HTTPException(
        status_code=401, detail="Authentication required to read audit logs."
    )


@router.get("/audit")
async def query_audit_logs(
    request: Request,
    agent_key: Optional[str] = Query(None, description="Filter by agent key"),
    action: Optional[str] = Query(
        None, description="Filter by action (pass/block/warn)"
    ),
    since: Optional[str] = Query(None, description="Filter entries since ISO datetime"),
    until: Optional[str] = Query(None, description="Filter entries until ISO datetime"),
    tenant_id: Optional[str] = Query(
        None,
        description="Master keys only: read a specific tenant's log. Ignored for tenant-scoped keys.",
    ),
    limit: int = Query(100, ge=1, le=1000, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """Query audit logs with optional filters (scoped to the caller's tenant)."""
    scope = _resolve_audit_scope(request)
    # Tenant keys are pinned to their own scope; master keys may target a
    # specific tenant via the query param, else read global.
    effective_tenant = scope if scope is not None else tenant_id

    filters = {}
    if agent_key:
        filters["agent_key"] = agent_key
    if action:
        filters["action_taken"] = action
    if since:
        filters["since"] = since
    if until:
        filters["until"] = until

    results = await audit_logger.query(
        filters=filters if filters else None,
        limit=limit,
        offset=offset,
        tenant_id=effective_tenant,
    )
    return {"entries": results, "count": len(results), "limit": limit, "offset": offset}


@router.get("/stats")
async def get_stats(
    request: Request,
    since: Optional[str] = Query(None, description="Stats since ISO datetime"),
    tenant_id: Optional[str] = Query(
        None,
        description="Master keys only: stats for a specific tenant. Ignored for tenant-scoped keys.",
    ),
):
    """Get aggregated statistics from the audit log (scoped to the caller's tenant).

    Returns: requests count, block rate, top triggered guardrails, avg latency.
    """
    scope = _resolve_audit_scope(request)
    effective_tenant = scope if scope is not None else tenant_id

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            since_dt = None

    stats = await audit_logger.get_stats(since=since_dt, tenant_id=effective_tenant)
    return stats
