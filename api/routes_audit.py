"""Audit log query routes for LLM Shield."""

import hmac
import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from core.auth import _extract_api_key, _validate_key
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield", tags=["audit"])


def _is_admin_or_master(request: Request) -> bool:
    """True if the caller presents a valid master API key or the admin key.

    This is the identity required to read GLOBAL (all-tenant) audit data. It is
    checked independently of whether the global auth middleware is enabled,
    because a multi-tenant audit log must never be served to an unidentified
    caller — even on a pod where Shield auth is delegated to an upstream proxy
    (e.g. RunPod). See QA auth-008.
    """
    # Master/global API key (X-API-Key / Bearer) validated against config.
    import config.schema as _cfg

    cfg = getattr(_cfg, "config", None)
    api_key = _extract_api_key(request)
    if cfg is not None and getattr(cfg, "auth", None) and cfg.auth.api_keys:
        if api_key and _validate_key(api_key, cfg.auth.api_keys):
            return True

    # Admin key (X-Admin-Key) matched against SHIELD_ADMIN_KEY, same as /admin.
    admin_key = os.environ.get("SHIELD_ADMIN_KEY", "")
    provided = request.headers.get("X-Admin-Key", "").strip()
    if admin_key and provided and hmac.compare_digest(provided, admin_key):
        return True

    return False


def _resolve_audit_scope(request: Request) -> Optional[str]:
    """Resolve which tenant's audit log the caller is authorized to read.

    Closes a cross-tenant disclosure (QA auth-008): the audit log is keyed
    by ``audit:{tenant_id}`` (+ ``audit:global``), but these routes used to
    query global scope for any caller. Scoping rules:

    - **Tenant-scoped key** (``request.state.tenant_id`` set by the auth
      middleware) -> that tenant only; a client-supplied ``tenant_id`` is
      ignored so a tenant key can never read another tenant or global.
    - **No tenant context** -> the caller is asking for GLOBAL data, which is
      allowed ONLY with a valid master or admin key (see ``_is_admin_or_master``).
      This holds even when the global auth middleware is disabled, so a pod that
      delegates auth to an upstream proxy still can't serve all-tenant audit to
      an unidentified caller.
    - **Otherwise** -> 401.
    """
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
    if tenant_id:
        return tenant_id

    if _is_admin_or_master(request):
        return None  # master/admin -> may read global / any tenant

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
