"""Edge fast-path policy bundle (Task 1 of the edge fast-path spec).

Serves a read-only, tenant-scoped bundle of *rules* (regex + blocklists) that an
on-device/edge client (the browser extension) caches and runs locally to block or
redact obvious sensitive data BEFORE a prompt leaves the device — escalating
ambiguous cases to the authoritative server check (`/guardrails/input`).

Edge blocks the obvious; the server stays the source of truth. This endpoint
ships **patterns only, never secrets**. It is read-only and off the guard path
(no impact to cap/mint / tools/call).
"""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Depends, Request, Response

from core.auth import get_tenant_from_request
from api.routes_data_policies import _load_all

router = APIRouter(prefix="/v1/edge", tags=["edge"])


def _build_bundle(tenant_id: str) -> dict:
    """Aggregate the tenant's regex sanitization rules + keyword blocklists into
    a flat, edge-runnable bundle with a content version (for ETag caching)."""
    policies = _load_all(tenant_id) or {}
    rules: list[dict] = []
    seen: set[str] = set()
    for _tool, p in policies.items():
        for r in (p.get("sanitization_rules") or []):
            if not r.get("enabled", True):
                continue
            rx = r.get("regex")
            if not rx or rx in seen:
                continue
            seen.add(rx)
            sev = r.get("severity", "medium")
            # critical always blocks; otherwise honor explicit action or default to redact
            action = r.get("action") or ("block" if sev == "critical" else "redact")
            rules.append({
                "id": r.get("pattern_id", ""),
                "regex": rx,
                "action": action,
                "severity": sev,
                "replacement": r.get("replacement", "[REDACTED]"),
            })

    blocklists: list[str] = []
    try:
        from storage.tenant_store import get_tenant
        cfg = get_tenant(tenant_id) or {}
        ig = cfg.get("input_guardrails") or {}
        kb = ig.get("keyword-blocklist") or ig.get("keyword_blocklist") or {}
        words = kb.get("blocklist") or kb.get("keywords") or []
        blocklists = [w for w in words if isinstance(w, str)]
    except Exception:
        pass

    bundle = {"rules": rules, "blocklists": blocklists}
    version = hashlib.sha256(
        json.dumps(bundle, sort_keys=True).encode()).hexdigest()[:16]
    bundle["version"] = version
    return bundle


@router.get("/policy-bundle")
async def policy_bundle(
    request: Request,
    response: Response,
    tenant_id: str = Depends(get_tenant_from_request),
):
    """Return the tenant's edge rule bundle. Supports ETag / If-None-Match so the
    edge can poll cheaply (304 when unchanged)."""
    bundle = _build_bundle(tenant_id)
    etag = f'"{bundle["version"]}"'
    if (request.headers.get("if-none-match") or "").strip() == etag:
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"
    return {"tenant_id": tenant_id, **bundle}
