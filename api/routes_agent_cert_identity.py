"""Certificate-based agent identity: management for the tenant.

Spec: docs/specs/agent-cert-identity.md (tasks 2, 3 and 5). Mounted on both
planes (the portal calls the admin plane); writes go through the registry
write gate and the admin audit. The verification itself runs on the guard
path, in core/mtls_middleware.py through core/cert_identity.py.

  GET    /v1/tenant/me/agent-identity/status
  GET    /v1/tenant/me/agent-identity/certs            registered certificates, expiry, last seen
  GET    /v1/tenant/me/agent-identity/anchors          trust anchors (the tenant's CAs)
  POST   /v1/tenant/me/agent-identity/anchors          {name, pem}
  DELETE /v1/tenant/me/agent-identity/anchors/{id}
  GET    /v1/tenant/me/agent-identity/rules
  PUT    /v1/tenant/me/agent-identity/rules            {rules: [{match, pattern, agent_id?}]}
  POST   /v1/tenant/me/agent-identity/test             {cert_pem, chain_pem?}
  GET    /v1/tenant/me/agent-identity/crls
  PUT    /v1/tenant/me/agent-identity/crls/{anchor_id} {pem, stale}
  DELETE /v1/tenant/me/agent-identity/crls/{anchor_id}
"""

from __future__ import annotations

import os
import time

from fastapi import APIRouter, Body, HTTPException, Request

from core import cert_identity as ci
from core.auth import get_tenant_from_request, require_registry_write

router = APIRouter(prefix="/v1/tenant/me/agent-identity", tags=["agent-identity"])

CERTS_PAGE_MAX = 500


def _http(e: ci.CertError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=str(e))


def _actor(request: Request, tenant_id: str) -> str:
    try:
        from core.auth import portal_principal
        principal = portal_principal(request)
    except Exception:
        principal = None
    if principal:
        return f"user:{principal.get('email') or principal.get('sub') or '?'}"
    return f"tenant:{tenant_id}"


def _audit(request: Request, action: str, tenant_id: str, metadata: dict) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=_actor(request, tenant_id), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", metadata=metadata)
    except Exception:
        pass


def _on(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


@router.get("/status")
async def identity_status(request: Request):
    """How certificate identity is configured on this Shield, for the portal's
    warnings: without the trusted-proxy boundary a forwarded certificate is a
    header anyone can send."""
    tenant_id = get_tenant_from_request(request)
    from core.feature_flags import CERT_IDENTITY_ENABLED
    from core.proxy_trust import trusted_proxy_only
    return {
        "tenant_id": tenant_id,
        "trusted_proxy_only": trusted_proxy_only(),
        "proxy_secret_set": bool(os.environ.get("SHIELD_TRUSTED_PROXY_SECRET", "").strip()),
        "mtls_enabled": _on("SHIELD_MTLS_ENABLED"),
        "cert_identity_header": bool(CERT_IDENTITY_ENABLED),
        "trust_header_escape_hatch": _on("SHIELD_CERT_IDENTITY_TRUST_HEADER"),
        "agent_token_pop": os.environ.get("SHIELD_AGENT_TOKEN_POP", "off").strip().lower() or "off",
        "anchors": len(ci.list_anchors(tenant_id)),
        "rules": len(ci.get_rules(tenant_id)),
    }


@router.get("/certs")
async def list_certs(request: Request):
    """Registered certificates, by agent: expiry, days left, when each was last
    verified and how. ?agent= filters; ?expiring_days=N keeps those expiring
    within N days (expired ones included); ?limit= and ?cursor= page."""
    from guardrails.agentic.identity.cert_registry import list_certs as _list
    tenant_id = get_tenant_from_request(request)
    q = request.query_params
    try:
        limit = int(q.get("limit") or 50)
        offset = int(q.get("cursor") or 0)
        expiring = int(q["expiring_days"]) if q.get("expiring_days") else None
    except ValueError:
        raise HTTPException(status_code=400, detail="limit, cursor and expiring_days: integers")
    if not 1 <= limit <= CERTS_PAGE_MAX or offset < 0:
        raise HTTPException(status_code=400, detail=f"limit: 1 to {CERTS_PAGE_MAX}")
    now = int(time.time())
    seen = ci.last_seen(tenant_id)
    rows = []
    for e in _list(tenant_id):
        if q.get("agent") and e.get("agent_key") != q["agent"]:
            continue
        na = e.get("not_after")
        days = None if not na else (na - now) // 86400
        if expiring is not None and (days is None or days > expiring):
            continue
        rows.append({"fingerprint": e["fingerprint"], "agent_key": e.get("agent_key"),
                     "subject": e.get("subject"), "not_after": na, "days_left": days,
                     "expired": bool(na and na < now),
                     "registered_at": e.get("registered_at"), "registered_by": e.get("registered_by"),
                     "last_seen": seen.get(e["fingerprint"])})
    page = rows[offset:offset + limit]
    nxt = offset + limit if offset + limit < len(rows) else None
    return {"tenant_id": tenant_id, "total": len(rows), "certs": page,
            "next_cursor": None if nxt is None else str(nxt)}


@router.get("/anchors")
async def get_anchors(request: Request):
    tenant_id = get_tenant_from_request(request)
    crls = ci.get_crls(tenant_id)
    now = int(time.time())
    return {"tenant_id": tenant_id, "anchors": [
        {**{k: v for k, v in a.items() if k != "pem"},
         "expired": a.get("not_after", 0) < now,
         "crl": ({k: v for k, v in crls[a["id"]].items() if k != "revoked"}
                 | {"revoked_count": len(crls[a["id"]].get("revoked") or [])})
         if a.get("id") in crls else None}
        for a in ci.list_anchors(tenant_id)]}


@router.post("/anchors")
async def add_anchor(request: Request, body: dict = Body(...)):
    """Trust a CA: any certificate it issues can identify an agent, through a
    mapping rule. A privilege: admin-gated and audited."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "add a certificate trust anchor")
    try:
        out = ci.add_anchor(tenant_id, body.get("name") or "", body.get("pem") or "",
                            added_by=_actor(request, tenant_id))
    except ci.CertError as e:
        raise _http(e)
    _audit(request, "tenant_add_cert_anchor", tenant_id,
           {"anchor_id": out["id"], "subject": out["subject"], "fingerprint": out["fingerprint"]})
    return {"tenant_id": tenant_id, "anchor": out}


@router.delete("/anchors/{anchor_id}")
async def delete_anchor(anchor_id: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "remove a certificate trust anchor")
    if not ci.remove_anchor(tenant_id, anchor_id):
        raise HTTPException(status_code=404, detail="no such trust anchor")
    _audit(request, "tenant_remove_cert_anchor", tenant_id, {"anchor_id": anchor_id})
    return {"tenant_id": tenant_id, "anchor_id": anchor_id, "removed": True}


@router.get("/rules")
async def get_rules(request: Request):
    tenant_id = get_tenant_from_request(request)
    return {"tenant_id": tenant_id, "rules": ci.get_rules(tenant_id),
            "matches": list(ci.RULE_MATCHES)}


@router.put("/rules")
async def put_rules(request: Request, body: dict = Body(...)):
    """Replace the mapping rules. First match wins. A rule maps only to a
    registered agent."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "change certificate mapping rules")
    try:
        rules = ci.put_rules(tenant_id, body.get("rules"))
    except ci.CertError as e:
        raise _http(e)
    _audit(request, "tenant_put_cert_rules", tenant_id, {"rules": len(rules)})
    return {"tenant_id": tenant_id, "rules": rules}


@router.post("/test")
async def test_certificate(request: Request, body: dict = Body(...)):
    """Which anchor a certificate chains to, which rule maps it, which agent it
    identifies, or why not. Changes nothing."""
    tenant_id = get_tenant_from_request(request)
    chain_pem = body.get("chain_pem") or ""
    chain = ci._split_pems(chain_pem) if isinstance(chain_pem, str) else []
    try:
        out = ci.explain(tenant_id, body.get("cert_pem") or "", chain)
    except ci.CertError as e:
        raise _http(e)
    return {"tenant_id": tenant_id, **out}


@router.get("/crls")
async def get_crls(request: Request):
    tenant_id = get_tenant_from_request(request)
    now = int(time.time())
    return {"tenant_id": tenant_id, "crls": {
        aid: {k: v for k, v in c.items() if k != "revoked"}
        | {"revoked_count": len(c.get("revoked") or []),
           "stale_now": bool(c.get("next_update") and c["next_update"] < now)}
        for aid, c in ci.get_crls(tenant_id).items()}}


@router.put("/crls/{anchor_id}")
async def put_crl(anchor_id: str, request: Request, body: dict = Body(...)):
    """Load the revocation list one anchor issued. `stale`: fail_closed
    (default: certificates from this anchor are refused once the CRL is past its
    next update) or fail_open (accepted, and the portal warns)."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "load a certificate revocation list")
    try:
        out = ci.put_crl(tenant_id, anchor_id, body.get("pem"), body.get("stale") or "fail_closed",
                         added_by=_actor(request, tenant_id))
    except ci.CertError as e:
        raise _http(e)
    _audit(request, "tenant_put_cert_crl", tenant_id,
           {"anchor_id": anchor_id, "revoked": out["revoked_count"], "stale": out["stale"]})
    return {"tenant_id": tenant_id, "crl": out}


@router.delete("/crls/{anchor_id}")
async def delete_crl(anchor_id: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "remove a certificate revocation list")
    if not ci.remove_crl(tenant_id, anchor_id):
        raise HTTPException(status_code=404, detail="no revocation list for this anchor")
    _audit(request, "tenant_remove_cert_crl", tenant_id, {"anchor_id": anchor_id})
    return {"tenant_id": tenant_id, "anchor_id": anchor_id, "removed": True}
