"""The operator's side of self-serve sign-up (docs/specs/self-serve-signup.md, task 5).
Admin plane, behind the /v1/admin gate (admin SSO session or admin key).

GET  /v1/admin/signups                      self-serve workspaces, newest first
GET  /v1/admin/signups/settings             what is configured, today's count, the limits in force
PUT  /v1/admin/signups/settings             pause or resume; trial limits and mode as overrides
POST /v1/admin/signups/{tenant_id}/suspend  its keys and sign-ins stop; its people are signed out
POST /v1/admin/signups/{tenant_id}/resume
POST /v1/admin/signups/{tenant_id}/convert  {"plan": "basic|pro|enterprise"}: no longer a trial

SHIELD_PORTAL_BASE_URL, RESEND_API_KEY and HCAPTCHA_SECRET_KEY are never set
here: an editable base URL would let one stolen admin session send every
sign-up and SSO link, with its one-time token, to another domain. The
settings view says only whether each is set.
"""

from __future__ import annotations

import os
import time
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request

import api.routes_signup as signup
from core.auth import require_admin_scope
from core.signup import trial
from storage import signup_store as store

router = APIRouter(prefix="/v1/admin/signups", tags=["signup-admin"])

PLANS = ("basic", "pro", "enterprise")


def _actor(request: Request) -> str:
    try:
        from api.routes_tenant import _actor_from_request
        return _actor_from_request(request)
    except Exception:       # noqa: BLE001
        return "admin"


def _audit(request: Request, action: str, tenant_id: str = "", **after) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=_actor(request), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", after=after)
    except Exception:       # noqa: BLE001 - the action happened; the audit is best effort
        pass


def _self_serve(tenant_id: str) -> dict:
    from storage.tenant_store import get_tenant
    t = get_tenant(tenant_id)
    if not t or not isinstance(t.get("trial"), dict) or \
            t["trial"].get("created_via") != "self_signup":
        raise HTTPException(status_code=404, detail="no self-serve workspace with that id")
    return t


@router.get("")
async def list_signups(request: Request, limit: int = Query(100, ge=1, le=500),
                       cursor: str = Query("")):
    require_admin_scope(request, "tenants:read", cross_tenant=True)
    from storage.tenant_store import get_tenant, list_tenants
    try:
        offset = int(cursor) if cursor else 0
    except ValueError:
        raise HTTPException(status_code=422, detail="cursor: the next_cursor of a previous page")
    rows = []
    for summary in list_tenants():
        if summary.get("plan") != "trial":
            continue
        t = get_tenant(summary["tenant_id"]) or {}
        tr = t.get("trial") if isinstance(t.get("trial"), dict) else {}
        if tr.get("created_via") != "self_signup":
            continue
        members = store.members_of(summary["tenant_id"])
        rows.append({"tenant_id": summary["tenant_id"], "name": t.get("name", ""),
                     "email_domain": tr.get("email_domain", ""),
                     "admin_email": next((m.get("email") for m in members
                                          if m.get("role") == "admin"), ""),
                     "created_at": t.get("created_at", ""), "expires_at": tr.get("expires_at"),
                     "status": trial.status(t), "policy_mode": t.get("policy_mode", "")})
    rows.sort(key=lambda r: r["created_at"] or "", reverse=True)
    page = rows[offset:offset + limit]
    return {"signups": page, "total": len(rows),
            "next_cursor": str(offset + limit) if offset + limit < len(rows) else ""}


def _settings_view() -> dict:
    from api.routes_portal_auth import portal_base_url
    o = store.get_settings()
    return {
        "mode": "open" if signup.is_open() else "off",
        "paused": o.get("paused") is True,
        "available": signup.is_open() and not signup.email_unavailable_reason()
                     and o.get("paused") is not True,
        "configured": {
            "SHIELD_SELF_SIGNUP": signup.is_open(),
            "SHIELD_PORTAL_BASE_URL": bool(portal_base_url()),
            "RESEND_API_KEY": bool(os.environ.get("RESEND_API_KEY", "").strip()),
            "SHIELD_SIGNUP_FROM": bool(os.environ.get("SHIELD_SIGNUP_FROM", "").strip()),
            "HCAPTCHA_SITE_KEY": bool(os.environ.get("HCAPTCHA_SITE_KEY", "").strip()),
            "HCAPTCHA_SECRET_KEY": bool(os.environ.get("HCAPTCHA_SECRET_KEY", "").strip()),
        },
        "unavailable_reason": signup.email_unavailable_reason(),
        "today": {"new_workspaces": store.count("all")},
        "in_force": {**{name: signup.limit(name, o) for name in signup.LIMITS},
                     "trial_mode": signup.trial_mode(o)},
        "overrides": o,
    }


@router.get("/settings")
async def get_settings(request: Request):
    require_admin_scope(request, "tenants:read", cross_tenant=True)
    return _settings_view()


@router.put("/settings")
async def put_settings(request: Request, body: dict = Body(...)):
    """Fields: paused (bool), trial_mode (enforce|monitor), and the integers in
    LIMITS. null clears an override, so the env value applies again."""
    require_admin_scope(request, "tenants:write", cross_tenant=True)
    allowed = set(signup.LIMITS) | {"paused", "trial_mode"}
    unknown = set(body) - allowed
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown settings: {sorted(unknown)}")
    current = dict(store.get_settings())
    errors = []
    for k, v in body.items():
        if v is None:
            current.pop(k, None)
        elif k == "paused":
            if not isinstance(v, bool):
                errors.append("paused: true or false")
            else:
                current[k] = v
        elif k == "trial_mode":
            if v not in signup.TRIAL_MODES:
                errors.append("trial_mode: enforce or monitor")
            else:
                current[k] = v
        else:
            _, _, lo, hi = signup.LIMITS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                errors.append(f"{k}: a whole number from {lo} to {hi}")
            else:
                current[k] = v
    if errors:
        raise HTTPException(status_code=422, detail={"message": "Not saved.", "errors": errors})
    store.save_settings(current)
    _audit(request, "signup_settings", **{k: body[k] for k in body})
    return _settings_view()


def _sign_out_members(tenant_id: str) -> int:
    from storage.portal_sessions import revoke_all_for_subject
    return sum(revoke_all_for_subject(tenant_id, "email:" + m["email_hash"])
               for m in store.members_of(tenant_id))


@router.post("/{tenant_id}/suspend")
async def suspend(tenant_id: str, request: Request, body: Optional[dict] = Body(None)):
    require_admin_scope(request, "tenants:write", tenant_id)
    t = _self_serve(tenant_id)
    from storage.tenant_store import update_tenant
    reason = str((body or {}).get("reason") or "")[:200]
    update_tenant(tenant_id, {"trial": {**t["trial"], "suspended_at": int(time.time()),
                                        "suspended_reason": reason}})
    signed_out = _sign_out_members(tenant_id)
    _audit(request, "signup_suspend", tenant_id, reason=reason, signed_out=signed_out)
    return {"tenant_id": tenant_id, "status": trial.SUSPENDED, "signed_out": signed_out}


@router.post("/{tenant_id}/resume")
async def resume(tenant_id: str, request: Request):
    require_admin_scope(request, "tenants:write", tenant_id)
    t = _self_serve(tenant_id)
    from storage.tenant_store import get_tenant, update_tenant
    tr = {k: v for k, v in t["trial"].items() if k not in ("suspended_at", "suspended_reason")}
    update_tenant(tenant_id, {"trial": tr})
    _audit(request, "signup_resume", tenant_id)
    return {"tenant_id": tenant_id, "status": trial.status(get_tenant(tenant_id))}


@router.post("/{tenant_id}/convert")
async def convert(tenant_id: str, request: Request, body: dict = Body(...)):
    """A paying customer: the plan's quotas, no expiry, no trial record. The
    policy, its mode, the keys and the members are kept."""
    require_admin_scope(request, "tenants:write", tenant_id)
    plan = body.get("plan")
    if plan not in PLANS:
        raise HTTPException(status_code=422, detail=f"plan: one of {', '.join(PLANS)}")
    t = _self_serve(tenant_id)
    from storage.tenant_models import _PLAN_QUOTA_DEFAULTS
    from storage.tenant_store import update_tenant
    converted = {**t["trial"], "converted_at": int(time.time()), "converted_to": plan}
    update_tenant(tenant_id, {"plan": plan, "quota": dict(_PLAN_QUOTA_DEFAULTS[plan]),
                              "trial": None, "converted_from_trial": converted})
    _audit(request, "signup_convert", tenant_id, plan=plan)
    return {"tenant_id": tenant_id, "plan": plan, "status": "converted"}
