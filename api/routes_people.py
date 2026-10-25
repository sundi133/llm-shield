"""People in a workspace (docs/specs/password-sign-in.md, task 3). Admin plane only.

GET    /v1/tenant/me/people                         members, their role and status
POST   /v1/tenant/me/people                         invite {email, name?, role}
POST   /v1/tenant/me/people/{email_hash}/resend     a new invite link; the old one stops working
PUT    /v1/tenant/me/people/{email_hash}            {role}
DELETE /v1/tenant/me/people/{email_hash}            remove; their sessions here end
GET    /v1/tenant/me/sign-in-methods                what this workspace accepts
PUT    /v1/tenant/me/sign-in-methods                {passwords: true|false}

An invitee chooses their own password from an emailed link (7 days); nobody
sees anyone else's password. Where the workspace does not accept passwords,
the email says to sign in with an emailed link instead. A workspace keeps at
least one admin. Writes go through the registry write gate, which also
refuses a viewer who signed in with Shield's own sign-in, in every mode.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Request

from core import email_resend
from storage import signup_store as members
from storage import user_accounts as accounts

router = APIRouter(prefix="/v1/tenant/me", tags=["tenant-people"])
logger = logging.getLogger("votal.people")

ROLES = ("admin", "viewer")
MAX_MEMBERS = 200


def _tenant(request: Request) -> str:
    from api.routes_tenant_self import _require_tenant
    return _require_tenant(request)


def _write(request: Request, tenant_id: str, action: str) -> None:
    from core.auth import require_registry_write
    require_registry_write(request, tenant_id, action)


def _actor(request: Request, tenant_id: str) -> str:
    from api.routes_tenant_self import _actor as actor
    return actor(request, tenant_id)


def _audit(request: Request, tenant_id: str, action: str, **meta) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=_actor(request, tenant_id), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", metadata=meta)
    except Exception:       # noqa: BLE001 - the action happened; the audit is best effort
        pass


def _workspace(tenant_id: str) -> dict:
    from storage.tenant_store import get_tenant
    t = get_tenant(tenant_id)
    if not t:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return t


def _passwords_here(tenant_id: str, t: Optional[dict] = None) -> bool:
    """Whether people of this workspace can sign in with a password."""
    from api.routes_password_auth import enabled
    from api.routes_tenant_self import _require_sso_enabled
    t = t if t is not None else _workspace(tenant_id)
    return enabled() and not _require_sso_enabled(tenant_id) and t.get("password_sign_in", True) is not False


def _member(tenant_id: str, eh: str) -> dict:
    m = members.get_member(tenant_id, eh)
    if not m:
        raise HTTPException(status_code=404, detail="No such person in this workspace")
    return m


def _admins(tenant_id: str) -> list[dict]:
    return [m for m in members.members_of(tenant_id) if m.get("role") == "admin"]


def _row(m: dict) -> dict:
    acct = accounts.get_account(m.get("email", "")) or {}
    return {"email_hash": m["email_hash"], "email": m.get("email", ""), "name": m.get("name", ""),
            "role": m.get("role", ""), "status": m.get("status", "active"),
            "invited_by": m.get("invited_by", ""), "added_at": m.get("created_at"),
            "has_password": bool(acct.get("password")), "last_sign_in": acct.get("last_sign_in")}


def _email_ready() -> str:
    from api.routes_portal_auth import portal_base_url
    if not email_resend.configured():
        return "email is not configured (RESEND_API_KEY, SHIELD_SIGNUP_FROM)"
    if not portal_base_url():
        return "SHIELD_PORTAL_BASE_URL is not set"
    return ""


def _kill_invite(m: dict) -> None:
    """End a member's pending invite link, if any."""
    h = m.get("invite_link")
    if h:
        members._take(f"pwdlink:{h}")


async def _send_invite(request: Request, tenant_id: str, t: dict, m: dict) -> None:
    """Email an invite and remember its link, so a resend can end it."""
    from api.routes_portal_auth import portal_base_url
    from api.routes_signup import _email
    name = t.get("name") or tenant_id
    who = _actor(request, tenant_id)
    if _passwords_here(tenant_id, t):
        token = accounts.new_link(m["email"], purpose="invite", tenant_id=tenant_id)
        members.update_member(tenant_id, m["email_hash"], invite_link=members.token_hash(token))
        link = f"{portal_base_url()}/v1/tenant/auth/password/set?token={token}"
        text, page = _email(f"You are invited to {name} on Votal Shield",
                            f"You have been added to the workspace \"{name}\" as "
                            f"{'an admin' if m['role'] == 'admin' else 'a viewer'}. Choose a "
                            "password to sign in. The link works once, for 7 days.",
                            link, "Choose a password")
    else:
        link = f"{portal_base_url()}/tenant"
        text, page = _email(f"You are invited to {name} on Votal Shield",
                            f"You have been added to the workspace \"{name}\". Sign in with "
                            "your organisation's SSO, or ask for an emailed sign-in link.",
                            link, "Sign in")
    await email_resend.send(m["email"], f"You are invited to {name} on Votal Shield", text, page)
    logger.info("invite sent: tenant=%s by=%s", tenant_id, who)


# ── read ─────────────────────────────────────────────────────────────


@router.get("/people")
async def list_people(request: Request):
    tid = _tenant(request)
    t = _workspace(tid)
    rows = [_row(m) for m in members.members_of(tid)]
    return {"tenant_id": tid, "people": rows, "count": len(rows), "roles": list(ROLES),
            "passwords_available": _passwords_here(tid, t),
            "invites_available": not _email_ready()}


@router.get("/sign-in-methods")
async def sign_in_methods(request: Request):
    from api.routes_password_auth import enabled
    from api.routes_tenant_self import _require_sso_enabled
    tid = _tenant(request)
    t = _workspace(tid)
    return {"passwords": t.get("password_sign_in", True) is not False,
            "passwords_available": _passwords_here(tid, t),
            "deployment_allows_passwords": enabled(),
            "require_sso": _require_sso_enabled(tid)}


# ── write ────────────────────────────────────────────────────────────


@router.post("/people")
async def invite(request: Request, body: dict = Body(...)):
    from api.routes_tenant_self import _reject_tenant_id_spoof
    await _reject_tenant_id_spoof(request, body if isinstance(body, dict) else None)
    tid = _tenant(request)
    _write(request, tid, "invite people")
    t = _workspace(tid)
    email = members.normalize_email(str(body.get("email") or ""))
    from api.routes_signup import _EMAIL_RE
    if len(email) > 254 or not _EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    role = body.get("role") or "viewer"
    if role not in ROLES:
        raise HTTPException(status_code=422, detail="role: admin or viewer")
    name = str(body.get("name") or "").strip()[:100]
    from api.routes_tenant_self import _require_sso_enabled
    if _require_sso_enabled(tid):
        raise HTTPException(status_code=409, detail="This workspace signs in with SSO only. "
                                                    "Add people in your identity provider.")
    reason = _email_ready()
    if reason:
        raise HTTPException(status_code=503, detail=f"Invites need email: {reason}.")
    eh = members.email_hash(email)
    if members.get_member(tid, eh):
        raise HTTPException(status_code=409, detail="That person is already a member.")
    if len(members.members_of(tid)) >= MAX_MEMBERS:
        raise HTTPException(status_code=409, detail=f"A workspace has at most {MAX_MEMBERS} people.")
    members.add_member(tid, email, role, name=name, invited_by=_actor(request, tid), status="invited")
    m = members.get_member(tid, eh)
    try:
        await _send_invite(request, tid, t, m)
    except email_resend.EmailError:
        members.remove_member(tid, eh)            # keep nothing we could not tell them about
        raise HTTPException(status_code=503, detail="We could not send the invite. Try again in a minute.")
    _audit(request, tid, "tenant_person_invite", email_hash=eh, role=role)
    return {"invited": True, "person": _row(members.get_member(tid, eh))}


@router.post("/people/{eh}/resend")
async def resend(eh: str, request: Request):
    tid = _tenant(request)
    m = _member(tid, eh)
    _write(request, tid, "resend an invite")
    if m.get("status", "active") != "invited":
        raise HTTPException(status_code=409, detail="That person has already joined.")
    reason = _email_ready()
    if reason:
        raise HTTPException(status_code=503, detail=f"Invites need email: {reason}.")
    _kill_invite(m)
    try:
        await _send_invite(request, tid, _workspace(tid), m)
    except email_resend.EmailError:
        raise HTTPException(status_code=503, detail="We could not send the invite. Try again in a minute.")
    _audit(request, tid, "tenant_person_invite_resend", email_hash=eh)
    return {"resent": True}


@router.put("/people/{eh}")
async def change_role(eh: str, request: Request, body: dict = Body(...)):
    tid = _tenant(request)
    m = _member(tid, eh)
    _write(request, tid, "change a person's role")
    role = body.get("role")
    if role not in ROLES:
        raise HTTPException(status_code=422, detail="role: admin or viewer")
    if m.get("role") == "admin" and role != "admin" and len(_admins(tid)) <= 1:
        raise HTTPException(status_code=409, detail="A workspace needs at least one admin. "
                                                    "Make someone else an admin first.")
    members.update_member(tid, eh, role=role)
    # A role is read when a session starts: end this person's sessions here so
    # the new role applies at their next sign-in, not whenever theirs expires.
    from storage.portal_sessions import revoke_all_for_subject
    ended = revoke_all_for_subject(tid, f"email:{eh}")
    _audit(request, tid, "tenant_person_role", email_hash=eh, role=role, sessions_ended=ended)
    return {"person": _row(members.get_member(tid, eh))}


@router.delete("/people/{eh}")
async def remove(eh: str, request: Request):
    tid = _tenant(request)
    m = _member(tid, eh)
    _write(request, tid, "remove a person")
    if m.get("role") == "admin" and len(_admins(tid)) <= 1:
        raise HTTPException(status_code=409, detail="A workspace needs at least one admin.")
    _kill_invite(m)
    members.remove_member(tid, eh)
    from storage.portal_sessions import revoke_all_for_subject
    ended = revoke_all_for_subject(tid, f"email:{eh}")
    _audit(request, tid, "tenant_person_remove", email_hash=eh, sessions_ended=ended)
    return {"removed": True, "sessions_ended": ended}


@router.put("/sign-in-methods")
async def set_sign_in_methods(request: Request, body: dict = Body(...)):
    tid = _tenant(request)
    _write(request, tid, "change sign-in methods")
    v = body.get("passwords")
    if not isinstance(v, bool):
        raise HTTPException(status_code=422, detail="passwords: true or false")
    from storage.tenant_store import update_tenant
    _workspace(tid)
    update_tenant(tid, {"password_sign_in": v})
    _audit(request, tid, "tenant_sign_in_methods", passwords=v)
    return await sign_in_methods(request)
