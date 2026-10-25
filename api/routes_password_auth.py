"""Password sign-in for the tenant portal (docs/specs/password-sign-in.md,
tasks 1 and 2). Admin plane only.

POST /v1/tenant/auth/password            {email, password, tenant_id?, captcha_token?}
GET  /v1/tenant/auth/password/config     whether passwords are offered, the captcha key
POST /v1/tenant/auth/password/forgot     {email, captcha_token} -> 202, always the same
GET  /v1/tenant/auth/password/set?token= a page to choose a password (consumes nothing)
POST /v1/tenant/auth/password/set        set it, end every other session, sign in
POST /v1/tenant/me/password              {current_password, new_password}

A wrong email and a wrong password get the same answer in the same time. A
password is offered only for a workspace that allows it: not under
require_sso, not with passwords switched off for the workspace or the
deployment (SHIELD_PORTAL_PASSWORDS=off), not for a suspended trial.
Sessions are the portal's own, with the subject the emailed link uses
(email:{hash}), so ending a person's sessions covers both ways in.
"""

from __future__ import annotations

import html
import logging
import os
import secrets

from fastapi import APIRouter, Body, Form, HTTPException, Request
from fastapi.responses import JSONResponse

import api.routes_signup as signup
from api.routes_signup import _email, email_unavailable_reason, expired_page, nonce_ok, not_from_this_page
from core import email_resend
from storage import signup_store as members
from storage import user_accounts as accounts

router = APIRouter(tags=["portal-auth"])
logger = logging.getLogger("votal.password_auth")

ISSUER = "votal-password"
NONCE_COOKIE = "shield_pwd_nonce"
COOKIE_PATH = "/v1/tenant/auth/password"
WRONG = "Email or password is incorrect"
SENT = {"status": "check_your_email",
        "message": "If that address can sign in with a password, we have sent it a link. "
                   "It works once, for 30 minutes."}


def enabled() -> bool:
    return (os.environ.get("SHIELD_PORTAL_PASSWORDS", "on") or "on").strip().lower() \
        not in ("off", "0", "false", "no")


def _require_enabled() -> None:
    if not enabled():
        raise HTTPException(status_code=404, detail="Not Found")


def workspaces(email: str) -> list[tuple[str, str, str]]:
    """(tenant_id, name, role) this email may sign in to with a password: the
    email-link rules (member, no require_sso, not suspended) plus the
    workspace's own password setting."""
    from api.routes_email_link import _reachable_workspaces
    from storage.tenant_store import get_tenant
    out = []
    for tid, name, role in _reachable_workspaces(email):
        if (get_tenant(tid) or {}).get("password_sign_in", True) is False:
            continue
        out.append((tid, name, role))
    return out


def _audit(action: str, tenant_id: str = "", ip: str = "", **meta) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=meta.pop("actor", "password-sign-in"),
                         tenant_id=tenant_id or None, source_ip=ip, metadata=meta)
    except Exception:       # noqa: BLE001 - audit is best effort here
        pass


def _session(tenant_id: str, email: str, role: str):
    """(session id, cookie kwargs) for a person signed in by password."""
    from api.routes_portal_auth import COOKIE_NAME, _cookie_secure
    from storage.portal_sessions import create_session, session_ttl
    sid = create_session(tenant_id, {"sub": "email:" + members.email_hash(email),
                                     "email": email, "name": "", "issuer": ISSUER},
                         is_admin=role == "admin")
    return sid, dict(key=COOKIE_NAME, value=sid, max_age=session_ttl(), httponly=True,
                     secure=_cookie_secure(), samesite="lax", path="/")


def _end_sessions(email: str) -> int:
    """Every portal session this person holds, in every workspace."""
    from storage.portal_sessions import revoke_all_for_subject
    sub = "email:" + members.email_hash(email)
    return sum(revoke_all_for_subject(tid, sub) for tid in members.tenants_of(email))


def _link(token: str) -> str:
    from api.routes_portal_auth import portal_base_url
    return f"{portal_base_url()}{COOKIE_PATH}/set?token={token}"


async def _send_reset(email: str, *, locked: bool = False) -> None:
    token = accounts.new_link(email, purpose="reset")
    if locked:
        heading, body = ("Your Votal Shield sign-in was locked",
                         "Someone entered the wrong password for your account several times, "
                         "so password sign-in is paused for a while. If it was you, you can "
                         "choose a new password now. The link works once, for 30 minutes.")
    else:
        heading, body = ("Choose a Votal Shield password",
                         "Choose a new password for your Votal Shield account. "
                         "The link works once, for 30 minutes.")
    text, page = _email(heading, body, _link(token), "Choose a password")
    await email_resend.send(email, heading, text, page)


# ── sign in ──────────────────────────────────────────────────────────


@router.get("/v1/tenant/auth/password/config")
async def password_config():
    return {"enabled": enabled(),
            "reset_available": enabled() and not email_unavailable_reason(),
            "captcha_after_failures": accounts.CAPTCHA_AFTER,
            "captcha_site_key": os.environ.get("HCAPTCHA_SITE_KEY", "") if enabled() else ""}


@router.post("/v1/tenant/auth/password")
async def password_sign_in(request: Request, body: dict = Body(...)):
    _require_enabled()
    from core.auth import _client_ip
    ip = _client_ip(request)
    email = members.normalize_email(str(body.get("email") or ""))
    password = body.get("password")
    if not email or "@" not in email or len(email) > 254 or not isinstance(password, str) \
            or not password or len(password) > 1024:
        raise HTTPException(status_code=422, detail="Enter your email and password.")
    try:
        if accounts.ip_failures(ip) >= accounts.IP_LIMIT:
            raise HTTPException(status_code=429, detail="Too many attempts. Try again in 15 minutes.")
        if accounts.ip_failures(ip) >= accounts.CAPTCHA_AFTER and \
                os.environ.get("HCAPTCHA_SECRET_KEY", "").strip() and \
                not await signup._captcha_ok(str(body.get("captcha_token") or ""), ip):
            return JSONResponse(status_code=403, content={
                "error": "captcha_required", "detail": "Solve the captcha to try again."})

        # A locked account is checked like any other and refused with the
        # same words, so a lockout does not confirm the address has an account.
        ok = accounts.check_password(email, password) and not accounts.is_locked(email)
        if not ok:
            accounts.record_ip_failure(ip)
            locked = accounts.has_password(email) and not accounts.is_locked(email) \
                and accounts.record_failure(email)
            _audit("password_sign_in_failed", ip=ip, email_hash=members.email_hash(email))
            if locked:
                _audit("password_locked", ip=ip, email_hash=members.email_hash(email))
                if not email_unavailable_reason():
                    try:
                        await _send_reset(email, locked=True)
                    except email_resend.EmailError:
                        logger.warning("lockout email not sent")
            return JSONResponse(status_code=401, content={"error": WRONG})

        reachable = workspaces(email)
        if not reachable:
            accounts.record_success(email)
            raise HTTPException(status_code=403,
                                detail="No workspace you belong to accepts password sign-in. "
                                       "Use SSO or an emailed sign-in link.")
        wanted = str(body.get("tenant_id") or "")
        if wanted:
            chosen = next((w for w in reachable if w[0] == wanted), None)
            if not chosen:
                raise HTTPException(status_code=403, detail="You cannot sign in to that workspace.")
        elif len(reachable) == 1:
            chosen = reachable[0]
        else:
            # Only now, after the password verified, are the workspaces named.
            return {"choose_workspace": [{"tenant_id": t, "name": n} for t, n, _ in reachable]}

        accounts.record_success(email)
        members.mark_joined(chosen[0], email)
        _, cookie = _session(chosen[0], email, chosen[2])
    except HTTPException:
        raise
    except Exception:       # noqa: BLE001 - never answer "wrong password" for a store fault
        logger.exception("password sign-in unavailable")
        raise HTTPException(status_code=503, detail="Sign-in is unavailable. Try again in a minute.")
    _audit("password_sign_in", tenant_id=chosen[0], ip=ip, actor=f"user:email:{members.email_hash(email)}")
    resp = JSONResponse({"signed_in": True, "tenant_id": chosen[0], "redirect": "/tenant"})
    resp.set_cookie(**cookie)
    return resp


# ── forgot and set ───────────────────────────────────────────────────


@router.post("/v1/tenant/auth/password/forgot", status_code=202)
async def forgot(request: Request, body: dict = Body(...)):
    _require_enabled()
    reason = email_unavailable_reason()
    if reason:
        logger.warning("password reset refused: %s", reason)
        raise HTTPException(status_code=503, detail="Password reset is not available right now.")
    from core.auth import _client_ip
    ip = _client_ip(request)
    email = members.normalize_email(str(body.get("email") or ""))
    if not email or "@" not in email or len(email) > 254:
        raise HTTPException(status_code=422, detail="Enter your email address.")
    if not await signup._captcha_ok(str(body.get("captcha_token") or ""), ip):
        raise HTTPException(status_code=403, detail="The captcha was not solved. Try again.")
    # The same limits for every address, so a 429 says nothing about membership.
    if members.incr("pwdresetip", ip) > signup._int_env("SHIELD_PASSWORD_RESET_PER_IP_DAY", 20) or \
            members.incr("pwdresetemail", email) > signup._int_env("SHIELD_PASSWORD_RESET_PER_EMAIL_DAY", 5):
        raise HTTPException(status_code=429, detail="Too many reset emails today. Try tomorrow.")
    # Any member of a workspace that accepts passwords, with a password or not:
    # that is how someone who has only ever used SSO links sets their first.
    if workspaces(email):
        try:
            await _send_reset(email)
        except email_resend.EmailError:
            raise HTTPException(status_code=503,
                                detail="We could not send the email. Try again in a minute.")
        _audit("password_reset_requested", ip=ip, email_hash=members.email_hash(email))
    return SENT


def _set_page(token: str, link: dict, error: str = "", status: int = 200):
    new = link.get("purpose") == "invite" or not accounts.has_password(link["email"])
    title = "Choose a password" if new else "Choose a new password"
    nonce = secrets.token_urlsafe(24)
    e = html.escape
    body = (f"<p>For <b>{e(link['email'])}</b>. At least {accounts.MIN_LENGTH} characters; "
            "a few unrelated words make a strong one.</p>"
            + (f"<p style=\"color:#b91c1c\">{e(error)}</p>" if error else "") +
            f"<form method=\"post\" action=\"{COOKIE_PATH}/set\">"
            f"<input type=\"hidden\" name=\"token\" value=\"{e(token)}\">"
            f"<input type=\"hidden\" name=\"nonce\" value=\"{nonce}\">"
            "<p><label>New password<br><input type=\"password\" name=\"password\" required "
            f"minlength=\"{accounts.MIN_LENGTH}\" maxlength=\"{accounts.MAX_LENGTH}\" "
            "autocomplete=\"new-password\" style=\"width:100%;padding:8px;box-sizing:border-box\"></label></p>"
            "<p><label>Type it again<br><input type=\"password\" name=\"password2\" required "
            "autocomplete=\"new-password\" style=\"width:100%;padding:8px;box-sizing:border-box\"></label></p>"
            "<button type=\"submit\">Save and sign in</button></form>"
            + ("" if new else "<p style=\"font-size:13px\">Saving signs you out everywhere else.</p>"))
    resp = signup._page(title, body, status)
    from api.routes_portal_auth import _cookie_secure
    resp.set_cookie(NONCE_COOKIE, nonce, max_age=signup.NONCE_TTL_S, httponly=True,
                    secure=_cookie_secure(), samesite="strict", path=COOKIE_PATH)
    return resp


def _names(email: str) -> tuple:
    return tuple(n for _, n, _ in workspaces(email))


@router.get("/v1/tenant/auth/password/set")
async def set_page(token: str = ""):
    _require_enabled()
    link = accounts.peek_link(token)
    if not link:
        return expired_page("30 minutes")
    return _set_page(token, link)


@router.post("/v1/tenant/auth/password/set")
async def set_password(request: Request, token: str = Form(""), nonce: str = Form(""),
                       password: str = Form(""), password2: str = Form("")):
    _require_enabled()
    if not nonce_ok(request, NONCE_COOKIE, nonce):
        return not_from_this_page()
    link = accounts.peek_link(token)
    if not link:
        return expired_page("30 minutes")
    email = link["email"]
    if password != password2:
        return _set_page(token, link, "The two passwords are not the same.", 422)
    problem = accounts.password_problem(password, email=email, names=_names(email))
    if problem:
        return _set_page(token, link, problem, 422)
    if not accounts.take_link(token):            # used in the meantime
        return expired_page("30 minutes")
    accounts.set_password(email, password)
    if link.get("tenant_id"):
        members.mark_joined(link["tenant_id"], email)
    ended = _end_sessions(email)
    _audit("password_set", tenant_id=link.get("tenant_id", ""), purpose=link.get("purpose"),
           sessions_ended=ended, email_hash=members.email_hash(email))
    reachable = workspaces(email)
    chosen = next((w for w in reachable if w[0] == link.get("tenant_id")), None) \
        or (reachable[0] if reachable else None)
    if not chosen:
        return signup._page("Password saved", "<p>Your password is saved, but no workspace "
                            "you belong to accepts password sign-in right now.</p>"
                            "<a class=\"btn\" href=\"/tenant\">Sign in another way</a>")
    return signup.sign_in(chosen[0], email, is_admin=chosen[2] == "admin", issuer=ISSUER,
                          clear_cookie=(NONCE_COOKIE, COOKIE_PATH))


# ── change ───────────────────────────────────────────────────────────


@router.post("/v1/tenant/me/password")
async def change_password(request: Request, body: dict = Body(...)):
    _require_enabled()
    from core.auth import _client_ip, portal_principal
    principal = portal_principal(request)
    sub = (principal or {}).get("sub", "")
    if not principal or not sub.startswith("email:") or not principal.get("email"):
        raise HTTPException(status_code=400,
                            detail="Sign in as yourself (password or emailed link) to change "
                                   "your password. SSO passwords are changed at your identity provider.")
    email, tenant_id = principal["email"], principal["tenant_id"]
    current, new = body.get("current_password"), body.get("new_password")
    if not isinstance(current, str) or not isinstance(new, str):
        raise HTTPException(status_code=422, detail="current_password and new_password are required.")
    if not accounts.has_password(email):
        raise HTTPException(status_code=409,
                            detail="You have no password yet. Use Forgot password to set one.")
    ip = _client_ip(request)
    if accounts.is_locked(email) or not accounts.check_password(email, current):
        accounts.record_ip_failure(ip)
        if not accounts.is_locked(email) and accounts.record_failure(email):
            _audit("password_locked", tenant_id=tenant_id, ip=ip, email_hash=members.email_hash(email))
        raise HTTPException(status_code=403, detail="Your current password is not right.")
    problem = accounts.password_problem(new, email=email, names=_names(email))
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    accounts.set_password(email, new)
    ended = _end_sessions(email)
    match = next((w for w in workspaces(email) if w[0] == tenant_id), None)
    _audit("password_changed", tenant_id=tenant_id, ip=ip, sessions_ended=ended,
           actor=f"user:{sub}")
    resp = JSONResponse({"changed": True, "signed_out_elsewhere": True})
    if match:       # this browser stays signed in, on a new session
        resp.set_cookie(**_session(tenant_id, email, match[2])[1])
    return resp
