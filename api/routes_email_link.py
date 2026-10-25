"""Email-link sign-in (docs/specs/self-serve-signup.md, task 3). Admin plane only.

POST /v1/tenant/auth/email-link            {email, captcha_token} -> 202, always the same
GET  /v1/tenant/auth/email-link/confirm    a page with Continue (consumes nothing)
POST /v1/tenant/auth/email-link/confirm    a portal session, then /tenant

A link goes only to an address that is a member of a workspace (members come
from self-serve sign-up), one link per workspace, valid 15 minutes, once. A
stranger's address gets the same answer and no email, so this cannot be used
to send mail to anyone. Not offered for a workspace whose operator set
require_sso: its people sign in through its identity provider, where its
offboarding lives. SSO and API-key sign-in are unchanged.
"""

from __future__ import annotations

import html
import logging
import os

from fastapi import APIRouter, Body, Form, HTTPException, Request

import api.routes_signup as signup
from api.routes_signup import (_email, _int_env, confirm_page, email_unavailable_reason,
                               expired_page, nonce_ok, not_from_this_page, sign_in)
from core import email_resend
from storage import signup_store as store

router = APIRouter(prefix="/v1/tenant/auth/email-link", tags=["portal-auth"])
logger = logging.getLogger("votal.email_link")

NONCE_COOKIE = "shield_link_nonce"
COOKIE_PATH = "/v1/tenant/auth/email-link"
MAX_WORKSPACES_PER_EMAIL = 5

SENT = {"status": "check_your_email",
        "message": "If that address can sign in, we have sent it a link. "
                   "It works once, for 15 minutes."}


def _reachable_workspaces(email: str) -> list[tuple[str, str, str]]:
    """(tenant_id, display name, role) this email may sign in to by link."""
    from storage.tenant_store import get_tenant
    out = []
    for tid in store.tenants_of(email)[:MAX_WORKSPACES_PER_EMAIL]:
        t = get_tenant(tid)
        role = store.member_role(tid, email)
        if not t or not role or t.get("require_sso"):
            continue
        from core.signup.trial import SUSPENDED, status
        if status(t) == SUSPENDED:      # an expired trial still signs in, to see why
            continue
        out.append((tid, t.get("name") or tid, role))
    return out


async def send_sign_in_links(email: str) -> int:
    """Email one sign-in link per workspace this address belongs to. Returns
    how many; zero sends nothing. Raises email_resend.EmailError."""
    from api.routes_portal_auth import portal_base_url
    workspaces = _reachable_workspaces(email)
    if not workspaces:
        return 0
    base = portal_base_url()
    lines, buttons = [], []
    for tid, name, _ in workspaces:
        token, tok_hash = store.new_token()
        store.save_link(tok_hash, tenant_id=tid, email=email)
        link = f"{base}{COOKIE_PATH}/confirm?token={token}"
        lines.append(f"{name}: {link}")
        buttons.append((name, link))
    if len(buttons) == 1:
        text, page = _email("Sign in to Votal Shield",
                            f"Sign in to the workspace \"{buttons[0][0]}\". "
                            "The link works once, for 15 minutes.", buttons[0][1], "Sign in")
    else:
        text = ("Sign in to Votal Shield\n\nChoose a workspace. Each link works once, "
                "for 15 minutes.\n\n" + "\n".join(lines) +
                "\n\nIf you did not ask for this, ignore this email.\n")
        page = ("<div style=\"font-family:Arial,sans-serif;max-width:520px\">"
                "<h2 style=\"font-size:18px\">Sign in to Votal Shield</h2>"
                "<p>Choose a workspace. Each link works once, for 15 minutes.</p>" +
                "".join(f"<p><a href=\"{html.escape(l)}\">{html.escape(n)}</a></p>"
                        for n, l in buttons) +
                "<p style=\"color:#666;font-size:12px\">If you did not ask for this, "
                "ignore this email.</p></div>")
    await email_resend.send(email, "Sign in to Votal Shield", text, page)
    return len(buttons)


@router.post("", status_code=202)
async def request_link(request: Request, body: dict = Body(...)):
    reason = email_unavailable_reason()
    if reason:
        logger.warning("email-link sign-in refused: %s", reason)
        raise HTTPException(status_code=503, detail="Email sign-in is not available right now.")
    from core.auth import _client_ip
    ip = _client_ip(request)
    email = store.normalize_email(str(body.get("email") or ""))
    if not email or "@" not in email or len(email) > 254:
        raise HTTPException(status_code=422, detail="Enter your email address.")
    # Looked up on the module each call, so there is one captcha check to change.
    if not await signup._captcha_ok(str(body.get("captcha_token") or ""), ip):
        raise HTTPException(status_code=403, detail="The captcha was not solved. Try again.")
    # Limits apply to every address alike, so a 429 says nothing about membership.
    if store.incr("linkip", ip) > _int_env("SHIELD_EMAIL_LINK_PER_IP_DAY", 20) or \
            store.incr("linkemail", email) > _int_env("SHIELD_EMAIL_LINK_PER_EMAIL_DAY", 5):
        raise HTTPException(status_code=429, detail="Too many sign-in emails today. Try tomorrow.")
    try:
        await send_sign_in_links(email)
    except email_resend.EmailError:
        raise HTTPException(status_code=503,
                            detail="We could not send the email. Try again in a minute.")
    return SENT


@router.get("/confirm")
async def confirm_link_page(token: str = ""):
    if not token or not store.link_is_valid(store.token_hash(token)):
        return expired_page("15 minutes")
    return confirm_page(title="Sign in to Votal Shield",
                        intro="Continue to sign in to your workspace.",
                        action=f"{COOKIE_PATH}/confirm", token=token,
                        cookie_name=NONCE_COOKIE, cookie_path=COOKIE_PATH)


@router.post("/confirm")
async def confirm_link(request: Request, token: str = Form(""), nonce: str = Form("")):
    if not nonce_ok(request, NONCE_COOKIE, nonce):
        return not_from_this_page()
    link = store.take_link(store.token_hash(token))
    if not link:
        return expired_page("15 minutes")
    email, tenant_id = link["email"], link["tenant_id"]
    # Checked again now, not when the link was sent: membership, the tenant,
    # or its require_sso may have changed in the 15 minutes since.
    match = next((w for w in _reachable_workspaces(email) if w[0] == tenant_id), None)
    if not match:
        return expired_page("15 minutes")
    logger.info("email-link sign-in: tenant=%s", tenant_id)
    store.mark_joined(tenant_id, email)
    return sign_in(tenant_id, email, is_admin=match[2] == "admin", issuer="votal-email-link",
                   clear_cookie=(NONCE_COOKIE, COOKIE_PATH))
