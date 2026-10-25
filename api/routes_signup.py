"""Self-serve sign-up (docs/specs/self-serve-signup.md, task 2). Admin plane only.

GET  /v1/signup/config          is sign-up open, and the captcha site key
POST /v1/signup                 {email, org, captcha_token} -> 202, always the same
GET  /v1/signup/verify?token=   a page with a Continue button (consumes nothing)
POST /v1/signup/verify          creates the trial tenant, signs its admin in

Off unless SHIELD_SELF_SIGNUP=open: then every route answers 404 and nothing
else changes. Open needs Resend (RESEND_API_KEY, SHIELD_SIGNUP_FROM), hCaptcha
(HCAPTCHA_SECRET_KEY) and SHIELD_PORTAL_BASE_URL; without any of them sign-up
answers 503 rather than running unprotected. Existing sign-in (SSO, API keys)
is untouched: this only adds a way in.

Why the verify link opens a page instead of acting: corporate email scanners
fetch every link in an email. A GET that created the tenant would be used up
by the scanner. The page posts the token with a nonce from a SameSite=Strict
cookie it set, so another site cannot post a token of its own and sign a
visitor into a tenant that site created.
"""

from __future__ import annotations

import hmac
import html
import logging
import os
import re
import secrets
import time
from typing import Optional

import httpx
from fastapi import APIRouter, Body, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from core import email_resend
from storage import signup_store as store

router = APIRouter(prefix="/v1/signup", tags=["signup"])
logger = logging.getLogger("votal.signup")

NONCE_COOKIE = "shield_signup_nonce"
NONCE_TTL_S = 15 * 60
_EMAIL_RE = re.compile(r"^[^\s@<>()\[\],;:\"]{1,64}@([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+)$")
_DISPOSABLE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "core", "signup", "disposable_domains.txt")
_disposable: Optional[frozenset] = None


# ── settings ─────────────────────────────────────────────────────────


def _int_env(name: str, default: int, lo: int = 1, hi: int = 10**12) -> int:
    try:
        v = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return min(max(v, lo), hi)


def is_open() -> bool:
    """SHIELD_SELF_SIGNUP=open. Whether sign-up is paused is separate (paused())."""
    return os.environ.get("SHIELD_SELF_SIGNUP", "off").strip().lower() == "open"


# The operator's overrides (admin console, task 5) win over the env, which
# wins over the built-in default. Each is (setting, env var, default, low, high).
LIMITS = {
    "trial_days": ("SHIELD_SIGNUP_TRIAL_DAYS", 30, 1, 365),
    "trial_requests_per_day": ("SHIELD_SIGNUP_TRIAL_REQUESTS_PER_DAY", 5000, 1, 10**9),
    "trial_tokens_per_day": ("SHIELD_SIGNUP_TRIAL_TOKENS_PER_DAY", 2_000_000, 1, 10**12),
    "daily_cap": ("SHIELD_SIGNUP_DAILY_CAP", 100, 1, 100_000),
}
TRIAL_MODES = ("enforce", "monitor")


def limit(name: str, overrides: Optional[dict] = None) -> int:
    env, default, lo, hi = LIMITS[name]
    o = (store.get_settings() if overrides is None else overrides).get(name)
    if isinstance(o, int) and not isinstance(o, bool) and lo <= o <= hi:
        return o
    return _int_env(env, default, lo, hi)


def trial_mode(overrides: Optional[dict] = None) -> str:
    """How a new trial's policy starts. Enforce: someone trying Shield expects
    an attack to be blocked, and "safe": true reads like a miss. Monitor only
    by choice (SHIELD_SIGNUP_TRIAL_MODE=monitor, or the console)."""
    o = (store.get_settings() if overrides is None else overrides).get("trial_mode")
    if o in TRIAL_MODES:
        return o
    env = os.environ.get("SHIELD_SIGNUP_TRIAL_MODE", "").strip().lower()
    return env if env in TRIAL_MODES else "enforce"


def paused() -> bool:
    return store.get_settings().get("paused") is True


def trial_days() -> int:
    return limit("trial_days")


def trial_quota() -> dict:
    # The per-minute limit is the platform floor for everyone
    # (storage/tenant_models.effective_quota): trials are limited per day.
    return {"max_requests_per_day": limit("trial_requests_per_day"),
            "max_tokens_per_day": limit("trial_tokens_per_day")}


def _require_open() -> None:
    if not is_open():
        raise HTTPException(status_code=404, detail="Not Found")


def _unavailable_reason() -> str:
    """Why open sign-up cannot run safely right now, or "" when it can."""
    return email_unavailable_reason()


def email_unavailable_reason() -> str:
    """Why sign-up or email-link sign-in cannot run safely, or "" when they can.
    Email-link sign-in uses the same checks but not SHIELD_SELF_SIGNUP: a
    workspace created while sign-up was open must still be reachable after."""
    from api.routes_portal_auth import portal_base_url
    if not os.environ.get("HCAPTCHA_SECRET_KEY", "").strip():
        return "captcha is not configured"
    if not email_resend.configured():
        return "email is not configured"
    if not portal_base_url():
        return "SHIELD_PORTAL_BASE_URL is not set"
    from core.auth import _store_is_degraded
    if _store_is_degraded():
        return "the store is unavailable"
    return ""


def _disposable_domains() -> frozenset:
    global _disposable
    if _disposable is None:
        try:
            with open(_DISPOSABLE_FILE, encoding="utf-8") as f:
                _disposable = frozenset(l.strip().lower() for l in f
                                        if l.strip() and not l.startswith("#"))
        except OSError:
            _disposable = frozenset()
    return _disposable


def _is_disposable(domain: str) -> bool:
    parts = domain.lower().split(".")
    return any(".".join(parts[i:]) in _disposable_domains() for i in range(len(parts) - 1))


def _clean_org(org: str) -> str:
    org = re.sub(r"[\x00-\x1f\x7f]", "", str(org or "")).strip()
    return org[:80]


def _slug(org: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", org.lower()).strip("-")[:40].strip("-")
    return s or "org"


def _new_tenant_id(org: str) -> str:
    from storage.tenant_store import get_tenant
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(10):
        tid = f"{_slug(org)}-{''.join(secrets.choice(alphabet) for _ in range(6))}"
        if not get_tenant(tid, include_deleted=True):
            return tid
    raise HTTPException(status_code=503, detail="could not choose a workspace id; try again")


async def _captcha_ok(token: str, ip: str) -> bool:
    secret = os.environ.get("HCAPTCHA_SECRET_KEY", "").strip()
    if not secret or not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post("https://api.hcaptcha.com/siteverify",
                                     data={"secret": secret, "response": token, "remoteip": ip})
        return bool(resp.json().get("success"))
    except Exception:       # noqa: BLE001 - an unverifiable captcha is a failed one
        return False


# ── emails ───────────────────────────────────────────────────────────


def _email(heading: str, body: str, link: str, button: str) -> tuple[str, str]:
    text = f"{heading}\n\n{body}\n\n{link}\n\nIf you did not ask for this, ignore this email.\n"
    h = html.escape
    page = (f"<div style=\"font-family:Arial,sans-serif;max-width:520px\">"
            f"<h2 style=\"font-size:18px\">{h(heading)}</h2><p>{h(body)}</p>"
            f"<p><a href=\"{h(link)}\" style=\"display:inline-block;padding:10px 16px;"
            f"background:#5b4ee6;color:#fff;border-radius:6px;text-decoration:none\">{h(button)}</a></p>"
            f"<p style=\"color:#666;font-size:12px\">Or open: {h(link)}<br>"
            f"If you did not ask for this, ignore this email.</p></div>")
    return text, page


async def _send_verify(email: str, org: str, token: str) -> None:
    from api.routes_portal_auth import portal_base_url
    link = f"{portal_base_url()}/v1/signup/verify?token={token}"
    text, page = _email("Confirm your Votal Shield workspace",
                        f"Confirm your email to create the workspace \"{org}\". "
                        "The link works once, for 24 hours.", link, "Create my workspace")
    await email_resend.send(email, "Confirm your Votal Shield workspace", text, page)


# ── routes ───────────────────────────────────────────────────────────


@router.get("/config")
async def signup_config():
    open_ = is_open()
    email_ok = not email_unavailable_reason()
    held = open_ and paused()
    return {"mode": "open" if open_ else "off",
            "available": open_ and email_ok and not held,
            "paused": held,
            "email_link_available": email_ok,
            "captcha_site_key": os.environ.get("HCAPTCHA_SITE_KEY", "") if (open_ or email_ok) else ""}


ACCEPTED = {"status": "check_your_email",
            "message": "If that address can sign up, we have sent it a link. "
                       "It works once, for 24 hours."}


@router.post("", status_code=202)
async def signup(request: Request, body: dict = Body(...)):
    _require_open()
    reason = _unavailable_reason()
    if reason:
        logger.warning("sign-up refused: %s", reason)
        raise HTTPException(status_code=503, detail="Sign-up is not available right now.")
    if paused():
        raise HTTPException(status_code=503, detail="Sign-ups are paused. Try again later.")
    from core.auth import _client_ip
    ip = _client_ip(request)
    email = store.normalize_email(str(body.get("email") or ""))
    org = _clean_org(body.get("org"))
    m = _EMAIL_RE.match(email) if len(email) <= 254 else None
    if not m:
        raise HTTPException(status_code=422, detail="Enter a valid work email.")
    if not org:
        raise HTTPException(status_code=422, detail="Enter your organisation's name.")
    domain = m.group(1).lower()
    if _is_disposable(domain):
        raise HTTPException(status_code=422, detail="Use a work email, not a disposable one.")
    if not await _captcha_ok(str(body.get("captcha_token") or ""), ip):
        raise HTTPException(status_code=403, detail="The captcha was not solved. Try again.")
    if store.incr("ip", ip) > _int_env("SHIELD_SIGNUP_PER_IP_DAY", 3) or \
            store.incr("domain", domain) > _int_env("SHIELD_SIGNUP_PER_DOMAIN_DAY", 3):
        raise HTTPException(status_code=429, detail="Too many sign-ups today. Try tomorrow.")
    if store.count("all") >= limit("daily_cap"):
        raise HTTPException(status_code=429, detail="Sign-ups are paused for today. Try tomorrow.")

    try:
        if store.trial_of(email):
            # Already has a workspace: a sign-in link instead (task 3), so the
            # answer here stays the same and the person still gets in.
            from api.routes_email_link import send_sign_in_links
            await send_sign_in_links(email)
        else:
            token, tok_hash = store.new_token()
            store.save_pending(tok_hash, email=email, org=org, ip=ip)
            try:
                await _send_verify(email, org, token)
            except email_resend.EmailError:
                store.take_pending(tok_hash)          # keep nothing we could not send
                raise
    except email_resend.EmailError:
        raise HTTPException(status_code=503,
                            detail="We could not send the email. Try again in a minute.")
    # The same answer for a new address and one that already has a workspace.
    return ACCEPTED


def _page(title: str, body_html: str, status: int = 200) -> HTMLResponse:
    page = (f"<!doctype html><html><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)}</title><style>"
            "body{font-family:Inter,Arial,sans-serif;background:#f5f6f8;margin:0;color:#1b1b22}"
            ".box{max-width:440px;margin:12vh auto;background:#fff;border:1px solid #e3e4e8;"
            "border-radius:12px;padding:28px}h1{font-size:20px;margin:0 0 10px}"
            "p{color:#555;line-height:1.5}button,a.btn{display:inline-block;margin-top:10px;"
            "padding:10px 16px;border:0;border-radius:8px;background:#5b4ee6;color:#fff;"
            "font-size:14px;cursor:pointer;text-decoration:none}</style></head><body>"
            f"<div class=\"box\"><h1>{html.escape(title)}</h1>{body_html}</div></body></html>")
    return HTMLResponse(page, status_code=status,
                        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


def expired_page(hours: str) -> HTMLResponse:
    return _page("This link has expired",
                 f"<p>It was used already, or it is more than {hours} old.</p>"
                 "<a class=\"btn\" href=\"/tenant\">Start again</a>", 410)


def confirm_page(*, title: str, intro: str, action: str, token: str,
                 cookie_name: str, cookie_path: str, extra_html: str = "",
                 status: int = 200) -> HTMLResponse:
    """The page an emailed link opens: it consumes nothing (email scanners
    fetch every link), and posts the token with a nonce from a SameSite=Strict
    cookie, so another site cannot post a token of its own. `extra_html` is
    trusted markup placed in the form, above the button."""
    nonce = secrets.token_urlsafe(24)
    resp = _page(title, f"<p>{html.escape(intro)}</p>"
                 f"<form method=\"post\" action=\"{html.escape(action)}\">"
                 f"<input type=\"hidden\" name=\"token\" value=\"{html.escape(token)}\">"
                 f"<input type=\"hidden\" name=\"nonce\" value=\"{nonce}\">"
                 f"{extra_html}<button type=\"submit\">Continue</button></form>", status)
    from api.routes_portal_auth import _cookie_secure
    resp.set_cookie(cookie_name, nonce, max_age=NONCE_TTL_S, httponly=True,
                    secure=_cookie_secure(), samesite="strict", path=cookie_path)
    return resp


def nonce_ok(request: Request, cookie_name: str, nonce: str) -> bool:
    cookie = request.cookies.get(cookie_name, "")
    return bool(cookie and nonce and hmac.compare_digest(cookie, nonce))


def not_from_this_page() -> HTMLResponse:
    return _page("Open the link from your email",
                 "<p>Continue from the page your email link opened, in the same browser.</p>",
                 400)


def sign_in(tenant_id: str, email: str, *, is_admin: bool, issuer: str,
            clear_cookie: tuple[str, str]) -> RedirectResponse:
    """A portal session for this email in this tenant, as SSO gives one."""
    from api.routes_portal_auth import COOKIE_NAME, _cookie_secure
    from storage.portal_sessions import create_session, session_ttl
    session_id = create_session(tenant_id, {"sub": "email:" + store.email_hash(email),
                                            "email": email, "name": "", "issuer": issuer},
                                is_admin=is_admin)
    resp = RedirectResponse("/tenant", status_code=303)
    resp.set_cookie(COOKIE_NAME, session_id, max_age=session_ttl(), httponly=True,
                    secure=_cookie_secure(), samesite="lax", path="/")
    resp.delete_cookie(clear_cookie[0], path=clear_cookie[1])
    return resp


def _password_field(error: str = "") -> str:
    """The optional password on the confirm page (docs/specs/password-sign-in.md,
    task 2): empty keeps today's emailed-link sign-in."""
    from api.routes_password_auth import enabled
    if not enabled():
        return ""
    from storage.user_accounts import MIN_LENGTH
    return ((f"<p style=\"color:#b91c1c\">{html.escape(error)}</p>" if error else "") +
            "<p><label>Password (optional, so you can sign in with it next time)<br>"
            f"<input type=\"password\" name=\"password\" minlength=\"{MIN_LENGTH}\" "
            "maxlength=\"128\" autocomplete=\"new-password\" style=\"width:100%;padding:8px;box-sizing:border-box\">"
            "</label></p>")


def _verify_page(token: str, error: str = "", status: int = 200) -> HTMLResponse:
    return confirm_page(title="Create your workspace",
                        intro="Confirm to create your Votal Shield workspace and sign in.",
                        action="/v1/signup/verify", token=token,
                        cookie_name=NONCE_COOKIE, cookie_path="/v1/signup",
                        extra_html=_password_field(error), status=status)


@router.get("/verify")
async def verify_page(token: str = ""):
    _require_open()
    if not token or not store.pending_is_valid(store.token_hash(token)):
        return expired_page("24 hours")
    return _verify_page(token)


@router.post("/verify")
async def verify(request: Request, token: str = Form(""), nonce: str = Form(""),
                 password: str = Form("")):
    _require_open()
    if not nonce_ok(request, NONCE_COOKIE, nonce):
        return not_from_this_page()
    if password:
        # Checked before the token is used, so a refused password costs nothing.
        from api.routes_password_auth import enabled
        from storage.user_accounts import password_problem
        peeked = store._peek(f"signup:pending:{store.token_hash(token)}")
        if not peeked:
            return expired_page("24 hours")
        problem = password_problem(password, email=peeked["email"], names=(peeked["org"],)) \
            if enabled() else ""
        if problem:
            return _verify_page(token, problem, 422)
    pending = store.take_pending(store.token_hash(token))
    if not pending:
        return expired_page("24 hours")
    email, org = pending["email"], pending["org"]

    tenant_id = _new_tenant_id(org)
    if not store.claim_email(email, tenant_id):
        return _page("You already have a workspace",
                     "<p>This email address has a workspace. Sign in to it.</p>"
                     "<a class=\"btn\" href=\"/tenant\">Sign in</a>", 409)
    if paused():
        store.release_email(email)
        return _page("Sign-ups are paused",
                     "<p>New workspaces are paused for now. Try the link again later.</p>", 503)
    if store.incr("all") > limit("daily_cap"):
        store.release_email(email)
        return _page("Sign-ups are paused for today",
                     "<p>We have reached today's limit for new workspaces. Try tomorrow.</p>", 429)

    from core.policy_templates import get_template
    from storage.tenant_store import create_tenant
    tpl = get_template("general") or {}
    now = int(time.time())
    config = {
        "name": org, "plan": "trial",
        "input_guardrails": tpl.get("input_guardrails", {}),
        "output_guardrails": tpl.get("output_guardrails", {}),
        "rbac": {"roles": {}, "agents": {}},
        "policy_mode": trial_mode(),
        "quota": trial_quota(),
        "trial": {"expires_at": now + trial_days() * 86400, "created_via": "self_signup",
                  "email_domain": email.rsplit("@", 1)[-1]},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    }
    try:
        create_tenant(tenant_id, config, [])
    except Exception:
        store.release_email(email)
        logger.exception("self-serve tenant not created")
        return _page("Something went wrong", "<p>Your workspace was not created. "
                     "Try the link again in a minute.</p>", 503)
    from api.routes_tenant import finish_new_tenant
    finish_new_tenant(tenant_id, actor=f"self-signup:{email}")
    store.add_member(tenant_id, email, "admin")
    if password:
        from api.routes_password_auth import enabled
        if enabled():
            from storage.user_accounts import set_password
            set_password(email, password)

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="self_signup_tenant", actor=f"self-signup:{email}",
                         tenant_id=tenant_id, source_ip=pending.get("ip", ""),
                         after={"name": org, "plan": "trial", "email_domain": config["trial"]["email_domain"]})
    except Exception:       # noqa: BLE001 - the tenant exists; audit is best effort here
        logger.warning("self-signup audit not written for %s", tenant_id)

    logger.info("self-serve tenant created: %s (%s)", tenant_id, config["trial"]["email_domain"])
    return sign_in(tenant_id, email, is_admin=True, issuer="votal-signup",
                   clear_cookie=(NONCE_COOKIE, "/v1/signup"))
