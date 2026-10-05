"""Connect your own account: the page a person uses for per-person MCP servers.

A server with `credential_scope: per_user` (B2) sends each caller's own
upstream token. This is where a person connects that account, once:

    GET  /connect/{tenant}                       my connections (per-person servers)
    GET  /connect/{tenant}/{route}               one server: status, Connect / Disconnect
    POST /connect/{tenant}/{route}/start         302 to the provider's sign-in
    POST /connect/{tenant}/{route}/disconnect    revoke at the provider, delete
    GET  /v1/tenant/me/mcp/oauth/callback        (existing) finishes it via complete_personal

**Who the person is** comes from their portal SSO session (no session: sent to
company sign-in and back). They must already be a principal, which anyone who
got the gateway's "connect your account" error is, since per-person servers
accept only signed-in callers.

**Account swap defence.** The pending record stores a hash of the browser
session that started the connection, and the callback stores nothing unless
the same session finishes it. Otherwise someone could start a connection, send
the provider link to a colleague, and attach the colleague's account to their
own grant.

**The upstream account** shown and recorded is the `email` (else `sub`) of the
id_token the provider's token endpoint returned over TLS (OIDC Core 3.1.3.7).
It is a label for people and auditors, never used to authorize anything.

Admin plane only; nothing here runs on the guard path.
Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§4.8, task B3)
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
from typing import Optional
from urllib.parse import quote, urlencode, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

logger = logging.getLogger("votal.mcp_connect")

router = APIRouter(tags=["mcp-connect"])

_PAGE_HEADERS = {
    "X-Frame-Options": "DENY",
    # No form-action: Start posts here and is redirected to the provider, and
    # browsers apply form-action to that redirect.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}

_STATUS_TEXT = {
    "connected": "Connected",
    "needs_consent": "Expired: connect again",
    "error": "Renewal failing: connect again if this persists",
}


def _e(value) -> str:
    return html.escape(str(value or ""))


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_e(title)}</title><style>"
        "body{font-family:Arial,sans-serif;max-width:560px;margin:48px auto;padding:0 16px;color:#1a1a1a}"
        "h1{font-size:20px}.row{border:1px solid #ddd;border-radius:8px;padding:12px 14px;margin:10px 0;"
        "display:flex;gap:12px;align-items:center;flex-wrap:wrap}.name{font-weight:600;flex:1;min-width:140px}"
        ".dim{color:#666;font-size:13px}.ok{color:#15803d}.warn{color:#b45309}"
        "button{font-size:14px;padding:8px 14px;border-radius:6px;border:1px solid #888;cursor:pointer;background:#fff}"
        "button.primary{background:#1a1a1a;color:#fff;border-color:#1a1a1a}form{margin:0}"
        "</style></head><body>" + body + "</body></html>",
        status_code=status, headers=_PAGE_HEADERS)


def _session_id(request: Request) -> str:
    from core.auth import PORTAL_COOKIE_NAME
    return request.cookies.get(PORTAL_COOKIE_NAME, "") or ""


def browser_binding(request: Request) -> str:
    sid = _session_id(request)
    return hashlib.sha256(f"mcp-connect:{sid}".encode()).hexdigest() if sid else ""


def _csrf(request: Request, route: str) -> str:
    """Per-session, per-server form token. The session cookie is SameSite=Lax,
    which already keeps it off cross-site POSTs; this is the second lock."""
    sid = _session_id(request)
    return hmac.new(sid.encode(), f"mcp-connect:{route}".encode(), hashlib.sha256).hexdigest()[:32]


def _person(request: Request, tenant_id: str):
    """(principal, None) for the signed-in person, or (None, response)."""
    from core.auth import portal_principal
    from storage.principal_store import find_user, is_active

    session = portal_principal(request)
    if session is None:
        next_path = request.url.path
        login = f"/v1/tenant/auth/login?{urlencode({'tenant': tenant_id, 'next': next_path})}"
        return None, RedirectResponse(login, status_code=302)
    if session.get("tenant_id") != tenant_id:
        return None, _page("Wrong organization",
                           "<h1>You are signed in to a different organization</h1>"
                           "<p>Sign out of the Shield console, then open this link again.</p>",
                           status=403)
    person = find_user(tenant_id, session.get("issuer", ""), session.get("sub", ""))
    if person is None:
        return None, _page("Sign in from your AI app first",
                           "<h1>Sign in from your AI app first</h1>"
                           "<p>Add this organization's MCP server in your AI app (Claude, Cursor, "
                           "VS Code) and sign in there once. Then come back to this page to "
                           "connect your account.</p>", status=403)
    if not is_active(person):
        return None, _page("Access suspended",
                           "<h1>Your access is suspended</h1>"
                           "<p>Ask your administrator.</p>", status=403)
    return person, None


def _per_user_routes(tenant_id: str) -> list[dict]:
    from storage.mcp_gateway_store import list_upstreams
    return [c for c in list_upstreams(tenant_id) if c.get("credential_scope") == "per_user"]


def _row(request: Request, tenant_id: str, cfg: dict, pid: str) -> str:
    from storage.mcp_grant_store import get_grant
    route = cfg.get("route", "")
    grant = get_grant(tenant_id, route, pid)
    base = f"/connect/{quote(tenant_id)}/{quote(route)}"
    token = f"<input type='hidden' name='csrf' value='{_e(_csrf(request, route))}'>"
    if grant:
        state = grant.get("status", "")
        tone = "ok" if state == "connected" else "warn"
        account = grant.get("upstream_account") or "your account"
        status = (f"<div class='dim {tone}'>{_e(_STATUS_TEXT.get(state, state))}"
                  f"{' as ' + _e(account) if state == 'connected' else ''}</div>")
        buttons = (f"<form method='post' action='{base}/start'>{token}"
                   f"<button>{'Reconnect' if state != 'connected' else 'Switch account'}</button></form>"
                   f"<form method='post' action='{base}/disconnect'>{token}"
                   f"<button>Disconnect</button></form>")
    else:
        status = "<div class='dim'>Not connected</div>"
        buttons = (f"<form method='post' action='{base}/start'>{token}"
                   f"<button class='primary'>Connect</button></form>")
    return (f"<div class='row'><div class='name'>{_e(route)}{status}"
            f"<div class='dim'>{_e(urlparse(cfg.get('url') or '').hostname or '')}</div></div>"
            f"{buttons}</div>")


@router.get("/connect/{tenant_id}")
async def my_connections(tenant_id: str, request: Request):
    person, refusal = _person(request, tenant_id)
    if refusal:
        return refusal
    routes = _per_user_routes(tenant_id)
    rows = "".join(_row(request, tenant_id, c, person["id"]) for c in routes) or \
        "<p class='dim'>No server in this organization uses personal accounts.</p>"
    return _page("Your connections",
                 f"<h1>Your connections</h1><p class='dim'>Signed in as {_e(person.get('email'))}. "
                 "These servers use each person's own account: your AI app acts as you, "
                 f"with your access, and never as anyone else.</p>{rows}")


@router.get("/connect/{tenant_id}/{route}")
async def connect_page(tenant_id: str, route: str, request: Request):
    person, refusal = _person(request, tenant_id)
    if refusal:
        return refusal
    cfg = _route_or_none(tenant_id, route)
    if cfg is None:
        return _page("Not found", "<h1>This server does not use personal accounts</h1>", 404)
    return _page(f"Connect {route}",
                 f"<h1>Connect your account to {_e(route)}</h1>"
                 f"<p class='dim'>Signed in as {_e(person.get('email'))}. You sign in with the "
                 "server's own provider; Shield keeps your connection encrypted and sends it "
                 "only to this server, only for your own requests.</p>"
                 f"{_row(request, tenant_id, cfg, person['id'])}"
                 f"<p class='dim'><a href='/connect/{quote(tenant_id)}'>All your connections</a></p>")


def _route_or_none(tenant_id: str, route: str) -> Optional[dict]:
    from storage.mcp_gateway_store import get_upstream
    cfg = get_upstream(tenant_id, route)
    return cfg if cfg and cfg.get("credential_scope") == "per_user" else None


async def _checked(request: Request, tenant_id: str, route: str):
    """(person, cfg, None) for a valid form post, else (None, None, response)."""
    person, refusal = _person(request, tenant_id)
    if refusal:
        return None, None, refusal
    form = await request.form()
    if not hmac.compare_digest(str(form.get("csrf", "")), _csrf(request, route)):
        return None, None, _page("Expired", "<h1>This page expired</h1>"
                                 "<p>Go back, reload and try again.</p>", 400)
    cfg = _route_or_none(tenant_id, route)
    if cfg is None:
        return None, None, _page("Not found", "<h1>This server does not use personal accounts</h1>", 404)
    return person, cfg, None


@router.post("/connect/{tenant_id}/{route}/start")
async def start(tenant_id: str, route: str, request: Request):
    from core.mcp_oauth import OAuthBrokerError, build_authorize_url, redirect_uri
    from core.oauth.pkce import generate_code_challenge, generate_code_verifier
    from storage.mcp_oauth_store import get_broker, new_state, put_pending

    person, _cfg, refusal = await _checked(request, tenant_id, route)
    if refusal:
        return refusal
    record = get_broker(tenant_id, route)
    if not record or not record.get("authorization_endpoint") or not record.get("client_id"):
        return _page("Not set up", "<h1>This server's sign-in is not set up yet</h1>"
                     "<p>Ask your administrator to configure OAuth for it in the Shield console.</p>", 409)
    verifier, state = generate_code_verifier(), new_state()
    try:
        callback = redirect_uri()
        url = build_authorize_url(record, client_id=record["client_id"],
                                  scopes=list(record.get("scopes") or []), state=state,
                                  code_challenge=generate_code_challenge(verifier))
    except OAuthBrokerError as e:
        return _page("Not available", f"<h1>Cannot connect right now</h1><p>{_e(e.message)}</p>", 409)
    put_pending(state, tenant_id, route, verifier, callback,
                principal_id=person["id"], browser_binding=browser_binding(request))
    return RedirectResponse(url, status_code=303)


@router.post("/connect/{tenant_id}/{route}/disconnect")
async def disconnect(tenant_id: str, route: str, request: Request):
    from core.mcp_credentials import revoke_grant
    person, _cfg, refusal = await _checked(request, tenant_id, route)
    if refusal:
        return refusal
    existed = await revoke_grant(tenant_id, route, person["id"])
    if existed:
        _audit(tenant_id, "mcp_personal_connection_removed", person,
               {"route": route, "via": "connect page"})
    return RedirectResponse(f"/connect/{quote(tenant_id)}/{quote(route)}", status_code=303)


def _audit(tenant_id: str, action: str, person: dict, after: dict) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=f"principal:{person['id']}", tenant_id=tenant_id,
                         after={**after, "principal_id": person["id"],
                                "email": person.get("email", "")})
    except Exception:       # noqa: BLE001
        pass


def _upstream_account(payload: dict) -> str:
    raw = payload.get("id_token") or ""
    if not raw:
        return ""
    try:
        from core.jwt_utils import decode_jwt_unverified
        claims = decode_jwt_unverified(raw)
    except Exception:       # noqa: BLE001 - a label, not a gate
        return ""
    return str(claims.get("email") or claims.get("sub") or "")[:254]


async def complete_personal(request: Request, pending: dict, code: str) -> HTMLResponse:
    """Finish a person's own connection (called by the OAuth callback)."""
    from core.mcp_credentials import (CredentialContext, CredentialError, _host, _token_extras,
                                      _with_client, expiry_from, post_token_endpoint)
    from storage.mcp_gateway_store import get_upstream
    from storage.mcp_grant_store import GrantError, store_tokens
    from storage.mcp_oauth_store import get_broker
    from storage.principal_store import get_principal, is_active

    tenant_id, route, pid = pending["tenant_id"], pending["route"], pending["principal_id"]
    binding = pending.get("browser_binding") or ""
    if not binding or not hmac.compare_digest(binding, browser_binding(request)):
        logger.warning("mcp connect: callback from a different browser refused (tenant=%s route=%s)",
                       tenant_id, route)
        return _page("Finish in the same browser",
                     "<h1>Finish connecting in the browser you started in</h1>"
                     "<p>For your safety, a connection can only be completed in the browser "
                     "session that started it. Nothing was saved. Start again from the "
                     "connect page.</p>", 403)
    person = get_principal(tenant_id, pid)
    cfg = get_upstream(tenant_id, route) or {}
    record = get_broker(tenant_id, route)
    if not is_active(person) or cfg.get("credential_scope") != "per_user" or not record:
        return _page("Not available", "<h1>This connection can no longer be completed</h1>"
                     "<p>Nothing was saved.</p>", 409)

    endpoint = record.get("token_endpoint") or ""
    data = {"grant_type": "authorization_code", "code": code,
            "redirect_uri": pending.get("redirect_uri", ""),
            "client_id": record.get("client_id") or "",
            "code_verifier": pending.get("code_verifier", ""), **_token_extras(record)}
    secret = CredentialContext(tenant_id=tenant_id, route=route, record=record).secret(
        "client_secret_ref")
    if secret:
        data["client_secret"] = secret
    try:
        payload = await _with_client(None, lambda c: post_token_endpoint(
            c, endpoint, data, purpose="oauth-token-exchange"))
        account = _upstream_account(payload)
        store_tokens(tenant_id, route, pid,
                     access_token=str(payload["access_token"]),
                     access_bindings=[_host(cfg.get("url") or "") or _host(endpoint)],
                     refresh_token=str(payload.get("refresh_token") or ""),
                     refresh_bindings=[_host(endpoint)], expires_at=expiry_from(payload),
                     scopes=payload.get("scope") or record.get("scopes"),
                     upstream_account=account)
    except (CredentialError, GrantError) as e:
        detail = getattr(e, "message", "") or str(e)
        return _page("Could not connect", f"<h1>Could not connect</h1><p>{_e(detail)}</p>", 502)

    _audit(tenant_id, "mcp_personal_connection", person,
           {"route": route, "upstream_account": account,
            "refresh_token_held": bool(payload.get("refresh_token"))})
    note = "" if payload.get("refresh_token") else (
        "<p class='warn'>The provider did not grant ongoing access, so this connection "
        "stops working when its first token expires.</p>")
    return _page(f"Connected: {route}",
                 f"<h1>Connected to {_e(route)}{' as ' + _e(account) if account else ''}</h1>"
                 "<p>Go back to your AI app and try again. Your app now acts as you on this "
                 "server, and only for your requests.</p>" + note +
                 f"<p class='dim'><a href='/connect/{quote(tenant_id)}'>Your connections</a></p>")
