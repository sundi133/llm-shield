"""MCP sign-in: a person signs in to an MCP server through their company's SSO.

An MCP client (Claude, Cursor, VS Code) that gets a 401 from a gateway URL
reads its protected-resource metadata, finds Shield's authorization server, and
sends the person to `/oauth/authorize` with `resource` set to that URL. This
module takes it from there:

1. `begin_sign_in` (called by /oauth/authorize): checks the tenant has turned
   sign-in on, then redirects to the tenant's own identity provider with PKCE
   and a nonce. The IdP leg reuses the portal SSO callback, so a tenant that
   already set up portal SSO registers nothing new with its IdP.
2. `complete_sign_in` (called by the portal callback once the id_token is
   verified): checks the nonce and the allowed groups, creates or refreshes the
   person (storage/principal_store.py), derives their roles with the tenant's
   role-binding config, and either asks for consent or issues the code.
3. `/oauth/consent`: the person approves the client. Self-registered clients
   always ask; clients the tenant registered itself do not. An approval is
   remembered for 90 days per person, client and server.

The code goes back to the client, which redeems it at /oauth/token for an
access token whose audience is that one gateway URL and which names the person.

Admin plane only. Nothing here runs on the guard path.

Spec: docs/specs/mcp-verified-callers-and-user-credentials.md (§4.5)
"""

from __future__ import annotations

import hashlib
import html
import logging
import secrets
import time
from typing import Optional
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from core.auth import get_tenant_from_request
from core.mcp.resource import parse_resource
from storage.tenant_store import kv_delete, kv_get, kv_set

logger = logging.getLogger("votal.mcp_signin")

router = APIRouter(tags=["mcp-signin"])

PURPOSE = "mcp_sign_in"
_TX_TTL_S = 600
_CONSENT_PREFIX = "shield:oauth:consent_tx:"
_REMEMBER_PREFIX = "shield:oauth:consent:"
_REMEMBER_TTL_S = 90 * 24 * 3600
CONSENT_COOKIE = "shield_mcp_consent"
_MAX_NAME = 100


def _hash(value: str) -> str:
    return hashlib.sha256((value or "").encode()).hexdigest()


def _error_redirect(redirect_uri: str, state: str, error: str, description: str):
    """RFC 6749 §4.1.2.1: once the client and its redirect URI are known good,
    errors go back to the client, which can show them to the person."""
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


def _code_redirect(redirect_uri: str, state: str, code: str):
    params = {"code": code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


# ── 1. begin ─────────────────────────────────────────────────────────────


async def begin_sign_in(*, client, redirect_uri: str, code_challenge: str,
                        scope: str, state: str, resource: str):
    """Start sign-in for a validated client and redirect URI."""
    from api.routes_portal_auth import _pkce_pair, _put_login, _redirect_uri
    from core.oauth.oidc_client import discover_openid_config, oidc_registry
    from storage.identity_policy import get_policy

    tenant_id, route = parse_resource(resource)
    if client.tenant_id and client.tenant_id != tenant_id:
        return _error_redirect(redirect_uri, state, "unauthorized_client",
                               "this client is registered to a different organization")

    policy = get_policy(tenant_id)
    sign_in = policy["mcp_sign_in"]
    if not sign_in["enabled"]:
        return _error_redirect(redirect_uri, state, "access_denied",
                               "sign-in to this MCP server is not enabled")

    providers = await oidc_registry.get_providers(tenant_id) or {}
    name = sign_in["provider"] or (sorted(providers)[0] if providers else "")
    cfg = providers.get(name)
    if cfg is None:
        return _error_redirect(redirect_uri, state, "access_denied",
                               "no identity provider is configured for sign-in")
    try:
        authorize_url = (await discover_openid_config(cfg.issuer)).get("authorization_endpoint")
        idp_redirect = _redirect_uri()
    except Exception as e:      # noqa: BLE001 - the person sees a clean error
        logger.warning("mcp sign-in: cannot start for tenant=%s: %s", tenant_id, e)
        return _error_redirect(redirect_uri, state, "temporarily_unavailable",
                               "the identity provider could not be reached")
    if not authorize_url:
        return _error_redirect(redirect_uri, state, "temporarily_unavailable",
                               "the identity provider has no authorization endpoint")

    verifier, challenge = _pkce_pair()
    nonce = secrets.token_urlsafe(24)
    idp_state = secrets.token_urlsafe(32)
    _put_login(idp_state, {
        "purpose": PURPOSE, "tenant_id": tenant_id, "provider": name,
        "code_verifier": verifier, "nonce": nonce,
        "client_id": client.client_id, "redirect_uri": redirect_uri,
        "code_challenge": code_challenge, "scope": scope or "mcp",
        "state": state, "resource": resource, "route": route,
        "expires_at": int(time.time()) + _TX_TTL_S,
    })
    params = {
        "response_type": "code", "client_id": cfg.client_id,
        "redirect_uri": idp_redirect, "scope": "openid profile email",
        "state": idp_state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{authorize_url}?{urlencode(params)}", status_code=302)


# ── 2. complete ──────────────────────────────────────────────────────────


async def complete_sign_in(request: Request, tx: dict, claims: dict, cfg):
    """Finish sign-in from verified id_token claims."""
    from api.routes_portal_auth import _claim_groups, _cookie_secure
    from core.identity_resolution import claim_config, extract_roles
    from storage.identity_policy import get_policy, sign_in_allowed
    from storage.oauth_store import get_client
    from storage.principal_store import is_active, upsert_user

    redirect_uri, state = tx.get("redirect_uri", ""), tx.get("state", "")
    if int(tx.get("expires_at") or 0) < int(time.time()):
        raise HTTPException(400, "sign-in expired. Start again from your MCP client.")
    if not tx.get("nonce") or claims.get("nonce") != tx.get("nonce"):
        raise HTTPException(401, "id_token nonce does not match this sign-in")

    tenant_id = tx["tenant_id"]
    groups = _claim_groups(claims, cfg.groups_claim or "groups")
    if not sign_in_allowed(get_policy(tenant_id), groups):
        logger.info("mcp sign-in refused: tenant=%s sub=%s not in an allowed group",
                    tenant_id, claims.get("sub"))
        return _error_redirect(redirect_uri, state, "access_denied",
                               "your account is not in a group allowed to use this MCP server")

    cc = claim_config(tenant_id)
    roles = list(extract_roles(claims, cc["role_claim"], cc["role_map"], cc["role_allowlist"]))
    person = upsert_user(tenant_id, issuer=cfg.issuer, sub=str(claims.get("sub") or ""),
                         email=str(claims.get("email") or ""), name=str(claims.get("name") or ""),
                         groups=groups, roles=roles)
    if not is_active(person):
        return _error_redirect(redirect_uri, state, "access_denied",
                               "your access to this organization's MCP servers is suspended")

    client = await get_client(tx["client_id"])
    if client is None:
        raise HTTPException(400, "the MCP client is no longer registered")
    principal = {"id": person["id"], "type": person["type"], "email": person.get("email", ""),
                 "roles": person.get("roles", []), "issuer": cfg.issuer}

    # Clients the tenant registered itself are trusted; self-registered ones ask.
    if client.tenant_id == tenant_id or _remembered(tenant_id, person["id"], client.client_id,
                                                    tx["resource"]):
        return await _issue_code(tx, principal)

    tx_id = secrets.token_urlsafe(32)
    browser = secrets.token_urlsafe(32)
    kv_set(_CONSENT_PREFIX + tx_id, {**tx, "principal": principal,
                                     "browser": _hash(browser),
                                     "client_name": (client.client_name or "")[:_MAX_NAME],
                                     "expires_at": int(time.time()) + _TX_TTL_S},
           ttl=_TX_TTL_S)
    resp = RedirectResponse(f"/oauth/consent?{urlencode({'tx': tx_id})}", status_code=302)
    resp.set_cookie(CONSENT_COOKIE, browser, max_age=_TX_TTL_S, httponly=True,
                    secure=_cookie_secure(), samesite="lax", path="/oauth/consent")
    return resp


async def _issue_code(tx: dict, principal: dict):
    from storage.oauth_store import AuthorizationCode, save_auth_code
    code = secrets.token_urlsafe(32)
    await save_auth_code(AuthorizationCode(
        code=code, client_id=tx["client_id"], redirect_uri=tx["redirect_uri"],
        code_challenge=tx["code_challenge"], code_challenge_method="S256",
        scope=tx.get("scope") or "mcp", tenant_id=tx["tenant_id"],
        user_sub=principal["id"], created_at=int(time.time()),
        resource=tx["resource"], principal=principal))
    logger.info("mcp sign-in: tenant=%s principal=%s client=%s route=%s",
                tx["tenant_id"], principal["id"], tx["client_id"], tx.get("route"))
    return _code_redirect(tx["redirect_uri"], tx.get("state", ""), code)


def _remember_key(tenant_id: str, pid: str, client_id: str, resource: str) -> str:
    return f"{_REMEMBER_PREFIX}{tenant_id}:{pid}:{client_id}:{_hash(resource)[:16]}"


def _remembered(tenant_id: str, pid: str, client_id: str, resource: str) -> bool:
    rec = kv_get(_remember_key(tenant_id, pid, client_id, resource))
    return isinstance(rec, dict) and int(rec.get("expires_at") or 0) > int(time.time())


# ── 3. consent ───────────────────────────────────────────────────────────


def _load_consent(request: Request, tx_id: str, *, consume: bool) -> Optional[dict]:
    key = _CONSENT_PREFIX + (tx_id or "")
    tx = kv_get(key) if tx_id else None
    if consume and tx_id:
        kv_delete(key)
    if not isinstance(tx, dict) or int(tx.get("expires_at") or 0) < int(time.time()):
        return None
    # Bound to the browser that signed in, so a consent link cannot be
    # completed by anyone it is forwarded to.
    cookie = request.cookies.get(CONSENT_COOKIE, "")
    if not cookie or not secrets.compare_digest(_hash(cookie), tx.get("browser", "")):
        return None
    return tx


_PAGE_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                               "form-action 'self'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Allow access</title><style>"
        "body{font-family:Arial,sans-serif;max-width:480px;margin:48px auto;padding:0 16px;"
        "color:#1a1a1a}h1{font-size:20px}.box{border:1px solid #ddd;border-radius:8px;"
        "padding:16px;margin:16px 0}dt{color:#666;font-size:13px;margin-top:8px}dd{margin:0}"
        "button{font-size:15px;padding:10px 18px;border-radius:6px;border:1px solid #888;"
        "margin-right:8px;cursor:pointer}.ok{background:#1a1a1a;color:#fff}"
        "</style></head><body>" + body + "</body></html>",
        status_code=status, headers=_PAGE_HEADERS)


@router.get("/oauth/consent")
async def consent_page(request: Request, tx: str = ""):
    rec = _load_consent(request, tx, consume=False)
    if rec is None:
        return _page("<h1>This request has expired</h1>"
                     "<p>Start again from your MCP client.</p>", status=400)
    e = html.escape
    back_to = urlparse(rec["redirect_uri"]).netloc or rec["redirect_uri"]
    return _page(
        f"<h1>Allow {e(rec.get('client_name') or 'this app')} to use "
        f"{e(rec.get('route', ''))}?</h1>"
        "<div class='box'><dl>"
        f"<dt>App</dt><dd>{e(rec.get('client_name') or rec['client_id'])}</dd>"
        f"<dt>Returns you to</dt><dd>{e(back_to)}</dd>"
        f"<dt>Server</dt><dd>{e(rec.get('route', ''))}</dd>"
        f"<dt>Signed in as</dt><dd>{e(rec['principal'].get('email') or rec['principal']['id'])}</dd>"
        "</dl></div>"
        "<p>The app will act as you on this server, under your organization's policies. "
        "Only allow apps you started yourself.</p>"
        "<form method='post' action='/oauth/consent'>"
        f"<input type='hidden' name='tx' value='{e(tx)}'>"
        "<button class='ok' name='decision' value='allow'>Allow</button>"
        "<button name='decision' value='deny'>Deny</button></form>")


@router.post("/oauth/consent")
async def consent_decision(request: Request):
    form = await request.form()
    rec = _load_consent(request, str(form.get("tx", "")), consume=True)
    if rec is None:
        return _page("<h1>This request has expired</h1>"
                     "<p>Start again from your MCP client.</p>", status=400)
    if form.get("decision") != "allow":
        return _error_redirect(rec["redirect_uri"], rec.get("state", ""), "access_denied",
                               "you declined access")
    principal = rec["principal"]
    kv_set(_remember_key(rec["tenant_id"], principal["id"], rec["client_id"], rec["resource"]),
           {"at": int(time.time()), "expires_at": int(time.time()) + _REMEMBER_TTL_S},
           ttl=_REMEMBER_TTL_S)
    resp = await _issue_code(rec, principal)
    resp.delete_cookie(CONSENT_COOKIE, path="/oauth/consent")
    return resp


# ── tenant settings ──────────────────────────────────────────────────────


@router.get("/v1/tenant/me/identity/policy")
async def get_identity_policy(request: Request):
    from storage.identity_policy import get_policy
    return get_policy(get_tenant_from_request(request))


@router.put("/v1/tenant/me/identity/policy")
async def put_identity_policy(request: Request):
    from core.auth import audit_actor, require_portal_admin
    from storage.admin_audit import log_admin_action
    from storage.identity_policy import get_policy, set_policy
    tenant_id = get_tenant_from_request(request)
    require_portal_admin(request)
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        return JSONResponse(status_code=422, content={"detail": "expected a JSON object"})
    before = get_policy(tenant_id)
    try:
        after = set_policy(tenant_id, body)
    except ValueError as e:
        return JSONResponse(status_code=422, content={"detail": str(e)})
    log_admin_action(action="identity.mcp_sign_in.update",
                     actor=audit_actor(request, tenant_id), tenant_id=tenant_id,
                     source_ip=request.client.host if request.client else "",
                     before=before, after=after)
    return after
