"""Portal SSO: sign a human in through the tenant's own IdP.

The portal authenticates with a shared tenant API key kept in browser storage,
so every administrative action is attributed to a tenant rather than a person.
These routes are the login half of fixing that; the session half is in
storage/portal_sessions.py.

Authorization code flow with PKCE. A public client by default, so no IdP secret
lives in Shield at all; client_secret is supported only for IdPs that mandate a
confidential client.

Nothing here runs on the guard path. The only hosts contacted are the issuer
configured for that tenant, so this works in an air gap.

Spec: docs/spec-portal-sso.md PR 2
"""
import base64
import hashlib
import logging
import os
import secrets
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from core.oauth.oidc_client import (
    OIDCValidationError,
    discover_openid_config,
    oidc_registry,
    validate_id_token,
)
from core.oauth.tls_trust import httpx_verify
from storage.portal_sessions import (
    create_session,
    revoke_session,
    session_ttl,
)
from storage.tenant_store import kv_delete, kv_get, kv_set

logger = logging.getLogger("votal.portal_auth")

router = APIRouter(prefix="/v1/tenant/auth", tags=["portal-auth"])

COOKIE_NAME = "shield_portal_session"

_LOGIN_PREFIX = "portallogin:"
_LOGIN_TTL_SECONDS = 600

_TRUTHY = ("1", "true", "yes", "on")


# ── configuration ────────────────────────────────────────────────────────


def portal_base_url() -> str:
    """The externally visible base URL of this deployment.

    Explicit, never inferred from Host or X-Forwarded-Proto. Behind Railway,
    an ingress or any TLS-terminating proxy the app sees plain HTTP while the
    browser sees HTTPS, so an inferred redirect_uri would be http:// and the
    IdP would reject it as a mismatch. Inferring from a header would also mean
    trusting a header to build a security-relevant URL, which is the mistake
    this entire workstream started from.
    """
    return (os.environ.get("SHIELD_PORTAL_BASE_URL", "") or "").rstrip("/")


def _redirect_uri() -> str:
    base = portal_base_url()
    if not base:
        raise HTTPException(
            status_code=500,
            detail="SHIELD_PORTAL_BASE_URL is not set. SSO needs the "
                   "externally visible URL of this deployment to build the "
                   "redirect_uri your IdP has registered, e.g. "
                   "https://shield.example.com",
        )
    return f"{base}/v1/tenant/auth/callback"


def _cookie_secure() -> bool:
    """Secure unless explicitly disabled for local HTTP development."""
    return os.environ.get(
        "SHIELD_PORTAL_INSECURE_COOKIE", "").strip().lower() not in _TRUTHY


def _safe_next(raw: str) -> str:
    """A same-site path, or "/tenant".

    Validated as a PATH, never against a host allowlist. A value carrying a
    scheme or starting with // is dropped rather than sanitized: patching a
    hostile redirect target tends to leave a variant that still works.
    """
    raw = (raw or "").strip()
    if not raw.startswith("/") or raw.startswith("//") or "\\" in raw:
        return "/tenant"
    if "://" in raw:
        return "/tenant"
    return raw


# ── PKCE ─────────────────────────────────────────────────────────────────


def _pkce_pair() -> tuple:
    """(verifier, challenge). S256 only — `plain` defeats the purpose."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


# ── login transactions ───────────────────────────────────────────────────


def _put_login(state: str, payload: dict) -> None:
    kv_set(_LOGIN_PREFIX + state, payload, ttl=_LOGIN_TTL_SECONDS)


def _take_login(state: str) -> Optional[dict]:
    """Read-and-delete. Single use, which makes a replayed callback fail and
    also covers a user double-clicking the IdP's consent button."""
    if not state:
        return None
    record = kv_get(_LOGIN_PREFIX + state)
    kv_delete(_LOGIN_PREFIX + state)
    return record if isinstance(record, dict) else None


# ── admin decision ───────────────────────────────────────────────────────


def _claim_groups(claims: dict, groups_claim: str) -> list:
    raw = (claims or {}).get(groups_claim)
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(g) for g in raw]
    return []


def _is_admin(claims: dict, provider) -> bool:
    """True when the token carries one of the provider's admin groups.

    A provider with no admin_groups cannot be used for login at all (see
    _require_configured), so this never has to decide what an empty list means.
    """
    allowed = {str(g) for g in (provider.admin_groups or [])}
    return bool(allowed.intersection(_claim_groups(
        claims, provider.groups_claim or "groups")))


def _require_configured(provider, name: str) -> None:
    """Refuse to run a login against a provider that would admit everyone.

    An empty admin_groups is the permissive default this deliberately does not
    have: connect SSO and every account in the directory could write the agent
    registry. Refusing at login is louder than a warning in a log nobody reads,
    and the fix is one field.
    """
    if not (provider.admin_groups or []):
        raise HTTPException(
            status_code=503,
            detail=f"OIDC provider {name!r} has no admin_groups configured. "
                   f"Set the group or role values that should grant portal "
                   f"administration before enabling SSO — an empty list would "
                   f"mean every account in your directory can administer this "
                   f"tenant.",
        )


# ── routes ───────────────────────────────────────────────────────────────


@router.get("/providers")
async def list_providers(tenant: str = ""):
    """Which IdPs this tenant can sign in with. Drives the login screen.

    Deliberately unauthenticated: the login screen has no credential yet. It
    returns names and issuers only — never client_secret, and never whether a
    tenant exists, so it cannot be used to enumerate tenants.
    """
    if not tenant:
        return {"providers": [], "sso_available": False}
    try:
        providers = await oidc_registry.get_providers(tenant)
    except Exception:
        providers = {}
    out = [
        {"name": name, "issuer": p.issuer, "configured": bool(p.admin_groups)}
        for name, p in (providers or {}).items()
    ]
    return {"providers": out, "sso_available": bool(out)}


@router.get("/login")
async def login(request: Request, tenant: str = "", provider: str = ""):
    """Begin sign-in: 302 to the IdP with PKCE and a server-side state.

    `next` is read from the query string rather than declared as a parameter,
    because naming it that way would shadow the builtin inside this function.
    """
    next_path = request.query_params.get("next", "")
    if not tenant:
        raise HTTPException(status_code=400, detail="tenant is required")

    providers = await oidc_registry.get_providers(tenant)
    if not providers:
        raise HTTPException(
            status_code=404,
            detail=f"no OIDC provider configured for tenant {tenant!r}")

    # Deterministic when a tenant has several and the caller named none.
    name = provider or sorted(providers)[0]
    cfg = providers.get(name)
    if cfg is None:
        raise HTTPException(status_code=404, detail=f"unknown provider {name!r}")

    _require_configured(cfg, name)

    try:
        discovery = await discover_openid_config(cfg.issuer)
    except Exception as e:
        # Name the issuer. A blank redirect back to the login screen reads as
        # "wrong password" and sends people to reset credentials that are fine.
        raise HTTPException(
            status_code=502,
            detail=f"could not reach the IdP at {cfg.issuer}: {e}")

    authorize_url = discovery.get("authorization_endpoint")
    if not authorize_url:
        raise HTTPException(
            status_code=502,
            detail=f"no authorization_endpoint in discovery for {cfg.issuer}")

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    _put_login(state, {
        "tenant_id": tenant,
        "provider": name,
        # Stays server-side. A verifier that reached the browser would make
        # PKCE decorative.
        "code_verifier": verifier,
        "redirect_after": _safe_next(next_path),
    })

    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": _redirect_uri(),
        "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{authorize_url}?{urlencode(params)}",
                            status_code=302)


@router.get("/callback")
async def callback(request: Request, code: str = "", state: str = "",
                   error: str = "", error_description: str = ""):
    """Finish sign-in: exchange, verify, create the session, set the cookie."""
    if error:
        raise HTTPException(status_code=400,
                            detail=f"IdP refused the login: {error} "
                                   f"{error_description}".strip())

    login_tx = _take_login(state)
    if login_tx is None:
        # Unknown, expired or already used. All three are the same answer, and
        # a more specific message would help someone probing.
        raise HTTPException(
            status_code=400,
            detail="login state is unknown, expired or already used. "
                   "Start again from the sign-in page.")
    if not code:
        raise HTTPException(status_code=400, detail="no authorization code")

    tenant_id = login_tx.get("tenant_id", "")
    cfg = await oidc_registry.get_provider(tenant_id, login_tx.get("provider", ""))
    if cfg is None:
        raise HTTPException(status_code=404, detail="provider no longer configured")
    _require_configured(cfg, login_tx.get("provider", ""))

    try:
        discovery = await discover_openid_config(cfg.issuer)
        token_url = discovery.get("token_endpoint")
    except Exception as e:
        raise HTTPException(status_code=502,
                            detail=f"could not reach the IdP at {cfg.issuer}: {e}")
    if not token_url:
        raise HTTPException(status_code=502, detail="no token_endpoint in discovery")

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _redirect_uri(),
        "client_id": cfg.client_id,
        "code_verifier": login_tx.get("code_verifier", ""),
    }
    if cfg.client_secret:
        form["client_secret"] = cfg.client_secret

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=httpx_verify()) as client:
            resp = await client.post(token_url, data=form)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"token exchange failed: {e}")

    if resp.status_code != 200:
        # The IdP's body can contain the code; log the status only.
        logger.warning("token exchange rejected by %s: %s",
                       cfg.issuer, resp.status_code)
        raise HTTPException(status_code=401,
                            detail="the IdP rejected the authorization code")

    id_token = (resp.json() or {}).get("id_token", "")
    if not id_token:
        raise HTTPException(status_code=401, detail="no id_token in the response")

    try:
        claims = await validate_id_token(id_token, cfg)
    except OIDCValidationError as e:
        raise HTTPException(status_code=401, detail=f"id_token rejected: {e}")

    # Belt and braces over validate_id_token's own issuer check: the provider
    # is looked up by the tenant recorded in the login transaction, so a token
    # from another tenant's IdP cannot open a session here.
    if str(claims.get("iss", "")).rstrip("/") != cfg.issuer.rstrip("/"):
        raise HTTPException(status_code=401, detail="issuer mismatch")

    session_id = create_session(
        tenant_id,
        {"sub": claims.get("sub"), "email": claims.get("email", ""),
         "name": claims.get("name", ""), "issuer": cfg.issuer},
        is_admin=_is_admin(claims, cfg),
    )

    response = RedirectResponse(_safe_next(login_tx.get("redirect_after", "")),
                                status_code=302)
    response.set_cookie(
        COOKIE_NAME, session_id,
        max_age=session_ttl(),
        httponly=True,
        secure=_cookie_secure(),
        # Lax, not Strict: the IdP redirects back with a top-level GET and
        # Strict would strip the cookie from exactly that request — the one
        # that creates the session.
        samesite="lax",
        path="/",
    )
    logger.info("portal sign-in: tenant=%s sub=%s admin=%s",
                tenant_id, claims.get("sub"), _is_admin(claims, cfg))
    return response


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Destroy the session and clear the cookie.

    Always 200, even with no session: a logout that reports "you were not
    signed in" is noise, and the caller wanted to end up signed out.
    """
    session_id = request.cookies.get(COOKIE_NAME, "")
    revoked = revoke_session(session_id) if session_id else False
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"success": True, "revoked": bool(revoked)}
