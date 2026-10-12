"""Admin-plane SSO: platform operators sign in with Votal's own IdP.

The Admin Console authenticates with a shared X-Admin-Key today. This adds SSO
as the primary operator login, gated to an operator group, so admin actions are
attributed to a person and access is centrally deprovisionable. X-Admin-Key
stays as a break-glass credential (enforced in core.auth.AuthMiddleware).

Deliberately distinct from the tenant portal SSO (api/routes_portal_auth):
- A SINGLE operator IdP, configured by the platform operator via environment,
  NOT per-tenant and NOT editable from inside the console — so a tenant-plane
  compromise cannot touch it.
- Gated to SHIELD_ADMIN_OPERATOR_GROUPS (fail-closed: empty = SSO unavailable).
- Mints an admin-operator session (storage.admin_sessions), never tenant-scoped.

Env config:
    SHIELD_ADMIN_OIDC_ISSUER         the operator IdP issuer URL
    SHIELD_ADMIN_OIDC_CLIENT_ID      Shield's client_id at that IdP
    SHIELD_ADMIN_OIDC_CLIENT_SECRET  optional (PKCE public client preferred)
    SHIELD_ADMIN_OIDC_AUDIENCE       optional (defaults to client_id)
    SHIELD_ADMIN_OPERATOR_GROUPS     comma-separated; a user needs one of these
    SHIELD_ADMIN_GROUPS_CLAIM        optional (default "groups")
    SHIELD_PORTAL_BASE_URL           base for the redirect_uri (shared)

Spec: docs/specs/spec-sso-primary-login.md PR 5
"""
import logging
import os
import secrets
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from core.oauth.oidc_client import (
    OIDCProvider, OIDCValidationError, discover_openid_config, validate_id_token,
)
from core.oauth.tls_trust import httpx_verify
from storage.admin_sessions import create_session, revoke_session, session_ttl
from storage.tenant_store import kv_get, kv_set, kv_delete
# Reuse the pure helpers from the tenant flow (PKCE, groups normalization).
from api.routes_portal_auth import _pkce_pair, _claim_groups, portal_base_url

logger = logging.getLogger("votal.admin_auth")

router = APIRouter(prefix="/v1/admin/auth", tags=["admin-auth"])

ADMIN_COOKIE_NAME = "shield_admin_session"
_LOGIN_PREFIX = "adminlogin:"
_LOGIN_TTL_SECONDS = 600
_TRUTHY = ("1", "true", "yes", "on")


# ── config (env, single operator IdP) ────────────────────────────────────


def _operator_groups() -> list:
    raw = os.environ.get("SHIELD_ADMIN_OPERATOR_GROUPS", "")
    return [g.strip() for g in raw.split(",") if g.strip()]


def _admin_provider() -> Optional[OIDCProvider]:
    """The operator IdP, or None when admin SSO is not configured.

    Fail-closed: without an issuer, a client_id, AND at least one operator group,
    admin SSO is simply unavailable (so an empty group list can never mean
    'every authenticated user is an operator').
    """
    issuer = os.environ.get("SHIELD_ADMIN_OIDC_ISSUER", "").strip()
    client_id = os.environ.get("SHIELD_ADMIN_OIDC_CLIENT_ID", "").strip()
    groups = _operator_groups()
    if not issuer or not client_id or not groups:
        return None
    return OIDCProvider(
        issuer=issuer,
        client_id=client_id,
        audience=os.environ.get("SHIELD_ADMIN_OIDC_AUDIENCE", "").strip(),
        client_secret=os.environ.get("SHIELD_ADMIN_OIDC_CLIENT_SECRET", "").strip(),
        admin_groups=groups,   # reused as the OPERATOR-group gate
        groups_claim=os.environ.get("SHIELD_ADMIN_GROUPS_CLAIM", "groups").strip() or "groups",
    )


def _redirect_uri() -> str:
    return f"{portal_base_url()}/v1/admin/auth/callback"


def _cookie_secure() -> bool:
    return os.environ.get("SHIELD_PORTAL_INSECURE_COOKIE", "").strip().lower() not in _TRUTHY


def _safe_next(raw: str) -> str:
    """A same-site path, or "/admin". Drops schemes, //, and backslashes."""
    raw = (raw or "").strip()
    if not raw.startswith("/") or raw.startswith("//") or "\\" in raw:
        return "/admin"
    if "://" in raw:
        return "/admin"
    return raw


def _is_operator(claims: dict, provider: OIDCProvider) -> bool:
    allowed = {str(g) for g in provider.admin_groups}
    have = {str(g) for g in _claim_groups(claims, provider.groups_claim or "groups")}
    return bool(allowed.intersection(have))


def _matched_roles(claims: dict, provider: OIDCProvider) -> list:
    allowed = {str(g) for g in provider.admin_groups}
    return [g for g in _claim_groups(claims, provider.groups_claim or "groups")
            if str(g) in allowed]


def _put_login(state: str, payload: dict) -> None:
    kv_set(_LOGIN_PREFIX + state, payload, ttl=_LOGIN_TTL_SECONDS)


def _take_login(state: str) -> Optional[dict]:
    if not state:
        return None
    payload = kv_get(_LOGIN_PREFIX + state)
    kv_delete(_LOGIN_PREFIX + state)
    return payload if isinstance(payload, dict) else None


# ── handlers ──────────────────────────────────────────────────────────────


@router.get("/providers")
async def admin_sso_available():
    """Whether admin SSO is configured (for the login UI). Unauthenticated."""
    p = _admin_provider()
    return {"sso_available": p is not None, "issuer": p.issuer if p else ""}


@router.get("/login")
async def login(request: Request):
    """Start the operator OIDC auth-code + PKCE flow."""
    next_path = request.query_params.get("next", "")
    provider = _admin_provider()
    if provider is None:
        raise HTTPException(status_code=503, detail="Admin SSO is not configured.")

    try:
        discovery = await discover_openid_config(provider.issuer)
        authorize_url = discovery["authorization_endpoint"]
    except Exception as e:
        logger.warning("admin OIDC discovery failed: %s", e)
        raise HTTPException(status_code=502, detail="Operator IdP is unreachable.")

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    _put_login(state, {
        "code_verifier": verifier,
        "nonce": nonce,
        "redirect_after": _safe_next(next_path),
    })
    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": _redirect_uri(),
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{authorize_url}?{urlencode(params)}", status_code=302)


@router.get("/callback")
async def callback(request: Request, code: str = "", state: str = "",
                   error: str = "", error_description: str = ""):
    if error:
        logger.info("admin OIDC error: %s", error)
        raise HTTPException(status_code=400, detail="Sign-in was cancelled or failed.")

    login_tx = _take_login(state)
    if not login_tx or not code:
        # Unknown/expired/replayed state, or no code — one message, no oracle.
        raise HTTPException(status_code=400, detail="Invalid or expired sign-in request.")

    provider = _admin_provider()
    if provider is None:
        raise HTTPException(status_code=503, detail="Admin SSO is not configured.")

    try:
        discovery = await discover_openid_config(provider.issuer)
        token_url = discovery["token_endpoint"]
    except Exception as e:
        logger.warning("admin OIDC discovery failed: %s", e)
        raise HTTPException(status_code=502, detail="Operator IdP is unreachable.")

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _redirect_uri(),
        "client_id": provider.client_id,
        "code_verifier": login_tx["code_verifier"],
    }
    if provider.client_secret:
        form["client_secret"] = provider.client_secret

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=httpx_verify()) as client:
            resp = await client.post(token_url, data=form)
    except Exception as e:
        logger.warning("admin token exchange failed: %s", e)
        raise HTTPException(status_code=502, detail="Token exchange failed.")
    if resp.status_code != 200:
        logger.warning("admin token endpoint http=%s", resp.status_code)
        raise HTTPException(status_code=401, detail="Token exchange rejected.")

    id_token = (resp.json() or {}).get("id_token", "")
    if not id_token:
        raise HTTPException(status_code=401, detail="No id_token returned.")

    try:
        claims = await validate_id_token(id_token, provider)
    except OIDCValidationError as e:
        logger.info("admin id_token invalid: %s", e)
        raise HTTPException(status_code=401, detail="Identity token failed validation.")

    # Belt-and-braces issuer check beyond what validate_id_token already does.
    if str(claims.get("iss", "")).rstrip("/") != provider.issuer.rstrip("/"):
        raise HTTPException(status_code=401, detail="Issuer mismatch.")

    # Nonce: validate_id_token does not check it; we must, to bind this token to
    # THIS login request (replay / token-injection defense).
    if str(claims.get("nonce", "")) != str(login_tx.get("nonce", "")):
        raise HTTPException(status_code=401, detail="Nonce mismatch.")

    # Operator-group gate — fail closed. A valid IdP user who is not in an
    # operator group is NOT an operator: 403, not a session.
    if not _is_operator(claims, provider):
        logger.warning("admin SSO denied: sub=%s not in operator groups",
                       claims.get("sub", "?"))
        raise HTTPException(status_code=403,
                            detail="Your account is not a platform operator.")

    session_id = create_session(
        {"sub": claims.get("sub"), "email": claims.get("email", ""),
         "name": claims.get("name", ""), "issuer": provider.issuer},
        roles=_matched_roles(claims, provider),
    )
    response = RedirectResponse(_safe_next(login_tx.get("redirect_after", "")),
                                status_code=302)
    response.set_cookie(
        ADMIN_COOKIE_NAME, session_id,
        max_age=session_ttl(), httponly=True, secure=_cookie_secure(),
        samesite="lax", path="/",
    )
    return response


@router.post("/logout")
async def logout(request: Request, response: Response):
    sid = request.cookies.get(ADMIN_COOKIE_NAME, "")
    revoked = revoke_session(sid) if sid else False
    response.delete_cookie(ADMIN_COOKIE_NAME, path="/")
    return {"success": True, "revoked": bool(revoked)}
