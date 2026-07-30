"""Upstream credential modes for the MCP gateway.

Eight ways an upstream authenticates, one runtime story. See
docs/spec-mcp-credential-modes.md.

    1 no-auth        3 static bearer/PAT    5 device flow      7 GitHub App
    2 api key        4 auth code + PKCE     6 client creds     8 gateway capability

Modes 1-3 are **static**: the operator supplies a header (or none) and there is
nothing to acquire or renew. They have no provider and no broker record — the
absence of a record *is* the mode, which is what keeps every already-configured
route untouched.

Modes 4-8 acquire a credential and keep it fresh. They differ only in *how* the
credential is obtained; the timer, the distributed lock, the single-flight, the
status model and the audit are identical, so they live here once. That is the whole
reason this module exists: writing the refresh loop per mode would have meant four
near-copies with four sets of bugs.

**Admin plane owns acquisition and renewal.** The data plane only materializes the
``shield://`` reference this module keeps current, which is what keeps OAuth
round-trips off the guard path.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional, Protocol
from urllib.parse import urlparse

logger = logging.getLogger("votal.mcp_credentials")

# ── modes ────────────────────────────────────────────────────────────

MODE_NONE = "none"                      # 1
MODE_API_KEY = "api_key"                # 2
MODE_STATIC_BEARER = "static_bearer"    # 3
MODE_AUTH_CODE = "auth_code"            # 4
MODE_DEVICE_CODE = "device_code"        # 5
MODE_CLIENT_CREDENTIALS = "client_credentials"  # 6
MODE_GITHUB_APP = "github_app"          # 7
MODE_CAPABILITY = "capability"          # 8

#: Modes with nothing to acquire or renew. No provider, no broker record, no timer.
STATIC_MODES = (MODE_NONE, MODE_API_KEY, MODE_STATIC_BEARER)

#: Modes that need a human in the loop to acquire (but not to renew).
INTERACTIVE_MODES = (MODE_AUTH_CODE, MODE_DEVICE_CODE)

ALL_MODES = STATIC_MODES + (
    MODE_AUTH_CODE, MODE_DEVICE_CODE, MODE_CLIENT_CREDENTIALS,
    MODE_GITHUB_APP, MODE_CAPABILITY,
)

#: How early to renew. A credential that expires mid-flight is an outage, so the
#: loop always acts before expiry rather than on it.
_MARGIN_ENV = "SHIELD_OAUTH_REFRESH_MARGIN_S"
_DEFAULT_MARGIN = 300

_TIMEOUT = 15.0


class CredentialError(Exception):
    """Acquisition or renewal failed. ``status`` is the HTTP code to surface.

    ``permanent`` distinguishes "a human must fix this" (a revoked grant, a wrong
    client secret) from "try again later" (a 503, a timeout). The loop must not
    retry a permanent failure: it cannot recover, and hammering the provider
    buries the one state an operator has to act on.
    """

    def __init__(self, status: int, message: str, *, permanent: bool = False):
        super().__init__(message)
        self.status = status
        self.message = message
        self.permanent = permanent


def modes_enabled() -> bool:
    """Escape hatch: SHIELD_MCP_CREDENTIAL_MODES=0 disables acquisition + renewal."""
    return os.getenv("SHIELD_MCP_CREDENTIAL_MODES", "1").strip().lower() not in (
        "0", "false", "no", "off",
    )


def refresh_margin_seconds() -> int:
    try:
        return max(0, int(os.getenv(_MARGIN_ENV, str(_DEFAULT_MARGIN))))
    except ValueError:
        return _DEFAULT_MARGIN


def is_static(mode: Optional[str]) -> bool:
    """Whether this mode needs no acquisition. Absent mode counts as static —
    an existing route with a literal header must keep working untouched."""
    return (mode or MODE_NONE) in STATIC_MODES


# ── provider interface ───────────────────────────────────────────────

class CredentialProvider(Protocol):
    """One acquisition strategy.

    ``renew`` covers both *refresh* (mode 4/5, exchange a refresh token) and
    *re-acquire* (modes 6/7/8, request a brand new credential). Deliberately one
    method: the loop should not branch on mode, and the distinction is the
    strategy's business, not the scheduler's.
    """

    mode: str
    interactive: bool

    async def begin(self, ctx: "CredentialContext") -> dict: ...
    async def complete(self, ctx: "CredentialContext", **kwargs) -> dict: ...
    async def renew(self, ctx: "CredentialContext") -> dict: ...
    async def revoke(self, ctx: "CredentialContext") -> None: ...


class CredentialContext:
    """Everything a strategy needs, without reaching into request state.

    Passed explicitly rather than read from globals so a strategy is testable
    without a live tenant, and so the admin plane and the gateway's reactive path
    can drive the same code with different callers.
    """

    def __init__(self, *, tenant_id: str, route: str, record: dict,
                 upstream_url: str = "", actor: str = "system"):
        self.tenant_id = tenant_id
        self.route = route
        self.record = record
        self.upstream_url = upstream_url
        self.actor = actor

    @property
    def mode(self) -> str:
        return self.record.get("mode") or MODE_NONE

    def secret(self, ref_field: str) -> str:
        """Resolve a vault-referenced secret named in the record.

        Reads through the vault so a strategy never sees, and cannot accidentally
        persist, plaintext beyond the call that needs it.
        """
        ref = (self.record.get(ref_field) or "").replace("shield://", "").strip()
        if not ref:
            return ""
        from storage.vault_store import resolve_secret_value
        return resolve_secret_value(self.tenant_id, ref) or ""


class _NotInteractive:
    """Mixin: modes 6/7/8 acquire without a human, so begin/complete are errors.

    Raising beats returning None — a caller that mistakenly routes a
    non-interactive mode through the browser flow should fail loudly, not produce
    a dead authorize URL an operator would sit waiting on.
    """

    interactive = False

    async def begin(self, ctx: CredentialContext) -> dict:
        raise CredentialError(
            422, f"mode '{getattr(self, 'mode', '?')}' is acquired without a "
                 f"browser; call renew instead of connect", permanent=True)

    async def complete(self, ctx: CredentialContext, **kwargs) -> dict:
        raise CredentialError(
            422, f"mode '{getattr(self, 'mode', '?')}' has no callback step",
            permanent=True)


# ── credential persistence ───────────────────────────────────────────

def store_credential(ctx: CredentialContext, *, token: str,
                     expires_at: int, refresh_token: str = "") -> dict:
    """Write the acquired credential to the vault and update the record.

    The vault is the only place a token lands. Binding is the token endpoint's
    host — or the upstream's, for modes with no token endpoint — because the
    vault refuses a binding to a Shield host and materializes only on the leg out
    to the real upstream, which is exactly where this is used.
    """
    from storage.mcp_oauth_store import (STATUS_CONNECTED, access_ref,
                                         refresh_ref, update_status)
    from storage.vault_store import create_vault_entry

    endpoint = ctx.record.get("token_endpoint") or ctx.upstream_url or ""
    host = urlparse(endpoint).hostname or ""
    if not host:
        raise CredentialError(
            500, "cannot determine the binding host for this credential",
            permanent=True)

    create_vault_entry(ctx.tenant_id, access_ref(ctx.route), token, [host],
                       mode="inject")
    if refresh_token:
        create_vault_entry(ctx.tenant_id, refresh_ref(ctx.route), refresh_token,
                           [host], mode="inject")

    update_status(ctx.tenant_id, ctx.route, STATUS_CONNECTED,
                  expires_at=expires_at, mark_refreshed=True)
    return {"expires_at": expires_at}


def expiry_from(payload: dict, *, default_ttl: int = 3600) -> int:
    """Absolute expiry from a token response's ``expires_in``.

    Providers are inconsistent — some omit it, some send a string. A missing or
    unparseable value falls back to a conservative TTL rather than treating the
    credential as eternal, because assuming eternity is how you get a dead
    credential in production and no signal.
    """
    raw = payload.get("expires_in")
    try:
        ttl = int(raw)
    except (TypeError, ValueError):
        ttl = default_ttl
    if ttl <= 0:
        ttl = default_ttl
    return int(time.time()) + ttl


async def post_token_endpoint(client, endpoint: str, data: dict,
                              *, purpose: str) -> dict:
    """POST a token request, SSRF-guarded, with errors that do not leak the body.

    Shared by every OAuth-family mode. Distinguishes permanent failures — the
    OAuth error codes that mean a human must act — from transient ones, so the
    renewal loop knows whether retrying can possibly help.
    """
    from core.url_safety import UnsafeURLError, validate_outbound_url

    try:
        safe = validate_outbound_url(endpoint, purpose=purpose)
    except UnsafeURLError as e:
        # NOT permanent. This one error covers two very different causes: a
        # genuinely internal/blocked address (config, never recovers) and a
        # hostname that will not resolve right now (transient). Marking it
        # permanent would push a route to needs_consent over a DNS blip and stop
        # retrying it — human toil for a network hiccup. A truly bad address just
        # keeps failing with this message visible, which is the cheaper mistake.
        raise CredentialError(
            400,
            f"cannot reach the token endpoint: the host is not publicly "
            f"resolvable, or resolves to an internal address ({e})") from e

    try:
        resp = await client.post(safe, data=data, timeout=_TIMEOUT,
                                 headers={"Accept": "application/json"})
    except Exception as e:
        raise CredentialError(
            502, f"token request failed: {type(e).__name__}") from e

    try:
        payload = resp.json()
    except Exception:
        payload = {}

    if resp.status_code >= 400:
        error = str(payload.get("error") or "")[:64]
        # These mean the grant or the client is wrong. Retrying cannot fix them,
        # and a loop would hammer the provider while hiding the real condition.
        permanent = error in (
            "invalid_grant", "invalid_client", "unauthorized_client",
            "unsupported_grant_type", "invalid_scope",
        )
        raise CredentialError(
            502,
            f"token endpoint rejected the request (HTTP {resp.status_code}"
            + (f", {error}" if error else "") + ")",
            permanent=permanent)

    if not payload.get("access_token"):
        raise CredentialError(502, "token response contained no access_token")
    return payload


# ── the shared renewal loop ──────────────────────────────────────────

def due_for_renewal(record: dict, *, now: Optional[int] = None) -> bool:
    """Whether this route's credential should be renewed now.

    Delegates to the store so the scheduling rule lives in exactly one place —
    including the part that matters most: a route needing human re-consent is
    never renewed automatically.
    """
    from storage.mcp_oauth_store import due_for_refresh

    if is_static(record.get("mode")):
        return False
    return due_for_refresh(record, margin_seconds=refresh_margin_seconds(), now=now)


def _lock_key(tenant_id: str, route: str) -> str:
    return f"mcp_cred:lock:{tenant_id}:{route}"


def acquire_renewal_lock(tenant_id: str, route: str, *, ttl: int = 60) -> bool:
    """Best-effort single-flight across replicas and across planes.

    This matters more than it looks. Most providers **invalidate the old refresh
    token** when it is used, so two concurrent renewals can destroy a working
    credential: one succeeds, the other presents a now-dead refresh token and
    lands the route in needs_consent. The lock is what stops the first expiry
    under load from becoming an outage.

    Without Redis (dev/tests) there is one process, so there is nothing to
    serialize and this always succeeds.
    """
    from storage.tenant_store import _get_redis

    r = _get_redis()
    if not r:
        return True
    try:
        return bool(r.set(_lock_key(tenant_id, route), "1", nx=True, ex=ttl))
    except Exception:
        # A lock we cannot take is not a reason to skip a needed renewal; the
        # provider's own idempotency is the backstop.
        return True


def release_renewal_lock(tenant_id: str, route: str) -> None:
    from storage.tenant_store import _get_redis

    r = _get_redis()
    if not r:
        return
    try:
        r.delete(_lock_key(tenant_id, route))
    except Exception:
        pass


async def renew_route(tenant_id: str, route: str, *, actor: str = "system") -> dict:
    """Renew one route's credential. Never raises; returns an outcome dict.

    Returns ``{"renewed": bool, "status": str, "detail": str}``. Every failure is
    an outcome rather than an exception because this runs from a background timer
    where an unhandled error would kill the sweep for every other route.
    """
    from storage.mcp_oauth_store import (STATUS_ERROR, STATUS_NEEDS_CONSENT,
                                         get_broker, update_status)

    if not modes_enabled():
        return {"renewed": False, "status": "disabled", "detail": "feature disabled"}

    record = get_broker(tenant_id, route)
    if record is None:
        return {"renewed": False, "status": "absent", "detail": "no credential record"}
    if is_static(record.get("mode")):
        return {"renewed": False, "status": "static", "detail": "nothing to renew"}

    provider = get_provider(record.get("mode"))
    if provider is None:
        return {"renewed": False, "status": "unsupported",
                "detail": f"no provider for mode {record.get('mode')!r}"}

    if not acquire_renewal_lock(tenant_id, route):
        return {"renewed": False, "status": "locked",
                "detail": "another renewal is in flight"}

    cfg = {}
    try:
        from storage.mcp_gateway_store import get_upstream
        cfg = get_upstream(tenant_id, route) or {}
    except Exception:
        pass

    ctx = CredentialContext(tenant_id=tenant_id, route=route, record=record,
                            upstream_url=cfg.get("url") or "", actor=actor)
    try:
        out = await provider.renew(ctx)
        return {"renewed": True, "status": "connected",
                "detail": "", "expires_at": out.get("expires_at", 0)}
    except CredentialError as e:
        # A permanent failure is a human's problem; say so instead of retrying
        # forever and burying it.
        status = STATUS_NEEDS_CONSENT if e.permanent else STATUS_ERROR
        update_status(tenant_id, route, status, error=e.message)
        logger.warning("mcp-cred: renew failed for %s/%s (%s): %s",
                       tenant_id, route, status, e.message)
        return {"renewed": False, "status": status, "detail": e.message}
    except Exception as e:  # pragma: no cover - defensive
        update_status(tenant_id, route, STATUS_ERROR, error=type(e).__name__)
        logger.exception("mcp-cred: unexpected renew failure for %s/%s", tenant_id, route)
        return {"renewed": False, "status": STATUS_ERROR, "detail": type(e).__name__}
    finally:
        release_renewal_lock(tenant_id, route)


async def sweep_tenant(tenant_id: str) -> dict:
    """Renew every route of one tenant that is due. Returns a summary."""
    from storage.mcp_oauth_store import get_broker, list_brokered_routes

    renewed, skipped, failed = [], [], []
    for route in list_brokered_routes(tenant_id):
        record = get_broker(tenant_id, route)
        if not record or not due_for_renewal(record):
            skipped.append(route)
            continue
        out = await renew_route(tenant_id, route)
        (renewed if out["renewed"] else failed).append(route)
    return {"renewed": renewed, "skipped": skipped, "failed": failed}


# ── strategy registry ────────────────────────────────────────────────
#
# Populated at import by each strategy module. A dict rather than a chain of
# isinstance checks so adding mode 5/7 later touches nothing here.

_PROVIDERS: dict = {}


def register_provider(provider) -> None:
    _PROVIDERS[provider.mode] = provider


def get_provider(mode: Optional[str]):
    """The strategy for a mode, or None. Static modes correctly have none."""
    if not mode or is_static(mode):
        return None
    return _PROVIDERS.get(mode)


def supported_modes() -> list[str]:
    """Modes this build can actually acquire, plus the static ones."""
    return sorted(set(STATIC_MODES) | set(_PROVIDERS))


# ── mode 4: authorization code + PKCE ────────────────────────────────
#
# The only mode that needs a browser redirect. Discovery, registration and the
# authorize URL already shipped in core/mcp_oauth.py; this is the half that turns
# a consented code into a stored credential and keeps it alive.

class AuthCodeProvider:
    """OAuth 2.1 authorization code with PKCE, plus refresh-token renewal."""

    mode = MODE_AUTH_CODE
    interactive = True

    async def begin(self, ctx: CredentialContext) -> dict:
        # Handled by the connect endpoint, which owns discovery + registration +
        # pending-state storage. Kept explicit rather than silently unsupported.
        raise CredentialError(
            422, "use POST /servers/{route}/oauth/connect to begin this mode",
            permanent=True)

    async def complete(self, ctx: CredentialContext, *, code: str = "",
                       code_verifier: str = "", client=None, **kwargs) -> dict:
        """Exchange an authorization code for tokens.

        The verifier proves this is the same client that started the flow, which
        is what makes an intercepted code useless on its own.
        """
        if not code:
            raise CredentialError(400, "no authorization code supplied", permanent=True)

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": ctx.record.get("redirect_uri") or _redirect_uri(),
            "client_id": ctx.record.get("client_id") or "",
            "code_verifier": code_verifier,
        }
        secret = ctx.secret("client_secret_ref")
        if secret:
            data["client_secret"] = secret

        payload = await _with_client(client, lambda c: post_token_endpoint(
            c, ctx.record.get("token_endpoint") or "", data,
            purpose="oauth-token-exchange"))

        refresh = str(payload.get("refresh_token") or "")
        if not refresh:
            # Without one, this "connection" dies with its first access token.
            # Better to say so now than to look connected and fail in an hour.
            logger.warning(
                "mcp-cred: %s/%s exchanged a code but the provider returned no "
                "refresh_token; the credential cannot be kept alive",
                ctx.tenant_id, ctx.route)
        return store_credential(
            ctx, token=str(payload["access_token"]),
            expires_at=expiry_from(payload), refresh_token=refresh)

    async def renew(self, ctx: CredentialContext, *, client=None) -> dict:
        refresh = ctx.secret("refresh_token_ref")
        if not refresh:
            raise CredentialError(
                400, "no refresh token stored for this route; re-authorize it",
                permanent=True)

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": ctx.record.get("client_id") or "",
        }
        secret = ctx.secret("client_secret_ref")
        if secret:
            data["client_secret"] = secret

        payload = await _with_client(client, lambda c: post_token_endpoint(
            c, ctx.record.get("token_endpoint") or "", data,
            purpose="oauth-token-refresh"))

        # Providers that ROTATE refresh tokens return a new one and invalidate the
        # old. Dropping it here would strand the route at the next renewal, so a
        # returned value always replaces the stored one; an omitted value means
        # the provider kept the existing token valid.
        return store_credential(
            ctx, token=str(payload["access_token"]),
            expires_at=expiry_from(payload),
            refresh_token=str(payload.get("refresh_token") or ""))

    async def revoke(self, ctx: CredentialContext, *, client=None) -> None:
        endpoint = ctx.record.get("revocation_endpoint") or ""
        token = ctx.secret("refresh_token_ref") or ctx.secret("access_token_ref")
        if not endpoint or not token:
            return  # nothing published to revoke against; caller still deletes locally
        data = {"token": token, "client_id": ctx.record.get("client_id") or ""}
        secret = ctx.secret("client_secret_ref")
        if secret:
            data["client_secret"] = secret
        try:
            await _with_client(client, lambda c: post_token_endpoint(
                c, endpoint, data, purpose="oauth-revocation"))
        except CredentialError:
            # Revocation is best-effort: the local delete must still happen, or a
            # provider outage would leave an un-deletable route behind.
            logger.info("mcp-cred: revocation call failed for %s/%s",
                        ctx.tenant_id, ctx.route)


def _redirect_uri() -> str:
    from core.mcp_oauth import OAuthBrokerError, redirect_uri
    try:
        return redirect_uri()
    except OAuthBrokerError as e:
        raise CredentialError(e.status, e.message, permanent=True) from e


async def _with_client(client, fn):
    """Run fn with the supplied client, or a short-lived one.

    Injectable so strategies are testable without network, and so a caller that
    already has a session (the connect endpoint) does not open a second.
    """
    if client is not None:
        return await fn(client)
    import httpx
    async with httpx.AsyncClient(follow_redirects=True) as c:
        return await fn(c)


register_provider(AuthCodeProvider())


# ── mode 6: client credentials ───────────────────────────────────────
#
# The workhorse for enterprise upstreams: a machine identity, no user consent, no
# browser, no callback. Also the only OAuth mode with nothing to store between
# renewals — a fresh grant is cheaper than tracking a refresh token, so `renew`
# simply re-acquires.

class ClientCredentialsProvider(_NotInteractive):
    mode = MODE_CLIENT_CREDENTIALS

    async def renew(self, ctx: CredentialContext, *, client=None) -> dict:
        client_id = ctx.record.get("client_id") or ""
        secret = ctx.secret("client_secret_ref")
        if not client_id or not secret:
            raise CredentialError(
                400, "client_credentials needs a client_id and a stored client "
                     "secret", permanent=True)

        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }
        scopes = [s for s in (ctx.record.get("scopes") or []) if s]
        if scopes:
            data["scope"] = " ".join(scopes)

        payload = await _with_client(client, lambda c: post_token_endpoint(
            c, ctx.record.get("token_endpoint") or "", data,
            purpose="oauth-client-credentials"))

        # No refresh token by design (RFC 6749 §4.4.3 says not to issue one):
        # re-running the grant is the renewal.
        return store_credential(ctx, token=str(payload["access_token"]),
                                expires_at=expiry_from(payload))

    async def revoke(self, ctx: CredentialContext, *, client=None) -> None:
        # Nothing is delegated — the credential is Shield's own machine identity,
        # so there is no upstream grant to withdraw. Deleting the vault entry is
        # the whole revocation.
        return None


register_provider(ClientCredentialsProvider())


# ── mode 8: gateway-issued capability token ──────────────────────────
#
# The only mode with NO vendor credential: Shield mints a short-lived signed
# capability and the upstream verifies it against Shield's JWKS. That makes it the
# right default for in-cluster upstreams — there is no secret to leak, rotate, or
# have stolen, and it composes with isolation_ack for genuine non-bypassability.

#: Deliberately short. The token is minted per renewal, and a capability that
#: outlives its need is just a bearer token with extra steps.
CAPABILITY_TTL_SECONDS = 900


class CapabilityProvider(_NotInteractive):
    mode = MODE_CAPABILITY

    async def renew(self, ctx: CredentialContext, *, client=None) -> dict:
        """Mint a fresh capability for this route.

        Fails closed when the signer is unavailable: a route configured to present
        a minted capability must never silently fall back to calling the upstream
        with no credential at all.
        """
        try:
            from core.capabilities import mint_cap
            from core.identity import IdentityTuple
        except Exception as e:
            raise CredentialError(
                500, f"capability signing is unavailable: {type(e).__name__}",
                permanent=True) from e

        # The subject is the gateway acting for this tenant+route, not an end user.
        # Per-user capabilities need verified identity first, so binding one to a
        # self-asserted caller here would be a lie the upstream would believe.
        identity = IdentityTuple(
            user_sub=f"shield-gateway:{ctx.tenant_id}",
            agent_id=f"mcp-gateway:{ctx.route}",
            agent_instance_id=f"route-{ctx.route}",
            tenant_id=ctx.tenant_id,
            build_hash="gateway",
            model_version="n/a",
            session_id=f"route-{ctx.route}",
            trust_level="high",
            identity_method="gateway_minted",
        )
        ttl = int(ctx.record.get("capability_ttl") or CAPABILITY_TTL_SECONDS)
        try:
            token = mint_cap(
                identity=identity,
                tool=f"mcp:{ctx.route}",
                resource=ctx.upstream_url or ctx.record.get("issuer") or ctx.route,
                scope=[s for s in (ctx.record.get("scopes") or []) if s] or None,
                ttl_seconds=ttl,
            )
        except Exception as e:
            raise CredentialError(
                500, f"could not mint a capability: {type(e).__name__}",
                permanent=True) from e

        return store_credential(ctx, token=token,
                                expires_at=int(time.time()) + ttl)

    async def revoke(self, ctx: CredentialContext, *, client=None) -> None:
        # Capabilities are short-lived and not registered anywhere upstream;
        # deleting the vault entry stops new calls and the last one expires on its
        # own within the TTL.
        return None


register_provider(CapabilityProvider())


# ── mode 7: GitHub App installation identity ─────────────────────────
#
# Two hops: sign a short-lived RS256 JWT with the App's private key, then trade it
# for an installation access token (~1 hour). The hourly expiry is exactly why this
# needs the renewal loop — it is unusable with a static header.
#
# NOTE: core/signers.py cannot do this. It is Ed25519-only (LocalEd25519Signer,
# PKCS11, Vault Transit ed25519) and GitHub requires RS256, so PyJWT is used
# directly over the App's PEM. PyJWT[crypto] is already a declared dependency.

#: GitHub rejects app JWTs valid for more than 10 minutes. 60s is all we need —
#: it is spent immediately on the installation-token exchange.
_APP_JWT_TTL = 60
#: GitHub rejects future-dated JWTs, so back-date iat to absorb clock skew.
_APP_JWT_SKEW = 30


class GitHubAppProvider(_NotInteractive):
    mode = MODE_GITHUB_APP

    def _app_jwt(self, app_id: str, pem: str) -> str:
        try:
            import jwt  # PyJWT
        except Exception as e:  # pragma: no cover - dependency is declared
            raise CredentialError(
                500, "PyJWT is required for GitHub App credentials",
                permanent=True) from e
        now = int(time.time())
        try:
            return jwt.encode(
                {"iat": now - _APP_JWT_SKEW, "exp": now + _APP_JWT_TTL, "iss": app_id},
                pem, algorithm="RS256")
        except Exception as e:
            # A malformed PEM is an operator error, not something to retry.
            raise CredentialError(
                400, f"could not sign the GitHub App JWT: {type(e).__name__} "
                     f"(is the private key a valid RSA PEM?)", permanent=True) from e

    async def renew(self, ctx: CredentialContext, *, client=None) -> dict:
        app_id = str(ctx.record.get("github_app_id") or "")
        installation_id = str(ctx.record.get("github_installation_id") or "")
        pem = ctx.secret("github_private_key_ref")
        if not (app_id and installation_id and pem):
            raise CredentialError(
                400, "GitHub App mode needs github_app_id, "
                     "github_installation_id and a stored private key",
                permanent=True)

        endpoint = (ctx.record.get("token_endpoint")
                    or f"https://api.github.com/app/installations/{installation_id}/access_tokens")
        app_jwt = self._app_jwt(app_id, pem)

        from core.url_safety import UnsafeURLError, validate_outbound_url
        try:
            safe = validate_outbound_url(endpoint, purpose="github-installation-token")
        except UnsafeURLError as e:
            raise CredentialError(400, f"cannot reach GitHub: {e}", permanent=True) from e

        async def _call(c):
            return await c.post(
                safe, timeout=_TIMEOUT,
                headers={"Authorization": f"Bearer {app_jwt}",
                         "Accept": "application/vnd.github+json"})

        try:
            resp = await _with_client(client, _call)
        except CredentialError:
            raise
        except Exception as e:
            raise CredentialError(
                502, f"installation token request failed: {type(e).__name__}") from e

        try:
            payload = resp.json()
        except Exception:
            payload = {}

        if resp.status_code == 404:
            # The app was uninstalled: a human must reinstall it.
            raise CredentialError(
                502, "GitHub reports no such installation; the App may have been "
                     "uninstalled", permanent=True)
        if resp.status_code == 401:
            raise CredentialError(
                502, "GitHub rejected the App JWT; check the app id and private key",
                permanent=True)
        if resp.status_code >= 400 or not payload.get("token"):
            raise CredentialError(
                502, f"GitHub did not return an installation token "
                     f"(HTTP {resp.status_code})")

        # GitHub sends an absolute expires_at, not expires_in.
        expires_at = int(time.time()) + 3300  # ~55 min, inside the 1 h window
        raw_expiry = str(payload.get("expires_at") or "")
        if raw_expiry:
            try:
                from datetime import datetime
                expires_at = int(datetime.fromisoformat(
                    raw_expiry.replace("Z", "+00:00")).timestamp())
            except Exception:
                pass  # keep the conservative default

        return store_credential(ctx, token=str(payload["token"]),
                                expires_at=expires_at)

    async def revoke(self, ctx: CredentialContext, *, client=None) -> None:
        # Installation tokens cannot be revoked individually and expire within the
        # hour; uninstalling the App is the real revocation and is done on GitHub.
        return None


register_provider(GitHubAppProvider())


# ── mode 5: OAuth device flow ────────────────────────────────────────
#
# For providers whose clients cannot receive a redirect. Two-phase like auth code,
# but the operator types a code into a browser instead of being redirected, and the
# gateway polls. Last of the eight because few providers implement it — and the one
# that motivated it (Higgsfield) 404s on its device-auth discovery.

_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class DeviceCodeProvider:
    mode = MODE_DEVICE_CODE
    interactive = True

    async def begin(self, ctx: CredentialContext, *, client=None) -> dict:
        """Request a device code. Returns what the operator must be shown."""
        endpoint = ctx.record.get("device_authorization_endpoint") or ""
        if not endpoint:
            raise CredentialError(
                422, "provider publishes no device_authorization_endpoint",
                permanent=True)

        data = {"client_id": ctx.record.get("client_id") or ""}
        scopes = [s for s in (ctx.record.get("scopes") or []) if s]
        if scopes:
            data["scope"] = " ".join(scopes)

        from core.url_safety import UnsafeURLError, validate_outbound_url
        try:
            safe = validate_outbound_url(endpoint, purpose="oauth-device-authorization")
        except UnsafeURLError as e:
            raise CredentialError(400, f"cannot reach the device endpoint: {e}",
                                  permanent=True) from e

        async def _call(c):
            return await c.post(safe, data=data, timeout=_TIMEOUT,
                                headers={"Accept": "application/json"})

        resp = await _with_client(client, _call)
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code >= 400 or not payload.get("device_code"):
            raise CredentialError(
                502, f"device authorization failed (HTTP {resp.status_code})")

        # device_code is the polling credential — treated like a secret and never
        # returned to the caller. Only the user-facing pieces go back.
        return {
            "device_code": str(payload["device_code"]),
            "user_code": str(payload.get("user_code") or ""),
            "verification_uri": str(payload.get("verification_uri")
                                    or payload.get("verification_url") or ""),
            "verification_uri_complete": str(
                payload.get("verification_uri_complete") or ""),
            "interval": int(payload.get("interval") or 5),
            "expires_in": int(payload.get("expires_in") or 600),
        }

    async def complete(self, ctx: CredentialContext, *, device_code: str = "",
                       client=None, **kwargs) -> dict:
        """One poll of the token endpoint.

        Polls once per call rather than blocking: the caller (an HTTP endpoint or
        the console) decides the cadence, and a request that sat open for the
        provider's full ``expires_in`` would just time out anyway.
        ``authorization_pending`` and ``slow_down`` come back as NON-permanent so
        the caller knows to keep polling.
        """
        if not device_code:
            raise CredentialError(400, "no device_code supplied", permanent=True)

        data = {
            "grant_type": _DEVICE_GRANT,
            "device_code": device_code,
            "client_id": ctx.record.get("client_id") or "",
        }
        secret = ctx.secret("client_secret_ref")
        if secret:
            data["client_secret"] = secret

        try:
            payload = await _with_client(client, lambda c: post_token_endpoint(
                c, ctx.record.get("token_endpoint") or "", data,
                purpose="oauth-device-token"))
        except CredentialError as e:
            # post_token_endpoint marks OAuth error codes permanent; these two are
            # the normal "not yet" of a device flow and must not be.
            if "authorization_pending" in e.message or "slow_down" in e.message:
                raise CredentialError(202, "authorization still pending") from e
            raise

        return store_credential(
            ctx, token=str(payload["access_token"]),
            expires_at=expiry_from(payload),
            refresh_token=str(payload.get("refresh_token") or ""))

    async def renew(self, ctx: CredentialContext, *, client=None) -> dict:
        # Renewal is an ordinary refresh_token grant — identical to auth code, so
        # reuse it rather than maintaining a second copy.
        return await AuthCodeProvider().renew(ctx, client=client)

    async def revoke(self, ctx: CredentialContext, *, client=None) -> None:
        await AuthCodeProvider().revoke(ctx, client=client)


register_provider(DeviceCodeProvider())
