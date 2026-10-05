"""OAuth brokering for upstream MCP servers: discovery, registration, authorize.

Some MCP servers issue only short-lived OAuth tokens and have no API key path at
all. Shield completes the authorization-code flow once, holds the refresh token,
and keeps a valid access token in the vault so the gateway's existing
``shield://`` header reference always resolves.

See docs/spec-mcp-oauth-brokering.md. This module covers task 2 — discovery,
dynamic client registration, and building the authorize URL. The callback,
exchange and refresh land next; nothing here obtains a token.

**Admin plane only.** The data plane never runs this: it only materializes the
vault reference the broker keeps fresh, which is what keeps the guard path free of
OAuth round-trips.

Every outbound URL here is derived from tenant-supplied route config, so every
fetch goes through ``core.url_safety.validate_outbound_url`` — discovery is
otherwise a clean SSRF primitive pointed at cloud metadata endpoints.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse

logger = logging.getLogger("votal.mcp_oauth")

#: Fixed redirect target, registered with the provider. NEVER request-derived —
#: an attacker-supplied redirect_uri is the classic code-interception bug.
_REDIRECT_ENV = "SHIELD_OAUTH_REDIRECT_URI"

#: Without a refresh token there is nothing to broker: the connection would die
#: with the first access token and an operator would be re-consenting hourly.
REQUIRED_SCOPE = "offline_access"

#: Scopes that identify the user or keep the grant alive, as opposed to scopes
#: that grant access to the resource itself. Only the second kind needs an
#: operator's explicit choice.
IDENTITY_SCOPES = ("openid", "email", "profile", REQUIRED_SCOPE)

#: How each provider family issues refresh tokens and what else its authorize
#: request needs. Matched on the discovered issuer; anything unlisted is
#: "standard", which is the behaviour this module always had. Adding a provider
#: is a row here, not new code. Spec: docs/specs/mcp-oauth-standard-providers.md
PROFILES: dict[str, dict] = {
    "standard": {
        "issuers": (),
        "refresh_via_scope": True,          # needs offline_access in the scope list
        "authorize_params": {},
        "send_resource": True,              # RFC 8707, as the MCP auth spec asks
    },
    "google": {
        "issuers": ("https://accounts.google.com",),
        # Google lists only openid/email/profile and issues refresh tokens for
        # access_type=offline. prompt=consent makes it issue one on every
        # connect, not only the first, and makes a silent re-grant impossible.
        "refresh_via_scope": False,
        "authorize_params": {"access_type": "offline", "prompt": "consent"},
        # Inferred, not observed: Google lists Claude as a supported client of
        # its Workspace MCP servers and Claude follows the MCP auth spec, which
        # sends `resource`. Turn off here if a live connect shows otherwise.
        "send_resource": True,
    },
}

_SCOPE_CHOICE_ENV = "SHIELD_MCP_OAUTH_REQUIRE_SCOPE_CHOICE"

_TIMEOUT = 15.0


class OAuthBrokerError(Exception):
    """Discovery/registration failed. ``status`` is the HTTP code to surface."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def profile_for(meta: dict) -> str:
    """The provider profile for discovered metadata (issuer-matched)."""
    issuer = str(meta.get("issuer") or "").rstrip("/")
    for name, prof in PROFILES.items():
        if issuer and issuer in prof["issuers"]:
            return name
    return "standard"


def _profile(meta: dict) -> dict:
    return PROFILES.get(meta.get("profile") or profile_for(meta), PROFILES["standard"])


def available_scopes(meta: dict) -> list[str]:
    """Everything the resource and its provider advertise, resource first,
    without duplicates. What the portal offers."""
    out: list[str] = []
    for s in list(meta.get("resource_scopes") or []) + list(meta.get("scopes_supported") or []):
        if s not in out:
            out.append(s)
    return out


def access_scopes(meta: dict) -> list[str]:
    """The advertised scopes that grant access to the resource, as opposed to
    identity scopes. A server advertising any of these needs a choice."""
    return [s for s in available_scopes(meta) if s not in IDENTITY_SCOPES]


def _scope_choice_required() -> bool:
    """SHIELD_MCP_OAUTH_REQUIRE_SCOPE_CHOICE=off restores "identity scopes only"."""
    return os.getenv(_SCOPE_CHOICE_ENV, "on").strip().lower() not in (
        "0", "false", "no", "off")


def choose_scopes(meta: dict, requested: Optional[list[str]] = None) -> list[str]:
    """The scopes to request: the profile's identity scopes plus the operator's
    choice of the resource's own scopes.

    Shield never picks between, say, `drive` and `drive.readonly`: a server that
    advertises access scopes needs them chosen, and every chosen scope must be
    one the server or its provider advertises.
    """
    base = check_brokerable(meta)
    advertised = available_scopes(meta)
    chosen = [s.strip() for s in (requested or []) if s and s.strip()]
    if chosen:
        unknown = [s for s in chosen if advertised and s not in advertised]
        if unknown:
            raise OAuthBrokerError(
                422, f"not offered by this server: {', '.join(unknown)}. "
                     f"Choose from: {', '.join(advertised)}")
        return base + [s for s in chosen if s not in base]
    offered = access_scopes(meta)
    if offered and _scope_choice_required():
        raise OAuthBrokerError(
            422, "this server grants access by scope; choose the scopes to request "
                 f"from: {', '.join(offered)}")
    return base


def broker_enabled() -> bool:
    """Escape hatch: SHIELD_MCP_OAUTH_BROKER=0 disables the feature."""
    return os.getenv("SHIELD_MCP_OAUTH_BROKER", "1").strip().lower() not in (
        "0", "false", "no", "off",
    )


def redirect_uri() -> str:
    """The configured callback URL, or raise.

    Required rather than defaulted: guessing a public URL for a security-relevant
    redirect target would be worse than refusing to start.
    """
    value = (os.getenv(_REDIRECT_ENV) or "").strip()
    if not value:
        raise OAuthBrokerError(
            409,
            f"{_REDIRECT_ENV} is not set; OAuth brokering needs a fixed callback "
            f"URL registered with the provider")
    return value


async def _get_json(client, url: str, *, purpose: str) -> Optional[dict]:
    """GET a discovery document. None if absent or not JSON; raises if unsafe."""
    from core.url_safety import UnsafeURLError, validate_outbound_url

    try:
        safe = validate_outbound_url(url, purpose=purpose)
    except UnsafeURLError as e:
        # The safety check folds two causes into one error: a genuinely internal
        # or metadata address, and a hostname that will not resolve right now.
        # Naming both keeps a transient DNS failure from reading as a deliberate
        # block, which sends an operator hunting for a policy that isn't there.
        raise OAuthBrokerError(
            400,
            f"cannot fetch {purpose}: the host is not publicly resolvable, or "
            f"resolves to an internal address ({e})") from e

    try:
        resp = await client.get(safe, timeout=_TIMEOUT,
                                headers={"Accept": "application/json"})
    except Exception as e:
        logger.info("mcp-oauth: %s fetch failed for %s: %s", purpose, url, type(e).__name__)
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _well_known(resource_url: str, suffix: str) -> str:
    """Build a .well-known URL for a resource, per RFC 9728.

    The resource path is appended after the well-known segment — for
    ``https://h/mcp`` the document lives at
    ``https://h/.well-known/oauth-protected-resource/mcp``, not at the host root.
    """
    parts = urlparse(resource_url)
    path = (parts.path or "").rstrip("/")
    return urlunparse((parts.scheme, parts.netloc,
                       f"/.well-known/{suffix}{path}", "", "", ""))


async def discover(client, resource_url: str) -> dict:
    """Resolve an MCP resource URL to its authorization-server metadata.

    Chain: protected-resource metadata (RFC 9728) names the authorization
    servers; each publishes its own metadata (RFC 8414) or an OIDC discovery
    document. Returns the merged view the flow needs.

    Raises OAuthBrokerError(502) when nothing is discoverable — better than
    storing a half-configured record that fails later at connect time.
    """
    resource_meta = await _get_json(
        client, _well_known(resource_url, "oauth-protected-resource"),
        purpose="oauth-protected-resource")

    servers = []
    scopes_supported = []
    resource = ""
    if resource_meta:
        resource = str(resource_meta.get("resource") or "")
        servers = [s for s in (resource_meta.get("authorization_servers") or [])
                   if isinstance(s, str)]
        scopes_supported = [s for s in (resource_meta.get("scopes_supported") or [])
                            if isinstance(s, str)]

    # No resource metadata: the issuer may still be the resource's own origin.
    if not servers:
        parts = urlparse(resource_url)
        servers = [urlunparse((parts.scheme, parts.netloc, "", "", "", ""))]

    for issuer in servers:
        base = issuer.rstrip("/")
        for suffix in ("oauth-authorization-server", "openid-configuration"):
            meta = await _get_json(client, f"{base}/.well-known/{suffix}",
                                   purpose="oauth-authorization-server")
            if not meta or not meta.get("token_endpoint"):
                continue
            # The provider's own scope list wins; the resource's is the fallback,
            # since a resource may advertise scopes its AS does not issue.
            scopes = [s for s in (meta.get("scopes_supported") or []) if isinstance(s, str)]
            found = {
                "issuer": meta.get("issuer") or base,
                "authorization_endpoint": meta.get("authorization_endpoint") or "",
                "token_endpoint": meta.get("token_endpoint"),
                "registration_endpoint": meta.get("registration_endpoint") or "",
                "revocation_endpoint": meta.get("revocation_endpoint") or "",
                "scopes_supported": scopes or scopes_supported,
                "grant_types_supported": [
                    g for g in (meta.get("grant_types_supported") or []) if isinstance(g, str)
                ],
                "code_challenge_methods_supported": [
                    m for m in (meta.get("code_challenge_methods_supported") or [])
                    if isinstance(m, str)
                ],
                # The resource's own scopes were discarded here before, so a
                # server's access scopes (Drive's, say) could never be asked for.
                "resource_scopes": scopes_supported,
                "resource": resource,
            }
            found["profile"] = profile_for(found)
            return found

    raise OAuthBrokerError(
        502,
        "could not discover an OAuth authorization server for this upstream; "
        "the server may not be OAuth-protected, or its metadata is unreachable")


def check_brokerable(meta: dict) -> list[str]:
    """The scopes to request, or raise if this provider cannot be brokered.

    Refuses early rather than producing a connection that dies with its first
    access token — an operator would read that as Shield being broken.
    """
    supported = list(meta.get("scopes_supported") or [])
    grants = list(meta.get("grant_types_supported") or [])

    if not meta.get("authorization_endpoint"):
        raise OAuthBrokerError(
            422, "provider publishes no authorization_endpoint; the "
                 "authorization-code flow is not available")

    # An empty grant list means "unstated", not "unsupported" — RFC 8414 defaults
    # to authorization_code. Only an explicit list that omits it is a refusal.
    if grants and "authorization_code" not in grants:
        raise OAuthBrokerError(
            422, "provider does not support the authorization_code grant")
    if grants and "refresh_token" not in grants:
        raise OAuthBrokerError(
            422, "provider does not support the refresh_token grant, so Shield "
                 "cannot keep the credential alive without re-consent")
    via_scope = _profile(meta)["refresh_via_scope"]
    if via_scope and supported and REQUIRED_SCOPE not in supported:
        raise OAuthBrokerError(
            422, f"provider does not offer the '{REQUIRED_SCOPE}' scope, so no "
                 f"refresh token can be issued")

    # Identity scopes the provider offers, plus offline_access where that is how
    # the provider issues refresh tokens (other profiles use an authorize param).
    wanted = [s for s in ("openid", "email") if not supported or s in supported]
    return wanted + ([REQUIRED_SCOPE] if via_scope else [])


async def register_client(client, meta: dict, *, route: str) -> dict:
    """Dynamically register Shield as a client (RFC 7591).

    Returns ``{"client_id", "client_secret"}``; the secret is absent for public
    clients. When the provider has no registration endpoint the caller must
    supply a pre-provisioned client — not every provider allows self-registration.
    """
    from core.url_safety import UnsafeURLError, validate_outbound_url

    endpoint = meta.get("registration_endpoint") or ""
    if not endpoint:
        raise OAuthBrokerError(
            422,
            "provider does not support dynamic client registration; supply "
            "client_id (and client_secret if required) when connecting")

    try:
        safe = validate_outbound_url(endpoint, purpose="oauth-registration")
    except UnsafeURLError as e:
        raise OAuthBrokerError(400, f"refusing to POST registration: {e}") from e

    body = {
        "client_name": f"Votal Shield gateway ({route})",
        "redirect_uris": [redirect_uri()],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        "scope": " ".join(meta.get("scopes_supported") or [REQUIRED_SCOPE]),
    }
    try:
        resp = await client.post(safe, json=body, timeout=_TIMEOUT)
    except Exception as e:
        raise OAuthBrokerError(
            502, f"client registration failed: {type(e).__name__}") from e

    if resp.status_code not in (200, 201):
        # The provider's body can echo our request; do not surface it verbatim.
        raise OAuthBrokerError(
            502, f"client registration rejected by the provider (HTTP {resp.status_code})")

    try:
        data = resp.json()
    except Exception as e:
        raise OAuthBrokerError(502, "client registration returned a non-JSON body") from e

    client_id = data.get("client_id")
    if not client_id:
        raise OAuthBrokerError(502, "client registration returned no client_id")
    return {"client_id": str(client_id),
            "client_secret": data.get("client_secret") or ""}


def build_authorize_url(meta: dict, *, client_id: str, scopes: list[str],
                        state: str, code_challenge: str) -> str:
    """The URL the operator's browser must visit.

    PKCE is unconditional. The verifier stays in the pending record, so an
    intercepted authorization code is unusable on its own.
    """
    endpoint = meta.get("authorization_endpoint") or ""
    if not endpoint:
        raise OAuthBrokerError(422, "provider publishes no authorization_endpoint")

    prof = _profile(meta)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri(),
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        **prof["authorize_params"],
    }
    if prof["send_resource"] and meta.get("resource"):
        params["resource"] = meta["resource"]
    query = urlencode(params)
    joiner = "&" if urlparse(endpoint).query else "?"
    return f"{endpoint}{joiner}{query}"


def public_status(record: Optional[dict]) -> dict:
    """Operator-facing view of a broker record.

    An explicit allowlist, not a blocklist: a future field holding secret
    material must not become visible because someone forgot to exclude it.
    """
    if not record:
        return {"status": "not_connected"}
    return {
        "status": record.get("status") or "unknown",
        "issuer": record.get("issuer") or "",
        "scopes": list(record.get("scopes") or []),
        "expires_at": record.get("expires_at") or 0,
        "last_refresh_at": record.get("last_refresh_at") or 0,
        "last_error": record.get("last_error") or "",
        "connected_at": record.get("connected_at") or 0,
        "connected_by": record.get("connected_by") or "",
        "profile": record.get("profile") or "standard",
        "available_scopes": list(record.get("available_scopes") or []),
    }


def token_request_extras(record: dict) -> dict:
    """Extra fields for token-endpoint requests: the RFC 8707 resource, when
    the record's profile sends it. Records written before profiles existed have
    no `resource`, so they send exactly what they always did."""
    prof = PROFILES.get(record.get("profile") or "standard", PROFILES["standard"])
    resource = record.get("resource") or ""
    return {"resource": resource} if prof["send_resource"] and resource else {}
