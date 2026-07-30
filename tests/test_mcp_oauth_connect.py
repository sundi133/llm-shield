"""OAuth discovery, registration and connect (task 2 of the brokering spec).

No network: a stub provider serves the discovery documents. The shapes come from
`mcp.higgsfield.ai`, which was probed while writing docs/spec-mcp-oauth-brokering.md
— registration_endpoint, authorization_code + refresh_token, PKCE S256,
offline_access.

Two properties get the most attention, because both are security-relevant and
neither is obvious from reading the happy path:

  * every discovery fetch is SSRF-guarded — the URL comes from tenant-supplied
    route config, so unguarded it is a clean primitive for hitting cloud metadata;
  * redirect_uri is a fixed env value and never request-derived.
"""

import asyncio
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
from core import mcp_oauth
from storage import mcp_gateway_store as gstore
from storage import mcp_oauth_store as ostore

_H = {"X-Test-Tenant": "acme"}
_REDIRECT = "https://shield.votal.ai/v1/tenant/me/mcp/oauth/callback"
_PREFIXES = ("mcp_oauth:", "mcp_gateway:", "vault:")


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _env_and_store():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(_PREFIXES)]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None), \
         patch.dict("os.environ", {"SHIELD_OAUTH_REDIRECT_URI": _REDIRECT}):
        yield
    _clear()


# ── stub provider ────────────────────────────────────────────────────

_RESOURCE_META = {
    "resource": "https://mcp.higgsfield.ai/mcp",
    "authorization_servers": ["https://mcp.higgsfield.ai"],
    "scopes_supported": ["openid", "email", "offline_access"],
}
_AS_META = {
    "issuer": "https://mcp.higgsfield.ai",
    "authorization_endpoint": "https://mcp.higgsfield.ai/oauth2/authorize",
    "token_endpoint": "https://mcp.higgsfield.ai/oauth2/token",
    "registration_endpoint": "https://mcp.higgsfield.ai/oauth2/register",
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "scopes_supported": ["openid", "email", "offline_access"],
    "code_challenge_methods_supported": ["S256"],
}


class _Resp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _StubClient:
    """Serves discovery + registration; records what was fetched."""

    def __init__(self, docs=None, reg=None):
        self.docs = docs if docs is not None else {
            "https://mcp.higgsfield.ai/.well-known/oauth-protected-resource/mcp": _RESOURCE_META,
            "https://mcp.higgsfield.ai/.well-known/oauth-authorization-server": _AS_META,
        }
        self.reg = reg if reg is not None else {"client_id": "cid-1", "client_secret": "csec"}
        self.fetched: list = []
        self.posted: list = []

    async def get(self, url, **kw):
        self.fetched.append(url)
        doc = self.docs.get(url)
        return _Resp(200, doc) if doc is not None else _Resp(404, {})

    async def post(self, url, **kw):
        self.posted.append((url, kw.get("json")))
        return _Resp(201, self.reg)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


# ── discovery ────────────────────────────────────────────────────────


def test_discovery_follows_the_rfc9728_chain():
    c = _StubClient()
    meta = run(mcp_oauth.discover(c, "https://mcp.higgsfield.ai/mcp"))
    assert meta["token_endpoint"].endswith("/oauth2/token")
    assert meta["registration_endpoint"].endswith("/oauth2/register")
    assert "offline_access" in meta["scopes_supported"]
    # The resource path is appended AFTER the well-known segment, not dropped.
    assert any(".well-known/oauth-protected-resource/mcp" in u for u in c.fetched)


def test_falls_back_to_openid_configuration():
    c = _StubClient(docs={
        "https://mcp.higgsfield.ai/.well-known/oauth-protected-resource/mcp": _RESOURCE_META,
        "https://mcp.higgsfield.ai/.well-known/openid-configuration": _AS_META,
    })
    meta = run(mcp_oauth.discover(c, "https://mcp.higgsfield.ai/mcp"))
    assert meta["token_endpoint"].endswith("/oauth2/token")


def test_no_resource_metadata_falls_back_to_the_origin():
    """A server may publish AS metadata without RFC 9728 resource metadata."""
    c = _StubClient(docs={
        "https://mcp.higgsfield.ai/.well-known/oauth-authorization-server": _AS_META,
    })
    meta = run(mcp_oauth.discover(c, "https://mcp.higgsfield.ai/mcp"))
    assert meta["issuer"] == "https://mcp.higgsfield.ai"


def test_undiscoverable_provider_raises_502():
    """A resolvable host that publishes nothing: 502, distinct from the 400 an
    unresolvable or internal address gets."""
    c = _StubClient(docs={})
    with pytest.raises(mcp_oauth.OAuthBrokerError) as ei:
        run(mcp_oauth.discover(c, "https://example.com/mcp"))
    assert ei.value.status == 502


def test_unresolvable_host_does_not_read_as_a_deliberate_block():
    """DNS failure and 'internal address' share one error type in the safety
    guard. Reporting a DNS blip as 'refusing' sends an operator looking for a
    policy that does not exist."""
    c = _StubClient(docs={})
    with pytest.raises(mcp_oauth.OAuthBrokerError) as ei:
        run(mcp_oauth.discover(c, "https://nx-does-not-resolve.invalid/mcp"))
    assert ei.value.status == 400
    assert "not publicly resolvable" in ei.value.message


def test_metadata_without_token_endpoint_is_not_accepted():
    c = _StubClient(docs={
        "https://mcp.higgsfield.ai/.well-known/oauth-protected-resource/mcp": _RESOURCE_META,
        "https://mcp.higgsfield.ai/.well-known/oauth-authorization-server": {"issuer": "x"},
    })
    with pytest.raises(mcp_oauth.OAuthBrokerError):
        run(mcp_oauth.discover(c, "https://mcp.higgsfield.ai/mcp"))


def test_discovery_is_ssrf_guarded():
    """The upstream URL is tenant-supplied. Unguarded, discovery is a clean SSRF
    primitive aimed at link-local and metadata addresses."""
    from core.url_safety import UnsafeURLError

    c = _StubClient()
    with patch("core.url_safety.validate_outbound_url",
               side_effect=UnsafeURLError("blocked")):
        with pytest.raises(mcp_oauth.OAuthBrokerError) as ei:
            run(mcp_oauth.discover(c, "http://169.254.169.254/mcp"))
    assert ei.value.status == 400
    assert c.fetched == []          # never dialed


# ── brokerability ────────────────────────────────────────────────────


def test_scopes_include_offline_access():
    assert mcp_oauth.REQUIRED_SCOPE in mcp_oauth.check_brokerable(_AS_META)


def test_missing_offline_access_is_refused_early():
    """Without a refresh token the connection dies with its first access token,
    and an operator would read that as Shield being broken."""
    meta = {**_AS_META, "scopes_supported": ["openid", "email"]}
    with pytest.raises(mcp_oauth.OAuthBrokerError) as ei:
        mcp_oauth.check_brokerable(meta)
    assert ei.value.status == 422
    assert "offline_access" in ei.value.message


def test_missing_refresh_grant_is_refused():
    meta = {**_AS_META, "grant_types_supported": ["authorization_code"]}
    with pytest.raises(mcp_oauth.OAuthBrokerError):
        mcp_oauth.check_brokerable(meta)


def test_missing_authorization_endpoint_is_refused():
    meta = {k: v for k, v in _AS_META.items() if k != "authorization_endpoint"}
    with pytest.raises(mcp_oauth.OAuthBrokerError):
        mcp_oauth.check_brokerable(meta)


def test_unstated_grants_are_not_treated_as_unsupported():
    """RFC 8414 defaults to authorization_code when the list is absent; refusing
    on silence would lock out compliant providers."""
    meta = {k: v for k, v in _AS_META.items() if k != "grant_types_supported"}
    assert mcp_oauth.REQUIRED_SCOPE in mcp_oauth.check_brokerable(meta)


# ── registration ─────────────────────────────────────────────────────


def test_registration_sends_the_fixed_redirect_uri():
    c = _StubClient()
    creds = run(mcp_oauth.register_client(c, _AS_META, route="higgsfield"))
    assert creds == {"client_id": "cid-1", "client_secret": "csec"}
    _, body = c.posted[0]
    assert body["redirect_uris"] == [_REDIRECT]
    assert set(body["grant_types"]) == {"authorization_code", "refresh_token"}


def test_no_registration_endpoint_tells_the_operator_what_to_do():
    meta = {k: v for k, v in _AS_META.items() if k != "registration_endpoint"}
    with pytest.raises(mcp_oauth.OAuthBrokerError) as ei:
        run(mcp_oauth.register_client(_StubClient(), meta, route="r"))
    assert ei.value.status == 422
    assert "client_id" in ei.value.message


def test_registration_rejection_does_not_echo_the_provider_body():
    class _Reject(_StubClient):
        async def post(self, url, **kw):
            return _Resp(400, {"error": "secret-ish detail"})

    with pytest.raises(mcp_oauth.OAuthBrokerError) as ei:
        run(mcp_oauth.register_client(_Reject(), _AS_META, route="r"))
    assert "secret-ish" not in ei.value.message


# ── authorize URL ────────────────────────────────────────────────────


def test_authorize_url_carries_pkce_and_state():
    url = mcp_oauth.build_authorize_url(
        _AS_META, client_id="cid-1", scopes=["openid", "offline_access"],
        state="st-123", code_challenge="chal")
    for expect in ("response_type=code", "client_id=cid-1", "state=st-123",
                   "code_challenge=chal", "code_challenge_method=S256",
                   "offline_access"):
        assert expect in url


def test_redirect_uri_is_env_derived_not_request_derived():
    """An attacker-supplied redirect_uri is the classic code-interception bug."""
    url = mcp_oauth.build_authorize_url(
        _AS_META, client_id="c", scopes=["offline_access"], state="s",
        code_challenge="x")
    assert "shield.votal.ai" in url

    with patch.dict("os.environ", {"SHIELD_OAUTH_REDIRECT_URI": ""}, clear=False):
        with pytest.raises(mcp_oauth.OAuthBrokerError) as ei:
            mcp_oauth.redirect_uri()
        assert ei.value.status == 409


def test_authorize_url_preserves_an_existing_query():
    meta = {**_AS_META,
            "authorization_endpoint": "https://p/authorize?tenant=x"}
    url = mcp_oauth.build_authorize_url(meta, client_id="c", scopes=["s"],
                                        state="st", code_challenge="ch")
    assert "?tenant=x&" in url


# ── public status never leaks ─────────────────────────────────────────


def test_public_status_is_an_allowlist():
    """A future field holding secret material must not become visible because
    someone forgot to exclude it."""
    rec = {"status": "connected", "issuer": "https://p", "scopes": ["openid"],
           "access_token": "SHOULD-NEVER-APPEAR",
           "refresh_token": "NOR-THIS", "client_secret": "NOR-THIS-EITHER"}
    out = mcp_oauth.public_status(rec)
    blob = repr(out)
    assert "SHOULD-NEVER-APPEAR" not in blob
    assert "NOR-THIS" not in blob
    assert out["status"] == "connected"


def test_public_status_of_nothing():
    assert mcp_oauth.public_status(None)["status"] == "not_connected"


# ── connect endpoint ─────────────────────────────────────────────────


@pytest.fixture
def client():
    app = FastAPI()

    @app.middleware("http")
    async def _set_tenant(request: Request, call_next):
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)

    app.include_router(admin.router)
    return TestClient(app)


def _route(route="higgsfield", **extra):
    cfg = {"route": route, "transport": "http",
           "url": "https://mcp.higgsfield.ai/mcp"}
    cfg.update(extra)
    gstore.set_upstream("acme", route, cfg)
    return cfg


def _vault_on():
    return patch("core.secret_vault.keyprovider.vault_enabled", return_value=True)


def _stub_httpx(stub):
    return patch("httpx.AsyncClient", lambda **kw: stub)


def test_connect_returns_an_authorize_url_and_stores_pending(client):
    _route()
    stub = _StubClient()
    with _vault_on(), _stub_httpx(stub), \
         patch("storage.vault_store.create_vault_entry", lambda *a, **k: {}):
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect", headers=_H)

    assert r.status_code == 202                    # not finished — operator must consent
    body = r.json()
    assert "code_challenge_method=S256" in body["authorize_url"]
    assert body["status"] == "pending"

    rec = ostore.get_broker("acme", "higgsfield")
    assert rec["status"] == ostore.STATUS_PENDING
    assert rec["client_id"] == "cid-1"
    # References only; the secret went to the vault.
    assert rec["access_token_ref"] == "shield://oauth-higgsfield-access"
    assert "client_secret" not in rec


def test_connect_warns_that_consent_is_a_durable_delegation(client):
    _route()
    with _vault_on(), _stub_httpx(_StubClient()), \
         patch("storage.vault_store.create_vault_entry", lambda *a, **k: {}):
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect", headers=_H)
    note = r.json()["consent_note"]
    assert "persists until revoked" in note and "service account" in note


def test_connect_never_returns_the_client_secret(client):
    _route()
    with _vault_on(), _stub_httpx(_StubClient()), \
         patch("storage.vault_store.create_vault_entry", lambda *a, **k: {}):
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect", headers=_H)
    assert "csec" not in r.text


def test_connect_accepts_a_preprovisioned_client(client):
    """For providers without dynamic registration."""
    _route()
    stub = _StubClient(docs={
        "https://mcp.higgsfield.ai/.well-known/oauth-protected-resource/mcp": _RESOURCE_META,
        "https://mcp.higgsfield.ai/.well-known/oauth-authorization-server":
            {k: v for k, v in _AS_META.items() if k != "registration_endpoint"},
    })
    with _vault_on(), _stub_httpx(stub):
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect",
                        json={"client_id": "manual-id"}, headers=_H)
    assert r.status_code == 202
    assert stub.posted == []       # no registration attempted
    assert ostore.get_broker("acme", "higgsfield")["client_id"] == "manual-id"


def test_connect_refuses_when_the_vault_is_off(client):
    """Refusing beats holding a live delegation of an account in plaintext."""
    _route()
    with patch("core.secret_vault.keyprovider.vault_enabled", return_value=False):
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect", headers=_H)
    assert r.status_code == 409
    assert "vault" in r.json()["detail"].lower()
    assert ostore.get_broker("acme", "higgsfield") is None


def test_connect_refuses_when_brokering_is_disabled(client):
    _route()
    with patch.dict("os.environ", {"SHIELD_MCP_OAUTH_BROKER": "0"}):
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect", headers=_H)
    assert r.status_code == 409


def test_connect_refuses_a_stdio_route(client):
    _route("local", transport="stdio", command="x", url=None)
    gstore.set_upstream("acme", "local", {"route": "local", "transport": "stdio",
                                          "command": "x"})
    with _vault_on():
        r = client.post("/v1/tenant/me/mcp/servers/local/oauth/connect", headers=_H)
    assert r.status_code == 422


def test_connect_unknown_route_404s(client):
    with _vault_on():
        assert client.post("/v1/tenant/me/mcp/servers/nope/oauth/connect",
                           headers=_H).status_code == 404


def test_connect_requires_a_tenant(client):
    _route()
    assert client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect").status_code == 401


def test_connect_rejects_unknown_fields(client):
    _route()
    with _vault_on():
        r = client.post("/v1/tenant/me/mcp/servers/higgsfield/oauth/connect",
                        json={"client_id": "x", "typo": 1}, headers=_H)
    assert r.status_code == 422


def test_status_endpoint_reports_and_never_leaks(client):
    _route()
    ostore.set_broker("acme", "higgsfield", {
        "status": ostore.STATUS_CONNECTED, "issuer": "https://p",
        "scopes": ["offline_access"], "access_token_ref": "shield://x",
    })
    r = client.get("/v1/tenant/me/mcp/servers/higgsfield/oauth", headers=_H)
    assert r.json()["oauth"]["status"] == "connected"
    assert "shield://" not in r.text          # not even a ref is surfaced


def test_status_of_an_unconnected_route(client):
    _route()
    r = client.get("/v1/tenant/me/mcp/servers/higgsfield/oauth", headers=_H)
    assert r.json()["oauth"]["status"] == "not_connected"
