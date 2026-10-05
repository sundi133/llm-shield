"""Who is calling the MCP gateway: principals, verified, recorded on every decision.

Tasks A1 and A2 of docs/specs/mcp-verified-callers-and-user-credentials.md.

- a principal store (people and service accounts) and principal keys that live
  outside the tenant-key namespace;
- the gateway resolves the verified principal behind a request (a Shield token
  naming one, or a principal key) and records it with how it was verified;
- a revoked Shield access token is no longer accepted.

A tenant-key caller is resolved exactly as before (test_a_tenant_key_caller_
resolves_exactly_as_before). A credential that names a principal is new, so it
follows stricter rules from the start (A2): its role comes from the principal,
never a header, and it admits nobody once the principal is suspended.
"""
import asyncio
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_mcp_gateway_server as srv
import api.routes_mcp_server as ms
import core.mcp.gateway as gw_core
import core.mcp.principal as principal
import storage.principal_store as ps
from core.oauth.authz_server import issue_access_token
from storage.tenant_store import resolve_tenant_by_api_key as _real_resolve_tenant

TENANT = "acme"
TENANT_KEY = "acme-tenant-key"
OTHER = "globex"
ISSUER = "https://acme.okta.example"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store
                  if k.startswith(("principal", "shield:revoke:"))]:
            del _fallback_store[k]
    _clear()
    monkeypatch.setattr(ps, "_get_redis", lambda: None)
    import storage.revocation as rev
    monkeypatch.setattr(rev, "_get_redis", lambda: None)
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "resolve_tenant_by_api_key",
                        lambda k: TENANT if k == TENANT_KEY else "")
    monkeypatch.delenv("SHIELD_MCP_AUTH_CHALLENGE", raising=False)
    principal.clear_cache()
    yield
    principal.clear_cache()
    _clear()


class _Router:
    """Records what enforcement would receive, and writes an audit entry the
    way MCPProxy does (inside the request's task)."""

    def __init__(self):
        self.calls = []
        self.callers = []

    async def call_tool(self, tenant, route, name, arguments, *, agent_key, user_role, **kw):
        self.calls.append((tenant, agent_key, user_role))
        self.callers.append(principal.current_caller())
        await gw_core._audit_decision({
            "tenant_id": tenant, "route": route, "tool": name, "agent_key": agent_key,
            "user_role": user_role, "allowed": True, "action": "pass", "results": []})
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}

    async def list_tools(self, tenant, route, *, agent_key, user_role):
        return [{"name": "t1"}]


@pytest.fixture
def router(monkeypatch):
    r = _Router()
    monkeypatch.setattr(srv, "gateway_router", r)
    return r


@pytest.fixture
def audit(monkeypatch):
    entries = []

    class _Logger:
        async def log(self, entry):
            entries.append(entry)

    import storage.audit_log as al
    monkeypatch.setattr(al, "audit_logger", _Logger())
    monkeypatch.delenv("SHIELD_MCP_AUDIT", raising=False)
    return entries


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(srv.router)
    return TestClient(app)


def _call(client, headers):
    return client.post("/gateway/drive/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_recent_files", "arguments": {}}})


def _user(tenant=TENANT, sub="00u-alice", email="alice@acme.example", groups=("eng",)):
    return ps.upsert_user(tenant, issuer=ISSUER, sub=sub, email=email, groups=list(groups))


def _token(doc, *, tenant=TENANT, roles=None, ptype=None):
    """A Shield access token naming a principal, as task A2's sign-in will mint."""
    from core.agent_tokens import get_signer
    from core.jwt_utils import decode_jwt, encode_jwt
    signer = get_signer()
    raw = issue_access_token(client_id="claude", scope="mcp", tenant_id=tenant,
                             user_sub=doc["id"])
    claims = decode_jwt(raw, signer, audience="shield-oauth")
    claims["ptype"] = ptype or doc["type"]
    if roles is not None:
        claims["roles"] = roles
    return encode_jwt(claims, signer)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ── the store ────────────────────────────────────────────────────────────


def test_a_person_is_one_principal_per_issuer_and_subject():
    a = _user()
    again = ps.upsert_user(TENANT, issuer=ISSUER, sub="00u-alice",
                           email="alice.ng@acme.example", groups=["eng", "finance"])
    assert a["id"].startswith("usr_") and again["id"] == a["id"]
    assert again["email"] == "alice.ng@acme.example"
    assert again["groups"] == ["eng", "finance"]
    assert ps.list_principals(TENANT) == [again]


def test_identity_is_the_subject_not_the_email():
    # An email can be reassigned to someone else; a subject cannot.
    a = _user(sub="00u-alice", email="shared@acme.example")
    b = _user(sub="00u-bob", email="shared@acme.example")
    assert a["id"] != b["id"]


def test_signing_in_again_never_reactivates_a_suspended_person():
    a = _user()
    ps.set_status(TENANT, a["id"], ps.STATUS_SUSPENDED)
    assert _user()["status"] == ps.STATUS_SUSPENDED


def test_principals_are_scoped_to_their_tenant():
    a = _user()
    assert ps.get_principal(OTHER, a["id"]) is None
    assert ps.find_user(OTHER, ISSUER, "00u-alice") is None


def test_service_accounts_carry_admin_set_roles():
    sa = ps.create_service_account(TENANT, name="nightly-reconciler",
                                   roles=["finance", "finance", ""])
    assert sa["id"].startswith("sa_") and sa["roles"] == ["finance"]
    with pytest.raises(ValueError):
        ps.create_service_account(TENANT, name="  ")
    with pytest.raises(ValueError):
        ps.set_status(TENANT, sa["id"], "deleted")


def test_principal_keys_are_hashed_and_are_not_tenant_keys():
    from storage.tenant_store import _fallback_store
    sa = ps.create_service_account(TENANT, name="bot")
    key, record = ps.create_principal_key(TENANT, sa["id"], label="ci")
    assert key.startswith("shk_") and record["prefix"] == key[:12]
    assert not any(key in str(v) for v in _fallback_store.values())
    assert ps.resolve_principal_key(key)["principal_id"] == sa["id"]
    # A separate namespace, so a principal key can never act as a tenant key
    # on the guard endpoints or the admin API.
    import storage.tenant_store as ts
    with pytest.MonkeyPatch.context() as m:
        m.setattr(ts, "_get_redis", lambda: None)
        assert _real_resolve_tenant(key) in ("", None)
    assert ps.revoke_principal_key(key) and ps.resolve_principal_key(key) is None
    with pytest.raises(ValueError):
        ps.create_principal_key(TENANT, "sa_missing")


# ── resolution: decisions unchanged ──────────────────────────────────────


def test_a_tenant_key_caller_resolves_exactly_as_before(client, router, audit):
    r = _call(client, {"X-API-Key": TENANT_KEY, "X-Agent-Key": "bot", "X-User-Role": "analyst"})
    assert r.status_code == 200 and "result" in r.json()
    assert router.calls == [(TENANT, "bot", "analyst")]
    ident = audit[0]["metadata"]["identity"]
    assert ident["identity_method"] == "tenant_key"
    assert ident["verified"] is False and ident["role_source"] == "header"
    assert ident["principal_id"] == ""


def test_a_signed_in_person_cannot_claim_a_role_with_a_header(client, router, audit):
    alice = _user()
    headers = {**_bearer(_token(alice, roles=["analyst", "reader"])),
               "X-Agent-Key": "claude-desktop", "X-User-Role": "admin"}
    _call(client, headers)
    assert router.calls == [(TENANT, "claude-desktop", "analyst")]
    ident = audit[0]["metadata"]["identity"]
    assert ident["role_source"] == "principal" and ident["role_override_refused"] is True


def test_a_header_may_pick_among_the_persons_own_roles(client, router, audit):
    alice = _user()
    _call(client, {**_bearer(_token(alice, roles=["analyst", "reader"])),
                   "X-User-Role": "reader"})
    assert router.calls[0][2] == "reader"
    ident = audit[0]["metadata"]["identity"]
    assert ident["role_source"] == "principal_selected" and not ident["role_override_refused"]


def test_a_person_with_no_roles_acts_with_none(client, router, audit):
    alice = _user()
    _call(client, {**_bearer(_token(alice, roles=[])), "X-User-Role": "admin"})
    assert router.calls[0][2] == ""
    assert audit[0]["metadata"]["identity"]["role_source"] == "principal_none"


def test_a_service_account_key_acts_as_its_own_role(client, router):
    sa = ps.create_service_account(TENANT, name="bot", roles=["finance"])
    key, _ = ps.create_principal_key(TENANT, sa["id"])
    _call(client, {"X-API-Key": key, "X-User-Role": "admin"})
    assert router.calls[0][2] == "finance"


def test_a_signed_in_person_is_recorded_as_verified(client, router, audit):
    alice = _user()
    _call(client, _bearer(_token(alice, roles=["analyst"])))
    ident = audit[0]["metadata"]["identity"]
    assert ident == {
        "principal_id": alice["id"], "principal_type": "user",
        "email": "alice@acme.example", "identity_method": "oauth_user",
        "verified": True, "role_source": "principal", "principal_roles": ["analyst"],
        "client_id": "claude", "role_override_refused": False,
        "credential_scope": "", "upstream_account": ""}   # set by the real router (B2)


def test_a_suspended_persons_token_admits_nobody(client, router):
    alice = _user()
    ps.set_status(TENANT, alice["id"], ps.STATUS_SUSPENDED)
    r = _call(client, _bearer(_token(alice)))
    assert r.status_code == 401 and router.calls == []


def test_a_token_whose_type_does_not_match_the_record_admits_nobody(client, router):
    sa = ps.create_service_account(TENANT, name="bot")
    assert _call(client, _bearer(_token(sa, ptype="user"))).status_code == 401


def test_a_principal_from_another_tenant_is_never_found(client, router):
    other = _user(tenant=OTHER)
    assert _call(client, _bearer(_token(other, tenant=TENANT))).status_code == 401


def test_a_suspended_persons_token_never_un_admits_a_tenant_key(client, router, audit):
    alice = _user()
    ps.set_status(TENANT, alice["id"], ps.STATUS_SUSPENDED)
    r = _call(client, {"X-API-Key": TENANT_KEY, **_bearer(_token(alice))})
    assert r.status_code == 200
    assert audit[0]["metadata"]["identity"]["identity_method"] == "principal_inactive"


def test_a_shield_token_without_a_principal_is_legacy(client, router, audit):
    raw = issue_access_token(client_id="cursor", scope="shield", tenant_id=TENANT,
                             user_sub="tenant:acme")
    _call(client, _bearer(raw))
    assert router.calls == [(TENANT, "oauth:tenant:acme", "")]
    assert audit[0]["metadata"]["identity"]["identity_method"] == "oauth_legacy"


# ── revocation: the one behaviour change ─────────────────────────────────


def test_a_revoked_token_is_no_longer_accepted(client, router):
    from core.agent_tokens import get_signer
    from core.jwt_utils import decode_jwt
    from storage.revocation import revoke_jti
    raw = issue_access_token(client_id="cursor", scope="shield", tenant_id=TENANT,
                             user_sub="tenant:acme")
    assert _call(client, _bearer(raw)).status_code == 200
    revoke_jti(decode_jwt(raw, get_signer(), audience="shield-oauth")["jti"])
    r = _call(client, _bearer(raw))
    assert r.status_code == 401 and "WWW-Authenticate" in r.headers
    assert len(router.calls) == 1


# ── principal keys ───────────────────────────────────────────────────────


def test_a_service_account_key_names_its_tenant_and_principal(client, router, audit):
    sa = ps.create_service_account(TENANT, name="reconciler", roles=["finance"])
    key, _ = ps.create_principal_key(TENANT, sa["id"])
    for headers in ({"X-API-Key": key}, _bearer(key)):
        audit.clear()
        r = _call(client, headers)
        assert r.status_code == 200, r.text
        ident = audit[0]["metadata"]["identity"]
        assert ident["identity_method"] == "principal_key" and ident["verified"]
        assert ident["principal_id"] == sa["id"] and ident["principal_roles"] == ["finance"]
    assert all(c[0] == TENANT for c in router.calls)


@pytest.mark.parametrize("state", ["suspended", "unknown"])
def test_a_key_for_an_inactive_or_unknown_principal_admits_nobody(client, router, state):
    sa = ps.create_service_account(TENANT, name="bot")
    key, _ = ps.create_principal_key(TENANT, sa["id"])
    if state == "suspended":
        ps.set_status(TENANT, sa["id"], ps.STATUS_SUSPENDED)
    else:
        ps.revoke_principal_key(key)
    r = _call(client, {"X-API-Key": key})
    assert r.status_code == 401 and router.calls == []


def test_a_key_never_un_admits_a_caller_with_a_tenant_key(client, router, audit):
    sa = ps.create_service_account(TENANT, name="bot")
    key, _ = ps.create_principal_key(TENANT, sa["id"])
    ps.set_status(TENANT, sa["id"], ps.STATUS_SUSPENDED)
    r = _call(client, {"X-API-Key": TENANT_KEY, **_bearer(key)})
    assert r.status_code == 200 and router.calls[0][0] == TENANT
    assert audit[0]["metadata"]["identity"]["verified"] is False


def test_a_key_from_another_tenant_is_a_mismatch_not_a_principal(client, router, audit):
    sa = ps.create_service_account(OTHER, name="bot")
    key, _ = ps.create_principal_key(OTHER, sa["id"])
    _call(client, {"X-API-Key": TENANT_KEY, **_bearer(key)})
    assert router.calls[0][0] == TENANT
    ident = audit[0]["metadata"]["identity"]
    assert ident["identity_method"] == "principal_tenant_mismatch" and not ident["verified"]


# ── robustness ───────────────────────────────────────────────────────────


def test_a_resolver_failure_falls_back_to_the_legacy_identity(client, router, audit, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("store down")
    monkeypatch.setattr(ps, "resolve_principal_key", boom)
    r = _call(client, {"X-API-Key": TENANT_KEY, "X-Agent-Key": "bot", **_bearer("shk_x")})
    assert r.status_code == 200 and router.calls == [(TENANT, "bot", "")]
    assert audit[0]["metadata"]["identity"]["identity_method"] == "tenant_key"


def test_a_resolver_failure_never_admits_a_principal_credential_alone(client, router, monkeypatch):
    sa = ps.create_service_account(TENANT, name="bot")
    key, _ = ps.create_principal_key(TENANT, sa["id"])

    def boom(*a, **k):
        raise RuntimeError("store down")
    monkeypatch.setattr(principal, "_cached_principal", boom)
    assert _call(client, {"X-API-Key": key}).status_code == 401
    alice = _user()
    assert _call(client, _bearer(_token(alice))).status_code == 401
    assert router.calls == []


def test_the_caller_does_not_outlive_its_request(client, router):
    _call(client, {"X-API-Key": TENANT_KEY})
    assert router.callers[0] is not None
    assert principal.current_caller() is None


def test_audit_entries_without_a_gateway_caller_are_unchanged(audit):
    asyncio.run(gw_core._audit_decision({"tenant_id": TENANT, "tool": "t", "allowed": True}))
    assert "identity" not in audit[0]["metadata"]


# ── latency budget ───────────────────────────────────────────────────────


def test_reads_per_request_stay_within_budget(client, router, monkeypatch):
    """Tenant-key callers add no read; a principal token adds the revocation
    read, plus one principal read only when the 15 s cache is cold."""
    import storage.revocation as rev
    counts = {"principal": 0, "revocation": 0}
    real_get, real_exists = ps.get_principal, rev._exists

    def get(*a, **k):
        counts["principal"] += 1
        return real_get(*a, **k)

    def exists(*a, **k):
        counts["revocation"] += 1
        return real_exists(*a, **k)
    monkeypatch.setattr(ps, "get_principal", get)
    monkeypatch.setattr(rev, "_exists", exists)

    _call(client, {"X-API-Key": TENANT_KEY, "X-Agent-Key": "bot"})
    assert counts == {"principal": 0, "revocation": 0}

    token = _token(_user())
    _call(client, _bearer(token))
    assert counts == {"principal": 1, "revocation": 1}
    _call(client, _bearer(token))                   # warm: one read in total
    assert counts == {"principal": 1, "revocation": 2}


def test_a_status_change_is_seen_once_the_cache_expires(client, router, audit, monkeypatch):
    alice = _user()
    token = _token(alice)
    _call(client, _bearer(token))
    ps.set_status(TENANT, alice["id"], ps.STATUS_SUSPENDED)
    now = time.monotonic()
    monkeypatch.setattr(principal.time, "monotonic", lambda: now + principal._CACHE_TTL_S + 1)
    assert _call(client, _bearer(token)).status_code == 401
