"""Per-person upstream grants, and the credential fixes that come with them.

Task B1 of docs/specs/mcp-verified-callers-and-user-credentials.md. Nothing on
the guard path changes yet (B2 starts using grants). What this covers:

- storage/mcp_grant_store.py: each person's tokens, sealed with the vault key
  and tied to tenant, route, person and kind, released only to their host;
- the renewal lock now has an owner, so a slow renewal cannot release a lock
  another renewal holds, and a person's credential never renews unlocked;
- the pending OAuth state is consumed atomically;
- a route's shared OAuth credential can be disconnected, and deleting a server
  revokes and removes its shared credential and every person's grant.
"""
import asyncio
import base64
import json

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
import core.mcp_credentials as creds
import storage.mcp_grant_store as grants
import storage.mcp_oauth_store as ostore
from storage import mcp_gateway_store as gstore

T, R = "acme", "gdrive"
ALICE, BOB = "usr_alice00000", "usr_bob0000000"
UPSTREAM = "drivemcp.googleapis.com"
TOKEN_HOST = "oauth2.googleapis.com"
REVOKE = "https://oauth2.googleapis.com/revoke"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def vault(monkeypatch):
    from core.secret_vault.keyprovider import _reset_provider_for_tests
    from storage.tenant_store import _fallback_store
    import storage.tenant_store as ts

    def _clear():
        for k in [k for k in _fallback_store if k.startswith(
                ("vault:", "mcp_grant", "mcp_oauth:", "mcp_gateway:"))]:
            del _fallback_store[k]
    _clear()
    monkeypatch.setenv("SECRET_VAULT_ENABLED", "true")
    monkeypatch.setenv("SECRET_VAULT_KEY_PROVIDER", "software")
    monkeypatch.setenv("SECRET_VAULT_KEK", base64.b64encode(b"k" * 32).decode())
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(grants, "_get_redis", lambda: None)
    monkeypatch.setattr(ostore, "_get_redis", lambda: None)
    monkeypatch.setattr("core.url_safety.validate_outbound_url", lambda u, purpose=None: u)
    _reset_provider_for_tests()
    yield
    _reset_provider_for_tests()
    _clear()


def _store(pid=ALICE, access="ya29.alice-access", refresh="1//alice-refresh", **kw):
    return grants.store_tokens(T, R, pid, access_token=access, access_bindings=[UPSTREAM],
                               refresh_token=refresh, refresh_bindings=[TOKEN_HOST],
                               expires_at=2_000_000_000, **kw)


# ── the store ────────────────────────────────────────────────────────────


def test_each_persons_token_is_released_only_to_its_own_host():
    _store()
    assert grants.access_token_for(T, R, ALICE, f"https://{UPSTREAM}/mcp/v1") == "ya29.alice-access"
    assert grants.refresh_token_for(T, R, ALICE, f"https://{TOKEN_HOST}/token") == "1//alice-refresh"
    for kind, dest in ((grants.access_token_for, "https://evil.test/mcp"),
                       (grants.access_token_for, f"https://{TOKEN_HOST}/token"),
                       (grants.refresh_token_for, f"https://{UPSTREAM}/mcp")):
        with pytest.raises(grants.GrantError) as e:
            kind(T, R, ALICE, dest)
        assert e.value.reason == "binding_mismatch"


def test_tokens_are_never_stored_or_returned_in_plaintext():
    from storage.tenant_store import _fallback_store
    view = _store(upstream_account="alice@acme.example", scopes="drive.readonly openid")
    stored = json.dumps({k: v for k, v in _fallback_store.items() if k.startswith("mcp_grant")})
    assert "alice-access" not in stored and "alice-refresh" not in stored
    assert "access" not in view and "refresh" not in view
    assert view["status"] == "connected" and view["refresh_token_held"] is True
    assert view["upstream_account"] == "alice@acme.example"
    assert view["scopes"] == ["drive.readonly", "openid"]
    assert grants.get_grant(T, R, ALICE) == view


def test_one_persons_sealed_token_cannot_be_used_as_anothers():
    """Copying Alice's sealed token into Bob's grant must not let Bob's slot
    release Alice's token: the seal names the person."""
    from storage.tenant_store import _fallback_store
    _store(ALICE)
    _store(BOB, access="ya29.bob-access")
    alice = json.loads(_fallback_store[f"mcp_grant:{T}:{R}:{ALICE}"])
    bob = json.loads(_fallback_store[f"mcp_grant:{T}:{R}:{BOB}"])
    bob["access"] = alice["access"]
    _fallback_store[f"mcp_grant:{T}:{R}:{BOB}"] = json.dumps(bob)
    with pytest.raises(grants.GrantError) as e:
        grants.access_token_for(T, R, BOB, f"https://{UPSTREAM}/mcp")
    assert e.value.reason == "unreadable"


def test_a_renewal_without_a_new_refresh_token_keeps_the_old_one():
    _store()
    grants.store_tokens(T, R, ALICE, access_token="ya29.new", access_bindings=[UPSTREAM])
    assert grants.access_token_for(T, R, ALICE, f"https://{UPSTREAM}/") == "ya29.new"
    assert grants.refresh_token_for(T, R, ALICE, f"https://{TOKEN_HOST}/") == "1//alice-refresh"
    grants.store_tokens(T, R, ALICE, access_token="ya29.newer", access_bindings=[UPSTREAM],
                        refresh_token="1//rotated", refresh_bindings=[TOKEN_HOST])
    assert grants.refresh_token_for(T, R, ALICE, f"https://{TOKEN_HOST}/") == "1//rotated"


@pytest.mark.parametrize("setup, reason", [
    (lambda: None, "not_connected"),
    (lambda: (_store(), grants.set_status(T, R, ALICE, grants.STATUS_NEEDS_CONSENT)), "needs_consent"),
])
def test_a_missing_or_lapsed_grant_says_why(setup, reason):
    setup()
    with pytest.raises(grants.GrantError) as e:
        grants.access_token_for(T, R, ALICE, f"https://{UPSTREAM}/")
    assert e.value.reason == reason


def test_without_the_vault_nothing_is_stored(monkeypatch):
    monkeypatch.setenv("SECRET_VAULT_ENABLED", "false")
    with pytest.raises(grants.GrantError) as e:
        _store()
    assert e.value.reason == "vault_disabled" and grants.get_grant(T, R, ALICE) is None


def test_grants_are_indexed_both_ways_and_deleted_cleanly():
    _store(ALICE)
    _store(BOB)
    grants.store_tokens(T, "gmail", ALICE, access_token="a", access_bindings=["gmail.test"])
    assert grants.principals_for_route(T, R) == [ALICE, BOB]
    assert grants.routes_for_principal(T, ALICE) == ["gdrive", "gmail"]
    assert [g["principal_id"] for g in grants.list_grants(T, R)] == [ALICE, BOB]
    assert grants.delete_grant(T, R, ALICE) is True
    assert grants.principals_for_route(T, R) == [BOB]
    assert grants.routes_for_principal(T, ALICE) == ["gmail"]
    assert grants.get_grant("globex", R, BOB) is None


# ── the renewal lock ─────────────────────────────────────────────────────


class _Redis:
    """Enough Redis for the lock: SET NX EX, GET, DEL and the owner script."""

    def __init__(self, *, scripting=True, broken=False):
        self.data, self.scripting, self.broken = {}, scripting, broken

    def set(self, k, v, nx=False, ex=None):
        if self.broken:
            raise RuntimeError("redis down")
        if nx and k in self.data:
            return False
        self.data[k] = v
        return True

    def get(self, k):
        return self.data.get(k)

    def delete(self, k):
        return 1 if self.data.pop(k, None) is not None else 0

    def eval(self, script, n, key, owner):
        if not self.scripting:
            raise RuntimeError("no scripting")
        return self.delete(key) if self.data.get(key) == owner else 0


@pytest.mark.parametrize("scripting", [True, False])
def test_a_lock_is_released_only_by_its_owner(monkeypatch, scripting):
    import storage.tenant_store as ts
    r = _Redis(scripting=scripting)
    monkeypatch.setattr(ts, "_get_redis", lambda: r)
    first = creds.take_lock(T, R)
    assert first and creds.take_lock(T, R) == ""          # single flight
    # The first renewal overran its TTL; a second one took the lock.
    r.data.clear()
    second = creds.take_lock(T, R)
    creds.drop_lock(T, R, first)                           # the late release
    assert r.data, "a late release deleted someone else's lock"
    creds.drop_lock(T, R, second)
    assert not r.data


def test_a_persons_credential_never_renews_unlocked(monkeypatch):
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: _Redis(broken=True))
    assert creds.take_lock(T, R, subject=ALICE) == ""
    assert creds.take_lock(T, R)            # shared credential: unchanged behaviour


def test_locks_are_per_person(monkeypatch):
    import storage.tenant_store as ts
    r = _Redis()
    monkeypatch.setattr(ts, "_get_redis", lambda: r)
    assert creds.take_lock(T, R, subject=ALICE)
    assert creds.take_lock(T, R, subject=BOB)              # not blocked by Alice
    assert creds.take_lock(T, R, subject=ALICE) == ""


def test_renew_route_releases_only_its_own_lock(monkeypatch):
    seen = []
    monkeypatch.setattr(creds, "take_lock", lambda t, r, **k: "owner-1")
    monkeypatch.setattr(creds, "drop_lock", lambda t, r, owner, **k: seen.append(owner))
    ostore.set_broker(T, R, {"mode": creds.MODE_AUTH_CODE, "status": "connected"})

    class _P:
        async def renew(self, ctx):
            return {"expires_at": 1}
    monkeypatch.setattr(creds, "get_provider", lambda mode: _P())
    monkeypatch.setattr(creds, "modes_enabled", lambda: {creds.MODE_AUTH_CODE})
    assert run(creds.renew_route(T, R))["renewed"] is True
    assert seen == ["owner-1"]


# ── the pending state ────────────────────────────────────────────────────


def test_a_pending_state_is_consumed_in_one_step(monkeypatch):
    class _R:
        def __init__(self):
            self.data, self.ops = {}, []

        def set(self, k, v, ex=None):
            self.data[k] = v

        def getdel(self, k):
            self.ops.append("getdel")
            return self.data.pop(k, None)
    r = _R()
    monkeypatch.setattr(ostore, "_get_redis", lambda: r)
    s = ostore.new_state()
    ostore.put_pending(s, T, R, "verifier", "https://shield/cb")
    assert ostore.take_pending(s)["route"] == R
    assert ostore.take_pending(s) is None
    assert r.ops == ["getdel", "getdel"]


# ── disconnect and delete ────────────────────────────────────────────────


def _http(log, status=200):
    def handler(request):
        log.append((str(request.url), dict(httpx.QueryParams(request.content.decode()))))
        return httpx.Response(status, json={})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _connected_shared_route(headers=None):
    from storage.vault_store import create_vault_entry
    gstore.set_upstream(T, R, {"route": R, "transport": "http", "url": f"https://{UPSTREAM}/mcp/v1",
                               "credential_mode": creds.MODE_AUTH_CODE,
                               "headers": headers or {"Authorization": f"Bearer shield://oauth-{R}-access",
                                                      "X-Other": "kept"}})
    ostore.set_broker(T, R, {"mode": creds.MODE_AUTH_CODE, "status": "connected",
                             "client_id": "client-1", "revocation_endpoint": REVOKE,
                             "token_endpoint": f"https://{TOKEN_HOST}/token",
                             "access_token_ref": f"shield://oauth-{R}-access",
                             "refresh_token_ref": f"shield://oauth-{R}-refresh"})
    create_vault_entry(T, name=f"oauth-{R}-access", value="shared-access", bindings=[UPSTREAM])
    create_vault_entry(T, name=f"oauth-{R}-refresh", value="shared-refresh", bindings=[TOKEN_HOST])


def test_disconnect_revokes_and_removes_the_shared_credential():
    from storage.vault_store import get_vault_entries
    _connected_shared_route()
    log = []
    out = run(creds.disconnect_route(T, R, client=_http(log)))
    assert out == {"had_connection": True, "revocation_attempted": True}
    assert log and log[0][0] == REVOKE and log[0][1]["token"] == "shared-refresh"
    assert ostore.get_broker(T, R) is None and get_vault_entries(T) == []
    cfg = gstore.get_upstream(T, R)
    assert cfg["headers"] == {"X-Other": "kept"} and "credential_mode" not in cfg


def test_disconnect_leaves_an_operator_set_header_alone():
    _connected_shared_route(headers={"Authorization": "Bearer operator-pasted"})
    run(creds.disconnect_route(T, R, client=_http([])))
    assert gstore.get_upstream(T, R)["headers"] == {"Authorization": "Bearer operator-pasted"}


def test_a_provider_outage_never_blocks_the_local_delete():
    _connected_shared_route()
    _store(ALICE)
    run(creds.disconnect_route(T, R, client=_http([], status=503)))
    assert run(creds.revoke_grant(T, R, ALICE, client=_http([], status=503))) is True
    assert ostore.get_broker(T, R) is None and grants.get_grant(T, R, ALICE) is None


def test_a_persons_grant_is_revoked_with_their_own_refresh_token():
    _connected_shared_route()
    _store(ALICE)
    log = []
    assert run(creds.revoke_grant(T, R, ALICE, client=_http(log))) is True
    assert log[0][0] == REVOKE and log[0][1]["token"] == "1//alice-refresh"
    assert log[0][1]["token_type_hint"] == "refresh_token"
    assert grants.get_grant(T, R, ALICE) is None


def test_a_token_is_never_sent_to_a_revocation_host_it_is_not_bound_to():
    _connected_shared_route()
    ostore.set_broker(T, R, {**ostore.get_broker(T, R),
                             "revocation_endpoint": "https://elsewhere.test/revoke"})
    _store(ALICE)
    log = []
    run(creds.revoke_grant(T, R, ALICE, client=_http(log)))
    assert log == [] and grants.get_grant(T, R, ALICE) is None


def test_offboarding_revokes_every_grant_a_person_holds():
    _store(ALICE)
    grants.store_tokens(T, "gmail", ALICE, access_token="a", access_bindings=["gmail.test"])
    _store(BOB)
    assert run(creds.revoke_principal_grants(T, ALICE, client=_http([]))) == 2
    assert grants.routes_for_principal(T, ALICE) == []
    assert grants.get_grant(T, R, BOB) is not None


@pytest.fixture
def admin_client(monkeypatch):
    logged = []
    import storage.admin_audit as aa
    monkeypatch.setattr(aa, "log_admin_action", lambda **k: logged.append(k))
    real_disconnect, real_revoke = creds.disconnect_route, creds.revoke_route_grants
    monkeypatch.setattr(creds, "disconnect_route",
                        lambda t, r, **k: real_disconnect(t, r, client=_http([]), **k))
    monkeypatch.setattr(creds, "revoke_route_grants",
                        lambda t, r, **k: real_revoke(t, r, client=_http([])))
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        request.state.tenant_id = T
        return await call_next(request)
    app.include_router(admin.router)
    c = TestClient(app)
    c.logged = logged
    return c


def test_deleting_a_server_removes_every_credential_it_had(admin_client):
    from storage.vault_store import get_vault_entries
    _connected_shared_route()
    _store(ALICE)
    _store(BOB)
    r = admin_client.delete(f"/v1/tenant/me/mcp/servers/{R}")
    assert r.status_code == 200, r.text
    assert r.json()["shared_credential_removed"] is True
    assert r.json()["personal_connections_revoked"] == 2
    assert ostore.get_broker(T, R) is None and get_vault_entries(T) == []
    assert grants.principals_for_route(T, R) == []
    assert admin_client.logged[-1]["after"]["personal_connections_revoked"] == 2
    assert admin_client.delete(f"/v1/tenant/me/mcp/servers/{R}").status_code == 404


def test_the_shared_oauth_connection_can_be_disconnected(admin_client):
    _connected_shared_route()
    r = admin_client.delete(f"/v1/tenant/me/mcp/servers/{R}/oauth")
    assert r.status_code == 200 and r.json()["status"] == "disconnected"
    assert admin_client.logged[-1]["action"] == "mcp_oauth_disconnected"
    assert admin_client.delete(f"/v1/tenant/me/mcp/servers/{R}/oauth").status_code == 404
    assert gstore.get_upstream(T, R) is not None          # the server stays


def test_the_admin_image_carries_the_grant_store():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert "COPY storage/mcp_grant_store.py " in open(os.path.join(root, "Dockerfile.admin")).read()
