"""API key scopes: runtime vs admin, stored but not yet enforced.

A key resolves to a tenant and nothing else, so the credential an agent must
hold to be guarded is also the credential that can rewrite the agent registry
and grant that agent every tool. Scope is the split.

This change stores and reports scope. It enforces nothing — that is the next
one — so the load-bearing tests here are the ones asserting the guard path is
untouched and that an absent scope behaves exactly as before:

  * test_the_guard_path_reads_no_scope
  * test_resolve_tenant_does_not_consult_the_scope_record
  * test_absent_scope_reads_as_none

The rest is round trip, cache invalidation, and the two ways garbage must not
read as privilege.

Spec: docs/spec-registry-write-authorization.md PR 1
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from storage import tenant_store as ts

TENANT = "acme"
RUNTIME_KEY = "sk-runtime-aaa"
ADMIN_KEY = "sk-admin-bbb"
LEGACY_KEY = "sk-legacy-ccc"


@pytest.fixture
def store(monkeypatch):
    """In-memory store, no Redis, cache cleared between tests."""
    data: dict = {}
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setattr(ts, "_fallback_store", data)
    monkeypatch.setattr(ts, "_cache", {})
    return data


# ── round trip ───────────────────────────────────────────────────────────


def test_scope_round_trips(store):
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert ts.key_scope(ADMIN_KEY) == "admin"


def test_runtime_scope_round_trips(store):
    ts.add_api_key(TENANT, RUNTIME_KEY, scope="runtime")
    assert ts.key_scope(RUNTIME_KEY) == "runtime"


def test_absent_scope_reads_as_none(store):
    """Every key that exists today. Absent must mean legacy, not denied."""
    ts.add_api_key(TENANT, LEGACY_KEY)
    assert ts.key_scope(LEGACY_KEY) is None


def test_scope_does_not_disturb_tenant_resolution(store):
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert ts.resolve_tenant_by_api_key(ADMIN_KEY) == TENANT


def test_by_hash_matches_by_key(store):
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert ts.key_scope_by_hash(ts._hash_key(ADMIN_KEY)) == "admin"


def test_empty_inputs_are_none_not_an_error(store):
    assert ts.key_scope("") is None
    assert ts.key_scope_by_hash("") is None


# ── garbage must not read as privilege ───────────────────────────────────


def test_unknown_scope_is_refused_at_write(store):
    with pytest.raises(ValueError):
        ts.set_key_scope(ADMIN_KEY, "superuser")


def test_unknown_stored_value_reads_as_unscoped_not_admin(store):
    """Direct store corruption, or a value written by a future version."""
    store[f"apikeyscope:{ts._hash_key(ADMIN_KEY)}"] = "superuser"
    assert ts.key_scope(ADMIN_KEY) is None


def test_bytes_from_redis_are_decoded(store):
    store[f"apikeyscope:{ts._hash_key(ADMIN_KEY)}"] = b"admin"
    assert ts.key_scope(ADMIN_KEY) == "admin"


# ── cache correctness ────────────────────────────────────────────────────


def test_downgrade_takes_effect_immediately(store):
    """A downgrade a stale cache ignores is a control that silently does not
    apply — worse than never having set it."""
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert ts.key_scope(ADMIN_KEY) == "admin"      # populates the cache
    ts.set_key_scope(ADMIN_KEY, "runtime")
    assert ts.key_scope(ADMIN_KEY) == "runtime"


def test_clearing_a_scope_takes_effect_immediately(store):
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert ts.key_scope(ADMIN_KEY) == "admin"
    ts.set_key_scope(ADMIN_KEY, None)
    assert ts.key_scope(ADMIN_KEY) is None


def test_reminting_over_a_hash_does_not_inherit_the_old_scope(store):
    """Re-adding a key with no scope must clear it, not silently keep admin."""
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    ts.add_api_key(TENANT, ADMIN_KEY)
    assert ts.key_scope(ADMIN_KEY) is None


def test_removing_a_key_removes_its_scope(store):
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    ts.remove_api_key(ADMIN_KEY)
    assert ts.key_scope(ADMIN_KEY) is None
    assert ts.resolve_tenant_by_api_key(ADMIN_KEY) is None


# ── the guard path must not pay for this ─────────────────────────────────


def test_the_guard_path_reads_no_scope(store, monkeypatch):
    """resolve_tenant_by_api_key runs on every guarded request. The scope
    record is a sidecar precisely so that call is unchanged."""
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    monkeypatch.setattr(ts, "_cache", {})          # cold cache, worst case

    reads: list = []
    real_get = dict.get

    class _Spy(dict):
        def get(self, k, *a):
            reads.append(k)
            return real_get(self, k, *a)

    monkeypatch.setattr(ts, "_fallback_store", _Spy(store))
    for _ in range(50):
        ts.resolve_tenant_by_api_key(ADMIN_KEY)

    assert not [k for k in reads if "apikeyscope" in k], \
        f"guard path read the scope record: {reads[:5]}"


def test_resolve_tenant_does_not_consult_the_scope_record():
    """Source-level companion to the test above. A behavioural spy only catches
    a read that happens today; this catches the reference added tomorrow."""
    import inspect
    src = inspect.getsource(ts.resolve_tenant_by_api_key)
    assert "apikeyscope" not in src
    assert "key_scope" not in src


# ── minting ──────────────────────────────────────────────────────────────


@pytest.fixture
def admin_client(store, monkeypatch):
    import api.routes_tenant as rt
    monkeypatch.setattr(rt, "get_tenant", lambda t: {"tenant_id": t})
    monkeypatch.setattr(rt, "log_admin_action",
                        lambda **kw: audit.append(kw) or {})
    app = FastAPI()
    app.include_router(rt.router)
    return TestClient(app)


audit: list = []


def _mint(client, key, **extra):
    audit.clear()
    body = {"api_key": key}
    body.update(extra)
    return client.post(f"/v1/admin/tenants/{TENANT}/api-keys", json=body)


def test_minting_without_a_scope_is_unchanged(admin_client):
    """Every existing caller sends no scope. That must keep working."""
    r = _mint(admin_client, LEGACY_KEY)
    assert r.status_code == 200, r.text
    assert ts.key_scope(LEGACY_KEY) is None


def test_minting_with_a_scope(admin_client):
    r = _mint(admin_client, ADMIN_KEY, scope="admin")
    assert r.status_code == 200, r.text
    assert r.json()["scope"] == "admin"
    assert ts.key_scope(ADMIN_KEY) == "admin"


def test_minting_an_unknown_scope_is_a_400(admin_client):
    assert _mint(admin_client, ADMIN_KEY, scope="superuser").status_code == 400


def test_minting_a_non_string_scope_is_a_400(admin_client):
    assert _mint(admin_client, ADMIN_KEY, scope=["admin"]).status_code == 400


def test_the_admin_audit_records_the_scope(admin_client):
    """Who was handed an admin key is the question this mechanism exists to
    make answerable."""
    _mint(admin_client, ADMIN_KEY, scope="admin")
    assert audit and audit[-1]["metadata"]["scope"] == "admin"


def test_the_admin_audit_records_unscoped_explicitly(admin_client):
    _mint(admin_client, LEGACY_KEY)
    assert audit[-1]["metadata"]["scope"] == "unscoped"


# ── reading your own scope ───────────────────────────────────────────────


class _StashingAuth(BaseHTTPMiddleware):
    """Stands in for AuthMiddleware: resolves a tenant AND stashes the hash."""

    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key") or ""
        bearer = (request.headers.get("Authorization") or "")[7:]
        actual = key or bearer
        if actual:
            request.state.tenant_id = TENANT
            request.state.api_key_hash = ts._hash_key(actual)
        return await call_next(request)


@pytest.fixture
def me_client(store, monkeypatch):
    import api.routes_tenant_self as rts
    monkeypatch.setattr(rts, "_require_tenant", lambda r: TENANT)
    app = FastAPI()
    app.add_middleware(_StashingAuth)
    app.include_router(rts.router)
    return TestClient(app)


def _scope_of(client, key, bearer=False):
    h = ({"Authorization": f"Bearer {key}"} if bearer else {"X-API-Key": key})
    return client.get("/v1/tenant/me/key-scope", headers=h).json()


def test_reports_an_admin_scope(me_client):
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert _scope_of(me_client, ADMIN_KEY)["scope"] == "admin"


def test_reports_null_for_an_unscoped_key(me_client):
    ts.add_api_key(TENANT, LEGACY_KEY)
    assert _scope_of(me_client, LEGACY_KEY)["scope"] is None


def test_a_bearer_caller_gets_its_real_scope(me_client):
    """The endpoint reads the stashed hash, not the X-API-Key header. Reading
    the header would report "unscoped" for every Bearer caller."""
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert _scope_of(me_client, ADMIN_KEY, bearer=True)["scope"] == "admin"


def test_enforcement_defaults_to_off(me_client):
    assert _scope_of(me_client, LEGACY_KEY)["enforcement"] == "off"


def test_registry_write_is_true_while_enforcement_is_off(me_client):
    """An unscoped key still writes today. Reporting otherwise would have the
    portal hide controls that in fact work."""
    ts.add_api_key(TENANT, LEGACY_KEY)
    assert _scope_of(me_client, LEGACY_KEY)["registry_write"] is True


def test_registry_write_is_false_for_a_runtime_key_under_enforce(me_client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    ts.add_api_key(TENANT, RUNTIME_KEY, scope="runtime")
    body = _scope_of(me_client, RUNTIME_KEY)
    assert body["enforcement"] == "enforce"
    assert body["registry_write"] is False


def test_an_unscoped_key_loses_registry_write_under_enforce(me_client, monkeypatch):
    """The migration cliff, reported honestly before it bites."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    ts.add_api_key(TENANT, LEGACY_KEY)
    assert _scope_of(me_client, LEGACY_KEY)["registry_write"] is False


def test_an_admin_key_keeps_registry_write_under_enforce(me_client, monkeypatch):
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    ts.add_api_key(TENANT, ADMIN_KEY, scope="admin")
    assert _scope_of(me_client, ADMIN_KEY)["registry_write"] is True


def test_an_unknown_enforcement_value_reads_as_off(me_client, monkeypatch):
    """A typo in a deploy config must not silently enable or disable a
    control. Falling back to off matches the documented default."""
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforced")   # typo
    ts.add_api_key(TENANT, LEGACY_KEY)
    assert _scope_of(me_client, LEGACY_KEY)["enforcement"] == "off"
