"""Per-tenant role-binding config: reachable, cached, and tenant-safe.

`shield:role_binding:{tenant_id}` carries the IdP claim path and group-to-role
map. It was unreachable in production for one reason: every one of the seven
`resolve_identity()` call sites omitted `tenant_id`, so `role_binding_config()`
always returned the env-only default and `role_claim` was pinned to Keycloak's
`realm_access.roles`. Okta puts roles at `groups`, Entra at `roles`.

Three properties are locked here:

  * the config is actually read, and the tenant comes from the AUTHENTICATED
    tenant rather than a caller-settable header;
  * a deployment with binding off performs zero store reads on the guard path;
  * a tenant with config performs one read per TTL, not one per request and not
    two per request.

Spec: docs/spec-idp-role-claim-config.md task 1
"""
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.identity_resolution import (SOURCE_HEADER, SOURCE_OIDC,
                                      clear_role_binding_cache_for_tests,
                                      extract_roles, resolve_identity,
                                      role_binding_config, role_binding_mode)

_ENV_KEYS = ("SHIELD_ROLE_BINDING", "SHIELD_TRUSTED_PROXY_ONLY",
             "SHIELD_TRUSTED_PROXY_SECRET", "SHIELD_TOKEN_BINDING",
             "SHIELD_DELEGATION")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    clear_role_binding_cache_for_tests()
    yield
    clear_role_binding_cache_for_tests()


class CountingRedis:
    """A Redis stand-in that counts GETs, so caching is asserted not assumed."""

    def __init__(self, values=None):
        self.values = values or {}
        self.gets = 0

    def get(self, key):
        self.gets += 1
        return self.values.get(key)


OKTA_CONFIG = json.dumps({"mode": "prefer", "role_claim": "groups",
                          "role_map": {"bank-payments": "payments_officer"}})


def _request(*, tenant_id=None, tenant_header=None, role_header="branch_manager",
             claims=None):
    headers = {"X-User-Role": role_header, "X-Agent-Key": "bot"}
    if tenant_header is not None:
        headers["X-Tenant-ID"] = tenant_header

    state = SimpleNamespace(identity=None)
    if tenant_id is not None:
        state.tenant_id = tenant_id
    if claims is not None:
        state.workload_identity = SimpleNamespace(claims=claims)

    return SimpleNamespace(
        headers=headers, state=state,
        client=SimpleNamespace(host="10.0.0.5"),
        method="POST", url="https://shield.local/guardrails/input")


def _redis(values):
    return patch("storage.tenant_store._get_redis",
                 return_value=CountingRedis(values))


# ── The config is reachable at all ───────────────────────────────────────────


def test_tenant_claim_path_is_actually_used(monkeypatch):
    """An Okta-shaped tenant resolves roles from `groups`.

    Before this change role_claim was pinned to realm_access.roles, so an Okta
    token resolved no roles and binding silently fell back to the header.
    """
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    with patch("storage.tenant_store._get_redis", return_value=r):
        cfg = role_binding_config("bankco")
    assert cfg["role_claim"] == "groups"
    assert cfg["role_map"] == {"bank-payments": "payments_officer"}


def test_role_map_renames_the_idp_group(monkeypatch):
    """The IdP's group name is not Shield's role name."""
    roles = extract_roles({"groups": ["bank-payments"]}, "groups",
                          {"bank-payments": "payments_officer"})
    assert roles == ("payments_officer",)


def test_tenant_id_comes_from_authenticated_state(monkeypatch):
    """resolve_identity resolves the tenant itself — no call site passes it."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request(tenant_id="bankco", claims={"groups": ["bank-payments"]})
    with patch("storage.tenant_store._get_redis", return_value=r):
        res = resolve_identity(req)
    assert res.user_role == "payments_officer"
    assert res.role_source == SOURCE_OIDC
    assert res.role_verified is True
    assert r.gets >= 1, "the tenant config was never read"


def test_header_role_is_ignored_once_the_claim_resolves(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request(tenant_id="bankco", role_header="branch_manager",
                   claims={"groups": ["bank-payments"]})
    with patch("storage.tenant_store._get_redis", return_value=r):
        res = resolve_identity(req)
    assert res.user_role != "branch_manager"
    assert res.header_overridden is True


# ── Tenant selection must follow authentication, not assertion ───────────────


def test_x_tenant_id_header_does_not_select_the_config(monkeypatch):
    """The security property.

    Role-binding config decides which claim path is read and how IdP groups map
    to Shield roles. If a caller could name the tenant whose mapping applies, it
    could pick a config that maps its own groups onto another tenant's
    privileged role. Config selection follows authentication.
    """
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request(tenant_header="bankco", claims={"groups": ["bank-payments"]})
    with patch("storage.tenant_store._get_redis", return_value=r):
        res = resolve_identity(req)
    assert r.gets == 0, "a caller-settable header selected the tenant config"
    assert res.user_role == "branch_manager"
    assert res.role_source == SOURCE_HEADER


def test_explicit_tenant_id_argument_still_wins(monkeypatch):
    """Callers that genuinely know the tenant may still pass it."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request(claims={"groups": ["bank-payments"]})
    with patch("storage.tenant_store._get_redis", return_value=r):
        res = resolve_identity(req, tenant_id="bankco")
    assert res.user_role == "payments_officer"


# ── Guard-path cost ──────────────────────────────────────────────────────────


def test_binding_off_performs_zero_store_reads(monkeypatch):
    """The latency contract. A deployment with binding off must pay nothing:
    the env kill switch is checked before any store is touched."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "off")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request(tenant_id="bankco")
    with patch("storage.tenant_store._get_redis", return_value=r):
        for _ in range(25):
            resolve_identity(req)
    assert r.gets == 0


def test_unset_binding_performs_zero_store_reads(monkeypatch):
    """Default (unset) is off, and must behave identically."""
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request(tenant_id="bankco")
    with patch("storage.tenant_store._get_redis", return_value=r):
        for _ in range(25):
            resolve_identity(req)
    assert r.gets == 0


def test_one_read_per_tenant_not_one_per_request(monkeypatch):
    """Whole config under one cache entry.

    The previous arrangement cached the mode but then issued a SECOND, uncached
    GET on the same key for the claim path — one synchronous Redis round trip
    per guarded request the moment the config became reachable.
    """
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request(tenant_id="bankco", claims={"groups": ["bank-payments"]})
    with patch("storage.tenant_store._get_redis", return_value=r):
        for _ in range(50):
            resolve_identity(req)
    assert r.gets == 1, f"expected one cached read, got {r.gets}"


def test_absent_config_is_cached_too(monkeypatch):
    """A tenant with no stored config is the common case. Re-reading an absent
    key every request is the same round trip as reading a present one."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({})
    req = _request(tenant_id="no-config-tenant")
    with patch("storage.tenant_store._get_redis", return_value=r):
        for _ in range(30):
            resolve_identity(req)
    assert r.gets == 1


# ── Degradation ──────────────────────────────────────────────────────────────


def test_redis_unavailable_falls_back_to_env(monkeypatch):
    """'Cannot read config' must not mean 'deny every tenant'."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    with patch("storage.tenant_store._get_redis", return_value=None):
        assert role_binding_mode("bankco") == "prefer"
        assert role_binding_config("bankco")["role_claim"] == "realm_access.roles"


def test_redis_raising_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    with patch("storage.tenant_store._get_redis", side_effect=RuntimeError("down")):
        assert role_binding_mode("bankco") == "prefer"


def test_malformed_stored_json_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    with _redis({"shield:role_binding:bankco": "{not json"}):
        assert role_binding_mode("bankco") == "prefer"
        assert role_binding_config("bankco")["role_claim"] == "realm_access.roles"


def test_non_dict_stored_value_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    with _redis({"shield:role_binding:bankco": '["a", "list"]'}):
        assert role_binding_config("bankco")["role_map"] == {}


def test_missing_storage_module_falls_back_to_env(monkeypatch):
    """The module is lazily imported and absent from images that do not COPY
    it. That must degrade to env defaults, not raise on the guard path."""
    import sys
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    monkeypatch.setitem(sys.modules, "storage.role_binding_config", None)
    assert role_binding_mode("bankco") == "prefer"


def test_env_off_still_beats_a_tenant_opting_in(monkeypatch):
    """The operator kill switch, now also proving it short-circuits the read."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "off")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    with patch("storage.tenant_store._get_redis", return_value=r):
        assert role_binding_mode("bankco") == "off"
    assert r.gets == 0


def test_no_tenant_resolves_to_env_default(monkeypatch):
    """An unauthenticated request has no tenant, and must not read anything."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    r = CountingRedis({"shield:role_binding:bankco": OKTA_CONFIG})
    req = _request()
    with patch("storage.tenant_store._get_redis", return_value=r):
        res = resolve_identity(req)
    assert r.gets == 0
    assert res.user_role == "branch_manager"


def test_tenant_mode_overrides_env(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    with _redis({"shield:role_binding:t1": json.dumps({"mode": "strict"})}):
        assert role_binding_mode("t1") == "strict"


def test_dockerfile_admin_copies_the_new_module():
    """The lazy import is inside a try/except, so a missing COPY does not
    crash the admin image — it silently ignores every tenant's IdP config.
    The transitive-import guard cannot see a lazy import, so assert it here."""
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "Dockerfile.admin")) as f:
        assert "COPY storage/role_binding_config.py storage/" in f.read()
