"""One claim path for role binding and delegation, and namespaced claims.

Three defects, all of which present as "role binding is broken" rather than as
themselves:

  * `core/delegation.py` read `SHIELD_ROLE_CLAIM` while role binding read a
    per-tenant `role_claim`. Point a deployment at Okta and the two silently
    disagreed about where the role lives.
  * An Okta or Entra token carries every group the user belongs to. Without an
    allowlist the FIRST of them is taken as the role, purely because it was
    first in the token.
  * Auth0 and custom Okta claims are namespaced URLs containing dots, which the
    dotted-path reader split into nonsense and resolved to nothing.

Spec: docs/spec-idp-role-claim-config.md task 3
"""
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.identity_resolution import (DEFAULT_ROLE_CLAIM, SOURCE_OIDC,
                                      _split_path, claim_config,
                                      clear_role_binding_cache_for_tests,
                                      extract_roles, resolve_identity)

_ENV_KEYS = ("SHIELD_ROLE_BINDING", "SHIELD_ROLE_CLAIM", "SHIELD_DELEGATION",
             "SHIELD_TOKEN_BINDING", "SHIELD_TRUSTED_PROXY_ONLY")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    clear_role_binding_cache_for_tests()
    yield
    clear_role_binding_cache_for_tests()


def _redis(values):
    return patch("storage.tenant_store._get_redis",
                 return_value=SimpleNamespace(get=lambda k: values.get(k)))


# ── Namespaced claim paths ───────────────────────────────────────────────


def test_plain_dotted_paths_are_unchanged():
    """The regression guard: every existing config must parse identically."""
    assert _split_path("realm_access.roles") == ["realm_access", "roles"]
    assert _split_path("groups") == ["groups"]
    assert _split_path("roles") == ["roles"]


def test_bracket_quoted_segment_is_taken_literally():
    assert _split_path('["https://votal.ai/roles"]') == ["https://votal.ai/roles"]


def test_bracket_segments_mix_with_dotted_ones():
    assert _split_path('resource_access.["my.app"].roles') == [
        "resource_access", "my.app", "roles"]


def test_single_quotes_work_too():
    assert _split_path("['https://votal.ai/roles']") == ["https://votal.ai/roles"]


def test_unterminated_bracket_does_not_raise():
    """A typo on the guard path should yield no roles, not a 500."""
    assert extract_roles({"a": ["x"]}, '["unterminated') == ()


def test_auth0_namespaced_claim_resolves():
    claims = {"https://votal.ai/roles": ["payments_officer"]}
    assert extract_roles(claims, '["https://votal.ai/roles"]') == ("payments_officer",)


def test_namespaced_claim_without_brackets_still_fails():
    """Documents why the bracket syntax is needed at all: the dots in a URL
    would otherwise be read as nesting."""
    claims = {"https://votal.ai/roles": ["payments_officer"]}
    assert extract_roles(claims, "https://votal.ai/roles") == ()


# ── role_allowlist ───────────────────────────────────────────────────────


def test_allowlist_filters_unrelated_idp_groups():
    """The common Okta rollout failure. Without this, 'all-employees' becomes
    the role because it happened to be first in the token."""
    claims = {"groups": ["all-employees", "vpn-users", "payments-officers"]}
    roles = extract_roles(claims, "groups",
                          {"payments-officers": "payments_officer"},
                          ["payments_officer"])
    assert roles == ("payments_officer",)


def test_allowlist_applies_after_role_map():
    """The allowlist names SHIELD roles, not IdP groups. Applying it before the
    rename would filter out everything."""
    claims = {"groups": ["bank-payments"]}
    assert extract_roles(claims, "groups", {"bank-payments": "payments_officer"},
                         ["payments_officer"]) == ("payments_officer",)
    assert extract_roles(claims, "groups", {"bank-payments": "payments_officer"},
                         ["bank-payments"]) == ()


def test_empty_allowlist_filters_nothing():
    """A tenant that has not configured one must be unaffected."""
    claims = {"groups": ["a", "b"]}
    assert extract_roles(claims, "groups", None, []) == ("a", "b")
    assert extract_roles(claims, "groups", None, None) == ("a", "b")


def test_allowlist_preserves_issued_order():
    claims = {"groups": ["b", "a"]}
    assert extract_roles(claims, "groups", None, ["a", "b"]) == ("b", "a")


def test_allowlist_that_matches_nothing_yields_no_roles():
    claims = {"groups": ["all-employees"]}
    assert extract_roles(claims, "groups", None, ["payments_officer"]) == ()


# ── One source of truth for the claim path ───────────────────────────────


def test_env_role_claim_now_applies_to_role_binding(monkeypatch):
    """Role binding used to hard-code Keycloak's path and ignore this var,
    while delegation read it. Setting it for Okta fixed one path and silently
    not the other."""
    monkeypatch.setenv("SHIELD_ROLE_CLAIM", "groups")
    assert claim_config(None)["role_claim"] == "groups"


def test_default_is_unchanged_when_nothing_is_set():
    assert claim_config(None)["role_claim"] == DEFAULT_ROLE_CLAIM


def test_tenant_config_beats_the_env_var(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_CLAIM", "groups")
    with _redis({"shield:role_binding:t1": json.dumps({"role_claim": "roles"})}):
        assert claim_config("t1")["role_claim"] == "roles"


def test_claim_config_ignores_the_role_binding_mode(monkeypatch):
    """Delegation has its own switch. Requiring SHIELD_ROLE_BINDING to be on
    before a tenant's IdP config applies to delegation would be a footgun."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "off")
    with _redis({"shield:role_binding:t1": json.dumps({"role_claim": "groups"})}):
        assert claim_config("t1")["role_claim"] == "groups"


def test_delegation_uses_the_same_claim_path(monkeypatch):
    """The unification. Delegation must resolve the role from the tenant's
    configured claim, not from its own env knob."""
    from core.delegation import _roles_from

    monkeypatch.setenv("SHIELD_ROLE_CLAIM", "realm_access.roles")
    claims = {"groups": ["bank-payments"]}
    with _redis({"shield:role_binding:t1": json.dumps(
            {"role_claim": "groups", "role_map": {"bank-payments": "payments_officer"}})}):
        assert _roles_from(claims, "t1") == ("payments_officer",)


def test_delegation_falls_back_to_env_without_tenant_config(monkeypatch):
    """A deployment with no tenant config must behave exactly as before."""
    from core.delegation import _roles_from

    monkeypatch.setenv("SHIELD_ROLE_CLAIM", "groups")
    with _redis({}):
        assert _roles_from({"groups": ["auditor"]}, "t1") == ("auditor",)


def test_delegation_honours_the_tenant_allowlist(monkeypatch):
    from core.delegation import _roles_from

    claims = {"groups": ["all-employees", "auditor"]}
    with _redis({"shield:role_binding:t1": json.dumps(
            {"role_claim": "groups", "role_allowlist": ["auditor"]})}):
        assert _roles_from(claims, "t1") == ("auditor",)


# ── End to end through resolve_identity ──────────────────────────────────


def _request(tenant_id, claims):
    return SimpleNamespace(
        headers={"X-User-Role": "branch_manager", "X-Agent-Key": "bot"},
        state=SimpleNamespace(identity=None, tenant_id=tenant_id,
                              workload_identity=SimpleNamespace(claims=claims)),
        client=SimpleNamespace(host="10.0.0.5"),
        method="POST", url="https://shield.local/guardrails/input")


def test_okta_tenant_resolves_one_role_from_many_groups(monkeypatch):
    """The whole point, end to end: an Okta token carrying five groups resolves
    to exactly the one Shield role, with the forged header ignored."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    cfg = json.dumps({
        "mode": "prefer", "role_claim": "groups",
        "role_map": {"bank-payments": "payments_officer"},
        "role_allowlist": ["payments_officer", "auditor"],
    })
    claims = {"groups": ["all-employees", "vpn-users", "bank-payments",
                         "printer-access", "slack-users"]}
    with _redis({"shield:role_binding:bankco": cfg}):
        res = resolve_identity(_request("bankco", claims))

    assert res.user_role == "payments_officer"
    assert res.role_source == SOURCE_OIDC
    assert res.role_verified is True
    assert res.header_overridden is True


def test_allowlist_miss_under_strict_yields_no_role(monkeypatch):
    """Fail closed, and worth pinning: a misconfigured allowlist denies rather
    than falling back to the header."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "strict")
    cfg = json.dumps({"role_claim": "groups", "role_allowlist": ["nobody"]})
    with _redis({"shield:role_binding:bankco": cfg}):
        res = resolve_identity(_request("bankco", {"groups": ["all-employees"]}))
    assert res.user_role == ""
