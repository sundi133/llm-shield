"""A tenant-wide default data policy, so a tool nobody wrote a policy for is
still judged.

The gap was opened deliberately: spec-tool-output-action-authority removed the
fallback that handed the model "No specific data policies configured. Apply
reasonable security defaults". That was right - it was an instruction to invent
a rule, and it produced blocks nobody could explain - but it was also, in
effect, a global policy, and nothing replaced it. A tool added upstream was
callable and completely unjudged.

The hard requirement running through this file: **per-tool policies keep
behaving exactly as they do today**. The global layer is additive and off until
a tenant creates one. test_no_global_policy_is_byte_identical_to_today and
test_a_tool_policy_alone_is_unchanged are the guards on that.

Spec: docs/spec-global-tool-data-policy.md
"""
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_data_policies as rdp
import guardrails.agentic.tool.payload_risk as pr

TENANT = "acme"

# Real model shapes: DataSanitizationRule requires pattern_id/regex/
# replacement/description, RoleDataPolicy requires role/action.
TOOL_POLICY = {
    "tool_name": "customer_profile_get",
    "sanitization_rules": [{"pattern_id": "ssn", "regex": r"\d{3}-\d{2}-\d{4}",
                            "replacement": "[SSN]", "description": "US SSN"}],
    "role_policies": [{"role": "support", "action": "redact"}],
    "compliance_framework": "gdpr",
}
GLOBAL_POLICY = {
    "sanitization_rules": [{"pattern_id": "passport", "regex": r"P\d{7}",
                            "replacement": "[PP]", "description": "passport"}],
    "role_policies": [{"role": "support", "action": "redact"}],
    "compliance_framework": None,
    "enabled": True,
}


class _FakeRedis:
    def __init__(self, initial=None):
        self.store = {f"data_policies:{TENANT}": json.dumps(initial or {})} \
            if initial is not None else {}

    def get(self, k):
        return self.store.get(k)

    def set(self, k, v):
        self.store[k] = v


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.delenv("SHIELD_GLOBAL_DATA_POLICY", raising=False)


@pytest.fixture
def redis(monkeypatch):
    r = _FakeRedis({})
    monkeypatch.setattr(rdp, "_get_redis", lambda: r)
    monkeypatch.setattr(pr, "_get_redis", lambda: r, raising=False)
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: r)
    return r


@pytest.fixture
def client(redis):
    """Override the dependency by its ORIGINAL identity.

    An earlier version monkeypatched rdp.get_tenant_from_request first and then
    keyed dependency_overrides on the patched value - which overrides nothing,
    because the routes captured the original function at import time. The real
    dependency ran and every API test failed on a response shape that was
    actually an error.
    """
    app = FastAPI()
    app.dependency_overrides[rdp.get_tenant_from_request] = lambda: TENANT
    app.include_router(rdp.router)
    return TestClient(app)


def _seed(redis, **policies):
    redis.store[f"data_policies:{TENANT}"] = json.dumps(policies)


def _load(tool_name=""):
    return pr._load_data_policies(TENANT, tool_name)


def _sources(policies):
    return [p.get("policy_source") for p in policies]


# ── backward compatibility: today's behaviour must not move ──────────────


def test_no_global_policy_is_byte_identical_to_today(redis):
    """THE guard. Nothing changes for a tenant that never creates one."""
    _seed(redis, customer_profile_get=TOOL_POLICY)
    got = _load("customer_profile_get")
    assert len(got) == 1
    assert got[0]["tool_name"] == "customer_profile_get"
    assert got[0]["sanitization_rules"] == TOOL_POLICY["sanitization_rules"]


def test_a_tool_policy_alone_is_unchanged(redis):
    """Custom per-tool policies keep working exactly as they do today."""
    _seed(redis, customer_profile_get=TOOL_POLICY, statement_generate=TOOL_POLICY)
    got = _load("statement_generate")
    assert [p["tool_name"] for p in got] == ["statement_generate"]
    assert got[0]["role_policies"] == TOOL_POLICY["role_policies"]


def test_an_unpoliced_tool_is_still_unjudged_without_a_global(redis):
    _seed(redis, customer_profile_get=TOOL_POLICY)
    assert _load("some_new_tool") == []


# ── the gap this closes ──────────────────────────────────────────────────


def test_a_tool_with_no_policy_inherits_the_global(redis):
    """The headline. An upstream adds a tool; it is judged from the first call."""
    _seed(redis, __global__=GLOBAL_POLICY)
    got = _load("some_new_tool")
    assert len(got) == 1
    assert got[0]["policy_source"] == "global"
    assert got[0]["sanitization_rules"] == GLOBAL_POLICY["sanitization_rules"]


def test_a_tool_with_its_own_policy_gets_both(redis):
    _seed(redis, __global__=GLOBAL_POLICY, customer_profile_get=TOOL_POLICY)
    got = _load("customer_profile_get")
    assert _sources(got) == ["global", "tool"]


def test_the_global_cannot_be_cancelled_by_a_tool_policy(redis):
    """A floor that can be cancelled from below is not a floor."""
    _seed(redis, __global__=GLOBAL_POLICY, customer_profile_get=TOOL_POLICY)
    assert "global" in _sources(_load("customer_profile_get"))


def test_inherit_global_false_isolates_one_tool(redis):
    """The explicit opt-out. Without it, one tool that legitimately returns an
    email address forces the operator to weaken the rule for everyone."""
    isolated = {**TOOL_POLICY, "inherit_global": False}
    _seed(redis, __global__=GLOBAL_POLICY, customer_profile_get=isolated)
    assert _sources(_load("customer_profile_get")) == ["tool"]


def test_disabled_global_is_ignored_but_not_deleted(redis):
    _seed(redis, __global__={**GLOBAL_POLICY, "enabled": False})
    assert _load("some_new_tool") == []
    assert "__global__" in json.loads(redis.store[f"data_policies:{TENANT}"])


def test_the_escape_hatch_ignores_the_global(monkeypatch, redis):
    monkeypatch.setenv("SHIELD_GLOBAL_DATA_POLICY", "off")
    _seed(redis, __global__=GLOBAL_POLICY)
    assert _load("some_new_tool") == []


@pytest.mark.parametrize("value", ["0", "off", "false", "no", "OFF"])
def test_escape_hatch_spellings(monkeypatch, redis, value):
    monkeypatch.setenv("SHIELD_GLOBAL_DATA_POLICY", value)
    _seed(redis, __global__=GLOBAL_POLICY)
    assert _load("some_new_tool") == []


def test_the_global_is_never_returned_as_a_tool_in_the_unscoped_load(redis):
    """Loading every policy (no tool name) must not present the default as a
    tool of that name."""
    _seed(redis, __global__=GLOBAL_POLICY, customer_profile_get=TOOL_POLICY)
    names = [p["tool_name"] for p in _load("")]
    assert "__global__" not in names


# ── the reserved name ────────────────────────────────────────────────────


def test_a_tool_may_not_be_named_the_reserved_key(client):
    """tool_name is unvalidated on the per-tool route, so without this guard a
    caller could POST /tools/__global__/policy and silently become the
    tenant-wide default."""
    r = client.post("/v1/data-policies/tools/__global__/policy",
                    json={"tool_name": "__global__"})
    assert r.status_code == 422
    assert "reserved" in r.json()["detail"].lower()


def test_the_reserved_name_cannot_be_deleted_through_the_tool_route(client):
    assert client.delete(
        "/v1/data-policies/tools/__global__/policy").status_code == 422


def test_the_tool_listing_excludes_the_global(client, redis):
    _seed(redis, __global__=GLOBAL_POLICY, customer_profile_get=TOOL_POLICY)
    body = client.get("/v1/data-policies/tools").json()
    assert "__global__" not in body["policies"]
    assert body["count"] == 1


# ── the API round trip ───────────────────────────────────────────────────


def test_get_returns_an_empty_policy_when_none_is_set(client):
    body = client.get("/v1/data-policies/global/policy").json()
    assert body["exists"] is False
    assert body["policy"]["role_policies"] == []


def test_post_then_get_round_trips(client):
    assert client.post("/v1/data-policies/global/policy",
                       json=GLOBAL_POLICY).status_code == 200
    body = client.get("/v1/data-policies/global/policy").json()
    assert body["exists"] is True
    assert body["policy"]["sanitization_rules"][0]["replacement"] == "[PP]"


def test_post_is_a_replace_and_preserves_created_at(client):
    client.post("/v1/data-policies/global/policy", json=GLOBAL_POLICY)
    first = client.get("/v1/data-policies/global/policy").json()["policy"]
    client.post("/v1/data-policies/global/policy",
                json={**GLOBAL_POLICY, "compliance_framework": "pci_dss"})
    second = client.get("/v1/data-policies/global/policy").json()["policy"]
    assert second["compliance_framework"] == "pci_dss"
    assert second["created_at"] == first["created_at"]


def test_delete_removes_only_the_global(client, redis):
    _seed(redis, __global__=GLOBAL_POLICY, customer_profile_get=TOOL_POLICY)
    assert client.delete("/v1/data-policies/global/policy").status_code == 200
    stored = json.loads(redis.store[f"data_policies:{TENANT}"])
    assert "__global__" not in stored
    assert "customer_profile_get" in stored, "a tool policy was collateral damage"


def test_delete_when_none_is_set_is_404(client):
    assert client.delete("/v1/data-policies/global/policy").status_code == 404


def test_a_saved_global_is_enforced_immediately(client, redis):
    """Ties the API to the guard path: what the endpoint writes is what
    _load_data_policies reads."""
    client.post("/v1/data-policies/global/policy", json=GLOBAL_POLICY)
    assert _sources(_load("any_tool_at_all")) == ["global"]


# ── the latency contract ─────────────────────────────────────────────────


def test_the_global_costs_no_extra_store_round_trip(redis, monkeypatch):
    """Pins §2 of the spec. A separate Redis key would be cleaner in isolation
    and would add I/O to every guarded tool call; a metrics write on this same
    path cost ~1.6s p50 until it was moved off. If a refactor splits the key,
    this fails."""
    _seed(redis, __global__=GLOBAL_POLICY, customer_profile_get=TOOL_POLICY)
    reads = []
    real_get = redis.get
    monkeypatch.setattr(redis, "get", lambda k: (reads.append(k), real_get(k))[1])

    _load("customer_profile_get")
    assert len(reads) == 1, f"expected one store read, made {len(reads)}: {reads}"


# ── the portal is wired to the same endpoints ────────────────────────────


def _portal() -> str:
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent
            / "static" / "tenant.html").read_text()


def test_the_portal_calls_the_global_policy_endpoints():
    """A UI that renders but calls nothing is worse than no UI: it looks
    configured. Pin the wiring to the three endpoints the API exposes."""
    html = _portal()
    assert "'/v1/data-policies/global/policy'" in html
    for fn in ("loadGlobalDataPolicy", "saveGlobalDataPolicy",
               "deleteGlobalDataPolicy", "toggleGlobalDataPolicy"):
        assert f"function {fn}" in html, f"{fn} is referenced but not defined"


def test_the_portal_renders_the_card_even_with_no_tools():
    """loadDataPolicies returns early when no tools are registered. The default
    policy card must render before that, or a fresh tenant can never create
    one - the exact tenant that most needs it."""
    html = _portal()
    body = html.split("async function loadDataPolicies() {")[1][:400]
    assert "loadGlobalDataPolicy()" in body
    assert body.index("loadGlobalDataPolicy()") < body.index("No tools registered") \
        if "No tools registered" in body else True


def test_a_blocking_default_is_confirmed_before_saving():
    """Blast radius is every tool call on the tenant. A click should not be
    enough."""
    html = _portal()
    save = html.split("async function saveGlobalDataPolicy()")[1][:1200]
    assert "confirm(" in save
    assert "'block'" in save
