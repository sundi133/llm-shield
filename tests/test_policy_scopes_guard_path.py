"""Policy scopes, task 3: the guard path picks the team policy from a header.

Spec: docs/specs/policy-scopes.md. Every guardrail here is keyword_blocklist,
which needs no model, so these are real end-to-end requests through the
middleware and the routes. The chat proxies would call an upstream model on a
pass, so for those the test records which config the input pipeline received
and stops there.
"""

import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ROOT = "psg-root-admin-key"
A_KEY = "sk-psg-tenant-a-0001"
PLAIN_KEY = "sk-psg-plain-0001"
A = {"X-API-Key": A_KEY}
BASE = "/v1/tenant/me/policy-scopes"


def kw(keywords, action="block"):
    return {"enabled": True, "action": action, "settings": {"keywords": list(keywords)}}


GLOBAL_IN = {"keyword_blocklist": kw(["ssn"])}
GLOBAL_OUT = {"keyword_blocklist": kw(["secret"])}
SCOPES = {
    "version": 1, "enabled": True,
    "selectors": [{"header": "X-Team-Id"}, {"header": "X-Org-Id"}],
    "missing": "global",
    "unmatched": {"input_guardrails": {"keyword_blocklist": kw(["internal draft"])}},
    "rules": [
        {"id": "team-a", "match": {"exact": ["team-a", "teama"]},
         "input_guardrails": {"keyword_blocklist": kw(["zebra"])},
         "output_guardrails": {"keyword_blocklist": kw(["zebra"])}},
        {"id": "engineering", "match": {"glob": ["eng-*"]},
         "input_guardrails": {"keyword_blocklist": kw(["payroll"])}},
    ],
    "key_bindings": {},
}


@pytest.fixture
def env(monkeypatch):
    import copy
    import core.middleware as mw
    import core.policy_scopes as ps
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: None)
    monkeypatch.setenv("SHIELD_ADMIN_KEY", ROOT)
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")
    for name in ("SHIELD_CONFIG_WRITE_SCOPE", "SHIELD_GUARD_REQUIRE_KEY", "REDIS_URL",
                 "UPSTASH_REDIS_REST_URL", "CONFIG_PATH", ps.DISABLE_ENV):
        monkeypatch.delenv(name, raising=False)
    ts._fallback_store.clear()
    ts._cache.clear()
    mw._tenant_cache.clear()
    ps._compiled.clear()
    ts.create_tenant("acme", {"name": "Acme", "input_guardrails": copy.deepcopy(GLOBAL_IN),
                              "output_guardrails": copy.deepcopy(GLOBAL_OUT),
                              "policy_scopes": copy.deepcopy(SCOPES)}, api_keys=[A_KEY])
    ts.create_tenant("plain", {"name": "Plain", "input_guardrails": copy.deepcopy(GLOBAL_IN)},
                     api_keys=[PLAIN_KEY])
    yield ts
    ts._fallback_store.clear()
    ts._cache.clear()
    mw._tenant_cache.clear()
    ps._compiled.clear()


@pytest.fixture
def client(env):
    import config.schema as cs
    original = cs.config
    cfg = original if original is not None else cs.load_config()
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app
        application = create_app()
    yield TestClient(application)
    cs.config = original


def reload_tenant_cache():
    """The middleware caches each key's tenant for 60 s; tests skip the wait."""
    import core.middleware as mw
    mw._tenant_cache.clear()


def check(client, message, key=A, **headers):
    r = client.post("/guardrails/input", headers={**key, **headers}, json={"message": message})
    assert r.status_code == 200, r.text
    return r


def action(client, message, **headers):
    return check(client, message, **headers).json()["action"]


# ── The matrix from the spec's worked example ────────────────────────────────

MESSAGES = ["hello", "my ssn is 123", "project zebra", "run payroll", "internal draft v2"]


@pytest.mark.parametrize("value,expected", [
    ("team-a", ["pass", "block", "block", "pass", "pass"]),
    ("TeamA", ["pass", "block", "block", "pass", "pass"]),
    ("  TEAM-A ", ["pass", "block", "block", "pass", "pass"]),
    ("eng-payments", ["pass", "block", "pass", "block", "pass"]),
    ("eng-brand-new", ["pass", "block", "pass", "block", "pass"]),
    ("sales-emea", ["pass", "block", "pass", "pass", "block"]),
])
def test_matrix(client, value, expected):
    got = [action(client, m, **{"X-Org-Id": value}) for m in MESSAGES]
    assert got == expected


def test_no_header_gets_global_only(client):
    assert [action(client, m) for m in MESSAGES] == ["pass", "block", "pass", "pass", "pass"]


def test_header_sent_twice_is_invalid_and_gets_unmatched(client):
    r = client.post("/guardrails/input",
                    headers=[("X-API-Key", A_KEY), ("X-Org-Id", "team-a"), ("X-Org-Id", "eng-x")],
                    json={"message": "internal draft v2"})
    assert r.json()["action"] == "block"
    assert r.json()["policy_scope"] == {"rule": "unmatched", "value": "(invalid)", "header": "X-Org-Id"}


def test_comma_joined_values_are_invalid(client):
    r = check(client, "internal draft v2", **{"X-Org-Id": "team-a, eng-search"})
    assert r.json()["policy_scope"]["value"] == "(invalid)" and r.json()["action"] == "block"


def test_spoofed_value_never_gets_below_global(client):
    for value in ("anything-i-want", "team-a", "eng-x", "(missing)", "x" * 200):
        assert action(client, "my ssn is 123", **{"X-Org-Id": value}) == "block", value


def test_first_selector_wins(client):
    r = check(client, "run payroll", **{"X-Team-Id": "eng-x", "X-Org-Id": "team-a"})
    assert r.json()["policy_scope"] == {"rule": "engineering", "value": "eng-x", "header": "X-Team-Id"}
    assert r.json()["action"] == "block"


# ── Response field, header and audit ─────────────────────────────────────────

def test_response_carries_policy_scope_and_header(client):
    r = check(client, "hello", **{"X-Org-Id": "TeamA"})
    assert r.json()["policy_scope"] == {"rule": "team-a", "value": "teama", "header": "X-Org-Id"}
    assert r.headers["X-Shield-Policy-Scope"] == "team-a"


def test_missing_header_is_reported_as_global(client):
    r = check(client, "hello")
    assert r.json()["policy_scope"] == {"rule": "global", "value": "(missing)", "header": None}
    assert r.headers["X-Shield-Policy-Scope"] == "global"


def test_tenant_without_scopes_is_unchanged(client):
    r = check(client, "project zebra", key={"X-API-Key": PLAIN_KEY}, **{"X-Org-Id": "team-a"})
    assert r.json()["action"] == "pass"
    assert "policy_scope" not in r.json()
    assert "X-Shield-Policy-Scope" not in r.headers


def test_audit_records_the_scope(client):
    import api.routes_classify as rc
    seen = []

    async def capture(entry):
        seen.append(entry)
    with patch.object(rc.audit_logger, "log", capture):
        check(client, "hello", **{"X-Org-Id": "team-a"})
    assert seen[-1]["metadata"]["policy_scope"]["rule"] == "team-a"


# ── Output and file stages ───────────────────────────────────────────────────

def test_output_stage_uses_the_team_policy(client):
    def out(**h):
        r = client.post("/guardrails/output", headers={**A, **h}, json={"output": "the zebra file"})
        assert r.status_code == 200, r.text
        return r.json()
    team = out(**{"X-Org-Id": "team-a"})
    assert team["action"] == "block" and team["policy_scope"]["rule"] == "team-a"
    assert out(**{"X-Org-Id": "eng-x"})["action"] != "block"


def test_output_global_holds(client):
    r = client.post("/guardrails/output", headers={**A, "X-Org-Id": "eng-x"},
                    json={"output": "here is the secret"})
    assert r.json()["action"] == "block"


def test_file_stage_uses_the_team_policy(client):
    def upload(**h):
        r = client.post("/guardrails/file", headers={**A, **h},
                        files={"file": ("notes.txt", b"project zebra launch", "text/plain")})
        assert r.status_code == 200, r.text
        return r.json()
    assert upload(**{"X-Org-Id": "team-a"})["action"] == "block"
    assert upload(**{"X-Org-Id": "team-b"})["action"] == "pass"
    assert upload(**{"X-Org-Id": "team-a"})["policy_scope"]["rule"] == "team-a"


# ── Chat proxies ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("module,path,body", [
    ("api.routes_openai_compat", "/v1/chat/completions",
     {"model": "m", "messages": [{"role": "user", "content": "project zebra"}]}),
    ("api.routes_gateway", "/v1/shield/chat/completions",
     {"model": "m", "messages": [{"role": "user", "content": "project zebra"}]}),
    ("api.routes_agent_chat", "/v1/shield/chat/agent",
     {"messages": [{"role": "user", "content": "project zebra"}]}),
])
def test_proxies_get_the_team_config(client, module, path, body):
    import importlib
    mod = importlib.import_module(module)
    real = mod.run_proxy_input_pipeline
    received = []

    # Record the config, then run the real pipeline: team-a's rule blocks
    # "zebra", so the proxy refuses before it would call an upstream model.
    async def recorder(content, context, tenant_config):
        received.append(tenant_config)
        return await real(content, context, tenant_config)
    with patch.object(mod, "run_proxy_input_pipeline", recorder):
        r = client.post(path, headers={**A, "X-Org-Id": "team-a"}, json=body)
    assert received, f"{path} never reached the input pipeline ({r.status_code} {r.text[:200]})"
    keywords = received[-1]["input_guardrails"]["keyword_blocklist"]["settings"]["keywords"]
    assert keywords == ["ssn", "zebra"]
    assert r.headers.get("X-Shield-Policy-Scope") == "team-a"


# ── Refusals ─────────────────────────────────────────────────────────────────

def test_missing_header_refused_when_required(client, env):
    env.update_tenant("acme", {"policy_scopes": {**SCOPES, "missing": "reject"}})
    reload_tenant_cache()
    r = client.post("/guardrails/input", headers=A, json={"message": "hello"})
    assert r.status_code == 403
    assert r.json()["error"] == "policy_scope_required"
    assert r.json()["headers"] == ["X-Team-Id", "X-Org-Id"]
    assert check(client, "hello", **{"X-Org-Id": "team-a"}).status_code == 200


def test_bound_key_cannot_claim_another_team(client, env):
    team_key = "sk-psgteamA1-" + uuid.uuid4().hex[:8]
    env.add_api_key("acme", team_key)
    env.update_tenant("acme", {"policy_scopes": {**SCOPES, "key_bindings": {team_key[:12]: ["team-a"]}}})
    reload_tenant_cache()
    h = {"X-API-Key": team_key}
    r = client.post("/guardrails/input", headers={**h, "X-Org-Id": "eng-x"}, json={"message": "hi"})
    assert r.status_code == 403 and r.json()["error"] == "policy_scope_not_allowed"
    ok = client.post("/guardrails/input", headers=h, json={"message": "project zebra"})
    assert ok.json()["action"] == "block" and ok.json()["policy_scope"]["rule"] == "team-a"


def test_refusal_does_not_spend_quota(client, env):
    env.update_tenant("acme", {"policy_scopes": {**SCOPES, "missing": "reject"}})
    reload_tenant_cache()
    import core.middleware as mw
    with patch.object(mw, "check_and_increment") as quota:
        client.post("/guardrails/input", headers=A, json={"message": "hello"})
    quota.assert_not_called()


# ── Isolation from everything that isn't a guarded I/O route ─────────────────

def test_config_routes_see_the_unscoped_config(client):
    r = client.get("/v1/tenant/me/policies", headers={**A, "X-Org-Id": "team-a"})
    assert r.status_code == 200
    assert r.json()["input_guardrails"]["keyword_blocklist"]["settings"]["keywords"] == ["ssn"]


def test_saving_global_policy_with_a_team_header_saves_global_only(client, env):
    r = client.put("/v1/tenant/me/policies", headers={**A, "X-Org-Id": "team-a"},
                   json={"input_guardrails": {"keyword_blocklist": kw(["ssn", "pin"])}})
    assert r.status_code == 200
    stored = env.get_tenant("acme")
    assert stored["input_guardrails"]["keyword_blocklist"]["settings"]["keywords"] == ["ssn", "pin"]
    assert "_policy_scope" not in stored


def test_scoped_paths_are_a_subset_of_guarded_paths():
    from core.middleware import ShieldMiddleware as M
    for path in M._POLICY_SCOPE_PATHS:
        assert path in M._GUARDED_EXACT or any(path.startswith(p) for p in M._GUARDED_PREFIXES), path
    assert not any("tool" in p or "cap" in p for p in M._POLICY_SCOPE_PATHS)


# ── Kill switch and failure ──────────────────────────────────────────────────

def test_kill_switch_restores_global_live(client, monkeypatch):
    assert action(client, "project zebra", **{"X-Org-Id": "team-a"}) == "block"
    monkeypatch.setenv("SHIELD_DISABLE_POLICY_SCOPES", "1")
    r = check(client, "project zebra", **{"X-Org-Id": "team-a"})
    assert r.json()["action"] == "pass" and "policy_scope" not in r.json()
    assert action(client, "my ssn is 123", **{"X-Org-Id": "team-a"}) == "block"


def test_selection_failure_falls_back_to_global(client, monkeypatch):
    import core.policy_scopes as ps

    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(ps, "_select", boom)
    r = check(client, "project zebra", **{"X-Org-Id": "team-a"})
    assert r.json()["action"] == "pass"
    assert r.json()["policy_scope"]["rule"] == "global"
    assert action(client, "my ssn is 123", **{"X-Org-Id": "team-a"}) == "block"


def test_global_edit_reaches_every_team_after_cache_reload(client, env):
    assert action(client, "my pin", **{"X-Org-Id": "team-a"}) == "pass"
    env.set_tenant_policies("acme", input_guardrails={"keyword_blocklist": kw(["ssn", "pin"])})
    reload_tenant_cache()
    for value in ("team-a", "eng-x", "sales-emea"):
        assert action(client, "my pin", **{"X-Org-Id": value}) == "block", value


# ── Team header forwarded in LiteLLM's body (spec section 10, task 6) ────────

LITELLM = "/beta/litellm_basic_guardrail_api"
KEY_ID = "XTZSE4KWMU7RCEMNMVRQ"
TF_SCOPES = {
    **SCOPES,
    "selectors": [{"header": "x-tf-api-key-id"}],
    "rules": [{"id": "key-a", "match": {"exact": [KEY_ID.lower()]},
               "input_guardrails": {"keyword_blocklist": kw(["zebra"])}}],
    "unmatched": None,
}


@pytest.fixture
def tf(env):
    import copy
    env.update_tenant("acme", {"policy_scopes": copy.deepcopy(TF_SCOPES)})
    reload_tenant_cache()
    return env


def litellm(client, text, forwarded=None, key=A, **headers):
    body = {"input_type": "request", "texts": [text]}
    if forwarded is not None:
        body["request_headers"] = forwarded
    return client.post(LITELLM, headers={**key, **headers}, json=body)


def test_body_header_selects_the_team(client, tf):
    r = litellm(client, "project zebra", {"x-tf-api-key-id": KEY_ID})
    assert r.status_code == 200 and r.json()["action"] == "BLOCKED"
    assert r.headers["X-Shield-Policy-Scope"] == "key-a"
    other = litellm(client, "project zebra", {"x-tf-api-key-id": "SOMEOTHERKEY"})
    assert other.json()["action"] == "NONE"
    # The global policy still holds for every key id.
    assert litellm(client, "my ssn is 1", {"x-tf-api-key-id": KEY_ID}).json()["action"] == "BLOCKED"


def test_body_header_name_ignores_case(client, tf):
    r = litellm(client, "project zebra", {"X-TF-API-KEY-ID": KEY_ID})
    assert r.json()["action"] == "BLOCKED"


@pytest.mark.parametrize("forwarded", [
    {"x-tf-api-key-id": "[present]"},
    {"x-tf-api-key-id": ""},
    {"x-tf-api-key-id": 123},
    {"x-tf-api-key-id": [KEY_ID]},
    {"other": KEY_ID},
    "x-tf-api-key-id: " + KEY_ID,
    None,
])
def test_no_usable_body_value_is_a_missing_header(client, tf, forwarded):
    r = litellm(client, "project zebra", forwarded)
    assert r.status_code == 200 and r.json()["action"] == "NONE"
    assert r.headers["X-Shield-Policy-Scope"] == "global"


def test_no_usable_body_value_is_refused_when_required(client, tf):
    tf.update_tenant("acme", {"policy_scopes": {**TF_SCOPES, "missing": "reject"}})
    reload_tenant_cache()
    r = litellm(client, "hello", {"x-tf-api-key-id": "[present]"})
    assert r.status_code == 403 and r.json()["error"] == "policy_scope_required"
    assert litellm(client, "hello", {"x-tf-api-key-id": KEY_ID}).status_code == 200


def test_two_casings_with_different_values_are_invalid(client, tf):
    r = litellm(client, "project zebra", {"x-tf-api-key-id": KEY_ID, "X-TF-API-KEY-ID": "OTHER"})
    assert r.json()["action"] == "NONE"


def test_real_header_wins_over_the_body(client, tf):
    r = litellm(client, "project zebra", {"x-tf-api-key-id": KEY_ID}, **{"x-tf-api-key-id": "OTHER"})
    assert r.json()["action"] == "NONE"
    r = litellm(client, "project zebra", {"x-tf-api-key-id": "OTHER"}, **{"x-tf-api-key-id": KEY_ID})
    assert r.json()["action"] == "BLOCKED"


def test_real_header_still_works_on_the_litellm_route(client, tf):
    assert litellm(client, "project zebra", **{"x-tf-api-key-id": KEY_ID}).json()["action"] == "BLOCKED"


def test_body_only_read_on_the_litellm_route(client, tf):
    # /guardrails/input never looks in the body for a team header.
    r = client.post("/guardrails/input", headers=A,
                    json={"message": "project zebra", "request_headers": {"x-tf-api-key-id": KEY_ID}})
    assert r.json()["action"] == "pass"


def test_body_not_read_for_tenants_without_team_policies(client, env, monkeypatch):
    import core.middleware as mw
    calls = []
    real = mw._forwarded_headers

    async def spy(request):
        calls.append(request.url.path)
        return await real(request)
    monkeypatch.setattr(mw, "_forwarded_headers", spy)
    r = litellm(client, "my ssn is 1", {"x-tf-api-key-id": KEY_ID}, key={"X-API-Key": PLAIN_KEY})
    assert r.json()["action"] == "BLOCKED"
    assert calls == []
    # The scoped tenant does read it, so the spy is wired to the right place.
    env.update_tenant("acme", {"policy_scopes": TF_SCOPES})
    reload_tenant_cache()
    litellm(client, "hi", {"x-tf-api-key-id": KEY_ID})
    assert calls == [LITELLM]


def test_bound_key_cannot_claim_another_team_from_the_body(client, tf):
    team_key = "sk-psgtfkeyA-" + uuid.uuid4().hex[:8]
    tf.add_api_key("acme", team_key)
    tf.update_tenant("acme", {"policy_scopes": {
        **TF_SCOPES,
        "rules": TF_SCOPES["rules"] + [{"id": "key-b", "match": {"exact": ["otherkey"]}}],
        "key_bindings": {team_key[:12]: [KEY_ID.lower()]}}})   # locks list values
    reload_tenant_cache()
    h = {"X-API-Key": team_key}
    r = litellm(client, "hi", {"x-tf-api-key-id": "OTHERKEY"}, key=h)
    assert r.status_code == 403 and r.json()["error"] == "policy_scope_not_allowed"
    ok = litellm(client, "project zebra", {"x-tf-api-key-id": KEY_ID}, key=h)
    assert ok.status_code == 200, ok.text
    assert ok.json()["action"] == "BLOCKED"


def test_discovery_records_the_body_value(client, tf):
    from storage.policy_scopes_store import read_seen
    litellm(client, "hi", {"x-tf-api-key-id": KEY_ID})
    seen = {e["value"]: e for e in read_seen("acme")}
    assert KEY_ID.lower() in seen
    assert seen[KEY_ID.lower()]["header"] == "x-tf-api-key-id"


def test_body_headers_escape_hatch(client, tf, monkeypatch):
    monkeypatch.setenv("SHIELD_POLICY_SCOPE_BODY_HEADERS", "off")
    assert litellm(client, "project zebra", {"x-tf-api-key-id": KEY_ID}).json()["action"] == "NONE"
    # A real header is unaffected by the switch.
    assert litellm(client, "project zebra", **{"x-tf-api-key-id": KEY_ID}).json()["action"] == "BLOCKED"
    monkeypatch.setenv("SHIELD_POLICY_SCOPE_BODY_HEADERS", "on")
    assert litellm(client, "project zebra", {"x-tf-api-key-id": KEY_ID}).json()["action"] == "BLOCKED"
