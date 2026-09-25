"""Sigma rules as a custom-policy format.

Covers the rule engine (core/sigma.py), policy storage, runtime enforcement by
the existing custom-policy guardrails (no LLM call for a Sigma policy), and
import / export (core/sigma_policy.py, core/sigma_translate.py, the API).
"""
import pytest

from core import sigma
from core.sigma import (
    SigmaEvalTimeout,
    SigmaRuleError,
    load_rule,
    load_rules,
    match_rule,
    policy_event,
)

SSN_RULE_YAML = """
title: SSN in prompt
id: 7d9d2d4e-1b7a-4f4b-9a3e-2d6c1f0a9b11
status: stable
description: Blocks prompts containing a US social security number
logsource:
  product: votal
  service: shield
  category: llm_input
detection:
  ssn:
    message|re: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
  condition: ssn
level: high
"""


def ev(message="", **ctx):
    return policy_event(message, ctx, "input")


# ── core.sigma: loading and validation ──────────────────────────────────────

def test_load_valid_rule():
    rule = load_rule(SSN_RULE_YAML)
    assert rule["title"] == "SSN in prompt"


def test_missing_title_rejected():
    with pytest.raises(SigmaRuleError):
        load_rule({"detection": {"a": {"message": "x"}, "condition": "a"}})


def test_unsupported_modifier_rejected_at_load():
    with pytest.raises(SigmaRuleError, match="unsupported"):
        load_rule({"title": "t", "detection": {
            "a": {"message|base64": "x"}, "condition": "a"}})


def test_unknown_identifier_in_condition_rejected():
    with pytest.raises(SigmaRuleError, match="unknown identifier"):
        load_rule({"title": "t", "detection": {
            "a": {"message": "x"}, "condition": "a and b"}})


def test_aggregation_and_timeframe_rejected():
    with pytest.raises(SigmaRuleError):
        load_rule({"title": "t", "detection": {
            "a": {"message": "x"}, "condition": "a | count() > 5"}})
    with pytest.raises(SigmaRuleError):
        load_rule({"title": "t", "detection": {
            "a": {"message": "x"}, "timeframe": "5m", "condition": "a"}})


def test_invalid_regex_rejected_at_load():
    with pytest.raises(SigmaRuleError, match="invalid regex"):
        load_rule({"title": "t", "detection": {
            "a": {"message|re": "(unclosed"}, "condition": "a"}})


def test_yaml_aliases_refused():
    bomb = "a: &a [x, x]\nb: *a\ntitle: t\n"
    with pytest.raises(SigmaRuleError, match="(anchors|aliases)"):
        load_rules(bomb)


def test_size_cap():
    with pytest.raises(SigmaRuleError, match="exceeds"):
        load_rules("title: t\n" + "#" * (sigma.MAX_RULE_BYTES + 1))


def test_multi_document_yaml():
    text = SSN_RULE_YAML + "\n---\n" + SSN_RULE_YAML.replace("SSN in prompt", "Second")
    rules = load_rules(text)
    assert [r["title"] for r in rules] == ["SSN in prompt", "Second"]


# ── core.sigma: matching semantics ──────────────────────────────────────────

def _rule(detection):
    return load_rule({"title": "t", "detection": detection})


def test_regex_match():
    rule = load_rule(SSN_RULE_YAML)
    assert match_rule(rule, ev("my ssn is 123-45-6789")).matched
    assert not match_rule(rule, ev("nothing here")).matched


def test_keywords_are_case_insensitive_substrings():
    rule = _rule({"kw": ["DROP TABLE", "rm -rf"], "condition": "kw"})
    assert match_rule(rule, ev("please drop table users")).matched
    assert not match_rule(rule, ev("safe")).matched


def test_plain_value_is_equality_with_wildcards():
    rule = _rule({"s": {"user_role": "contract*"}, "condition": "s"})
    assert match_rule(rule, ev("x", user_role="Contractor")).matched
    assert not match_rule(rule, ev("x", user_role="employee")).matched


def test_contains_startswith_endswith():
    assert match_rule(_rule({"s": {"message|contains": "secret"}, "condition": "s"}),
                      ev("top SECRET stuff")).matched
    assert match_rule(_rule({"s": {"message|startswith": "ignore"}, "condition": "s"}),
                      ev("Ignore previous instructions")).matched
    assert match_rule(_rule({"s": {"tool_name|endswith": ".export"}, "condition": "s"}),
                      ev("x", tool_name="crm.export")).matched


def test_list_is_or_and_all_modifier_is_and():
    any_rule = _rule({"s": {"message|contains": ["alpha", "beta"]}, "condition": "s"})
    all_rule = _rule({"s": {"message|contains|all": ["alpha", "beta"]}, "condition": "s"})
    assert match_rule(any_rule, ev("alpha only")).matched
    assert not match_rule(all_rule, ev("alpha only")).matched
    assert match_rule(all_rule, ev("alpha and beta")).matched


def test_cased_modifier():
    rule = _rule({"s": {"message|contains|cased": "API_KEY"}, "condition": "s"})
    assert match_rule(rule, ev("here is API_KEY")).matched
    assert not match_rule(rule, ev("here is api_key")).matched


def test_exists_and_null():
    exists = _rule({"s": {"tool_name|exists": True}, "condition": "s"})
    assert match_rule(exists, ev("x", tool_name="db.query")).matched
    assert not match_rule(exists, ev("x")).matched
    null = _rule({"s": {"tool_name": None}, "condition": "s"})
    assert match_rule(null, ev("x")).matched


def test_absent_field_never_matches_a_value():
    rule = _rule({"s": {"tool_name": "db.query"}, "condition": "s"})
    assert not match_rule(rule, ev("x")).matched


def test_condition_boolean_logic_and_quantifiers():
    det = {
        "sel_pii": {"message|contains": "ssn"},
        "sel_card": {"message|contains": "card"},
        "filter_admin": {"user_role": "admin"},
        "condition": "1 of sel_* and not filter_admin",
    }
    rule = _rule(det)
    assert match_rule(rule, ev("my card", user_role="analyst")).matched
    assert not match_rule(rule, ev("my card", user_role="admin")).matched
    all_rule = _rule({**det, "condition": "all of sel_*"})
    assert not match_rule(all_rule, ev("card only")).matched
    assert match_rule(all_rule, ev("ssn and card")).matched
    them = _rule({"a": {"message|contains": "x"}, "b": {"message|contains": "y"},
                  "condition": "1 of them"})
    assert match_rule(them, ev("y")).matched
    paren = _rule({"a": {"message|contains": "a"}, "b": {"message|contains": "b"},
                   "c": {"message|contains": "c"}, "condition": "a and (b or c)"})
    assert match_rule(paren, ev("a c")).matched
    assert not match_rule(paren, ev("a only")).matched


def test_list_of_maps_is_or():
    rule = _rule({"s": [{"tool_name": "a"}, {"tool_name": "b"}], "condition": "s"})
    assert match_rule(rule, ev("x", tool_name="b")).matched


def test_escaped_wildcard_is_literal():
    rule = _rule({"s": {"message": "cost\\*"}, "condition": "s"})
    assert match_rule(rule, ev("cost*")).matched
    assert not match_rule(rule, ev("costly")).matched


def test_matched_selections_reported():
    rule = _rule({"a": {"message|contains": "x"}, "b": {"message|contains": "zz"},
                  "condition": "a or b"})
    assert match_rule(rule, ev("x")).selections == ["a"]


def test_timeout_bounds_catastrophic_regex():
    # Unbounded, this pattern runs for well over 5 s on this input; the budget
    # must stop it almost immediately.
    import time
    rule = _rule({"s": {"message|re": "(a+)+$"}, "condition": "s"})
    start = time.monotonic()
    with pytest.raises(SigmaEvalTimeout):
        match_rule(rule, ev("a" * 5000 + "!"), timeout_s=0.05)
    assert time.monotonic() - start < 1.0


# ── storage ─────────────────────────────────────────────────────────────────

NL_POLICY = {
    "name": "No pricing", "description": "Block internal pricing",
    "prompt": "Flag any disclosure of internal margins or supplier costs.",
    "action": "block",
}


def _fake_tenant_store(monkeypatch):
    import storage.custom_policies as cp
    store = {"tenant_id": "t1"}
    monkeypatch.setattr(cp, "get_tenant", lambda tid: store)
    monkeypatch.setattr(cp, "set_tenant_policies", lambda tid, **kw: store.update(kw))
    return cp


def test_save_sigma_policy(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", {
        "name": "SSN", "description": "d", "action": "block",
        "format": "sigma", "sigma_rule": SSN_RULE_YAML,
    }, stage="input")
    assert saved["format"] == "sigma"
    assert saved["sigma_rule"]["title"] == "SSN in prompt"  # normalized to a dict
    assert saved["prompt"] == ""


def test_save_nl_policy_unchanged_shape(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", dict(NL_POLICY), stage="input")
    assert saved["format"] == "natural_language"
    assert "sigma_rule" not in saved
    assert saved["prompt"] == NL_POLICY["prompt"]


def test_save_sigma_requires_valid_rule(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    with pytest.raises(ValueError):
        cp.save_custom_policy("t1", {"name": "x", "description": "d", "action": "block",
                                     "format": "sigma", "sigma_rule": "title: no detection"},
                              stage="input")
    with pytest.raises(ValueError, match="sigma_rule"):
        cp.save_custom_policy("t1", {"name": "x", "description": "d", "action": "block",
                                     "format": "sigma"}, stage="input")


def test_unknown_format_rejected(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    with pytest.raises(ValueError, match="format"):
        cp.save_custom_policy("t1", {**NL_POLICY, "format": "rego"}, stage="input")


def test_update_switches_nl_to_sigma_and_back(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", dict(NL_POLICY), stage="input")
    pid = saved["policy_id"]
    to_sigma = cp.update_custom_policy("t1", pid, {"format": "sigma", "sigma_rule": SSN_RULE_YAML})
    assert to_sigma["format"] == "sigma" and to_sigma["sigma_rule"]["title"] == "SSN in prompt"
    back = cp.update_custom_policy("t1", pid, {"format": "natural_language"})
    assert back["format"] == "natural_language" and "sigma_rule" not in back


def test_update_rejects_bad_rule_without_mutating(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", dict(NL_POLICY), stage="input")
    with pytest.raises(ValueError):
        cp.update_custom_policy("t1", saved["policy_id"],
                                {"format": "sigma", "sigma_rule": {"title": "bad"}})
    assert cp.get_custom_policy("t1", saved["policy_id"])["format"] == "natural_language"


# ── runtime enforcement (existing guardrails) ───────────────────────────────

def _sigma_policy(action="block", rule=SSN_RULE_YAML, pid="s1", stage="input"):
    return {"policy_id": pid, "name": "SSN guard", "description": "no SSNs",
            "prompt": "", "action": action, "stage": stage, "enabled": True,
            "format": "sigma", "sigma_rule": load_rule(rule), "priority": 10}


def _no_llm(monkeypatch, mod):
    async def boom(*a, **k):
        raise AssertionError("a Sigma policy must not call the LLM")
    monkeypatch.setattr(mod, "async_llm_call", boom)


@pytest.mark.asyncio
async def test_input_guardrail_blocks_on_sigma_match_without_llm(monkeypatch):
    import guardrails.input.custom_policy as mod
    from guardrails.input.custom_policy import CustomPolicyInputGuardrail
    _no_llm(monkeypatch, mod)
    g = CustomPolicyInputGuardrail()
    g._temp_config = {"settings": {"policies": [_sigma_policy()]}, "action": "pass"}

    hit = await g.check("ssn 123-45-6789 please", {})
    assert hit.passed is False and hit.action == "block"
    assert hit.details["primary_violation"]["format"] == "sigma"

    miss = await g.check("hello there", {})
    assert miss.passed is True


@pytest.mark.asyncio
async def test_output_guardrail_sigma_policy(monkeypatch):
    import guardrails.output.custom_policy as mod
    from guardrails.output.custom_policy import CustomPolicyOutputGuardrail
    _no_llm(monkeypatch, mod)
    g = CustomPolicyOutputGuardrail()
    policy = _sigma_policy(action="warn", stage="output", rule={
        "title": "Leaks key", "detection": {"k": {"message|contains": "sk-live-"},
                                            "condition": "k"}})
    g._temp_config = {"settings": {"policies": [policy]}, "action": "pass"}
    res = await g.check("your key is sk-live-abc", {})
    assert res.passed is False and res.action == "warn"


@pytest.mark.asyncio
async def test_mixed_nl_and_sigma_policies(monkeypatch):
    import guardrails.input.custom_policy as mod
    from guardrails.input.custom_policy import CustomPolicyInputGuardrail
    calls = []

    async def fake(messages, **kwargs):
        calls.append(1)
        return {"choices": [{"message": {"content": "false,0.9,none,ok"}}]}

    monkeypatch.setattr(mod, "async_llm_call", fake)
    g = CustomPolicyInputGuardrail()
    nl = {**NL_POLICY, "policy_id": "n1", "stage": "input", "enabled": True}
    g._temp_config = {"settings": {"policies": [nl, _sigma_policy()]}, "action": "pass"}
    res = await g.check("ssn 123-45-6789", {})
    assert res.passed is False and res.action == "block"   # Sigma blocked
    assert len(calls) == 1                                  # only the NL policy used the LLM


@pytest.mark.asyncio
async def test_sigma_context_fields(monkeypatch):
    import guardrails.input.custom_policy as mod
    from guardrails.input.custom_policy import CustomPolicyInputGuardrail
    _no_llm(monkeypatch, mod)
    policy = _sigma_policy(rule={"title": "contractors no export", "detection": {
        "role": {"user_role": "contractor"}, "exp": {"message|contains": "export"},
        "condition": "role and exp"}})
    g = CustomPolicyInputGuardrail()
    g._temp_config = {"settings": {"policies": [policy]}, "action": "pass"}
    assert (await g.check("export all rows", {"user_role": "contractor"})).passed is False
    assert (await g.check("export all rows", {"user_role": "admin"})).passed is True


@pytest.mark.asyncio
async def test_sigma_timeout_is_an_eval_error_honoring_fail_open(monkeypatch):
    import guardrails.input.custom_policy as mod
    from guardrails.input.custom_policy import CustomPolicyInputGuardrail
    _no_llm(monkeypatch, mod)
    monkeypatch.setenv("SHIELD_SIGMA_EVAL_TIMEOUT_MS", "1")
    policy = _sigma_policy(rule={"title": "redos", "detection": {
        "s": {"message|re": "(a+)+$"}, "condition": "s"}})
    g = CustomPolicyInputGuardrail()
    g._temp_config = {"settings": {"policies": [policy]}, "action": "pass"}
    text = "a" * 5000 + "!"

    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_FAIL_OPEN", "1")
    res = await g.check(text, {})
    assert res.passed is True and res.details.get("errors")

    monkeypatch.setenv("SHIELD_CUSTOM_POLICY_FAIL_OPEN", "0")
    res = await g.check(text, {})
    assert res.passed is False and res.action == "block"


# ── conversion: import / export ─────────────────────────────────────────────

def test_rule_to_policy_stage_and_action_precedence():
    from core.sigma_policy import rule_to_policy_data
    rule = load_rule(SSN_RULE_YAML)  # llm_input + level high
    data, stage = rule_to_policy_data(rule)
    assert stage == "input" and data["action"] == "block" and data["format"] == "sigma"
    data, stage = rule_to_policy_data(rule, stage="output", action="warn")
    assert stage == "output" and data["action"] == "warn"


def test_rule_without_stage_needs_one():
    from core.sigma_policy import SigmaImportError, rule_to_policy_data
    rule = load_rule({"title": "t", "detection": {"a": {"message": "x"}, "condition": "a"}})
    with pytest.raises(SigmaImportError):
        rule_to_policy_data(rule)


def test_sigma_policy_roundtrip():
    from core.sigma_policy import rule_to_policy_data, sigma_policy_to_rule
    policy = {**_sigma_policy(action="warn"), "stage": "input"}
    rule = sigma_policy_to_rule(policy)
    assert rule["votal"]["source_format"] == "sigma"
    data, stage = rule_to_policy_data(load_rule(sigma.dump_rule(rule)))
    assert data["format"] == "sigma" and data["action"] == "warn" and stage == "input"
    assert "votal" not in data["sigma_rule"]
    assert data["sigma_rule"]["detection"] == policy["sigma_rule"]["detection"]


def test_nl_policy_export_is_lossless_on_reimport():
    from core.sigma_policy import nl_policy_to_rule, rule_to_policy_data
    policy = {**NL_POLICY, "policy_id": "6f1c2b1e-9d0a-4a9e-8f3a-111111111111",
              "stage": "output", "confidence_threshold": 0.9, "multi_turn": True}
    rule = nl_policy_to_rule(policy, ["supplier cost"], [r"\bmargin\s+\d+%"])
    assert rule["status"] == "experimental"
    assert match_rule(rule, policy_event("our margin 62% is high", {}, "output")).matched
    data, stage = rule_to_policy_data(load_rule(sigma.dump_rule(rule)))
    assert data["format"] == "natural_language" and data["prompt"] == NL_POLICY["prompt"]
    assert stage == "output" and data["confidence_threshold"] == 0.9 and data["multi_turn"]


def test_nl_export_with_no_terms_fails():
    from core.sigma_policy import SigmaImportError, nl_policy_to_rule
    with pytest.raises(SigmaImportError):
        nl_policy_to_rule({**NL_POLICY, "policy_id": "x"}, [], [])


@pytest.mark.asyncio
async def test_translate_nl_policy_drops_bad_regex(monkeypatch):
    import core.sigma_translate as tr

    async def fake(messages, **kwargs):
        assert kwargs.get("response_format")  # structured output only
        return {"choices": [{"message": {"content":
            '{"keywords": ["supplier cost"], "patterns": ["(bad", "\\\\d{3}-\\\\d{4}"]}'}}]}

    monkeypatch.setattr(tr, "async_llm_call", fake)
    rule = await tr.translate_nl_policy({**NL_POLICY, "policy_id": "p", "stage": "input"})
    assert rule["detection"]["patterns"]["message|re|i"] == ["\\d{3}-\\d{4}"]


# ── API (data plane router) ─────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    import api.routes_custom_policies as routes

    _fake_tenant_store(monkeypatch)
    monkeypatch.setattr(routes, "get_tenant_from_request", lambda request: "t1")
    monkeypatch.setattr(routes, "log_admin_action", lambda **kw: None)
    app = FastAPI()
    app.include_router(routes.router)
    return TestClient(app)


BASE = "/v1/tenant/me/custom-policies"


def test_api_create_sigma_policy(client):
    r = client.post(f"{BASE}/", json={"name": "SSN", "description": "d", "action": "block",
                                      "stage": "input", "format": "sigma",
                                      "sigma_rule": SSN_RULE_YAML})
    assert r.status_code == 200, r.text
    assert r.json()["policy"]["format"] == "sigma"


def test_api_create_sigma_invalid_rule_is_400(client):
    r = client.post(f"{BASE}/", json={"name": "x", "description": "d", "action": "block",
                                      "format": "sigma", "sigma_rule": "title: t"})
    assert r.status_code == 400


def test_api_create_requires_definition_for_format(client):
    r = client.post(f"{BASE}/", json={"name": "x", "description": "d", "action": "block",
                                      "format": "sigma"})
    assert r.status_code == 422
    r = client.post(f"{BASE}/", json={"name": "x", "description": "d", "action": "block"})
    assert r.status_code == 422  # natural language still needs a prompt


def test_api_nl_create_unchanged(client):
    r = client.post(f"{BASE}/", json={**NL_POLICY, "stage": "input"})
    assert r.status_code == 200
    assert r.json()["policy"]["format"] == "natural_language"


def test_api_import_partial_success_and_dry_run(client):
    bad = "title: broken\ndetection:\n  a:\n    message|base64: x\n  condition: a\n"
    text = SSN_RULE_YAML + "\n---\n" + bad
    dry = client.post(f"{BASE}/import/sigma", json={"sigma": text, "dry_run": True})
    assert dry.status_code == 200
    assert len(dry.json()["would_create"]) == 1 and dry.json()["created"] == []
    assert client.get(f"{BASE}/").json()["policies"] == []

    r = client.post(f"{BASE}/import/sigma", json={"sigma": text})
    body = r.json()
    assert len(body["created"]) == 1 and len(body["errors"]) == 1
    assert body["errors"][0]["title"] == "broken"


def test_api_import_unreadable_yaml_is_400(client):
    r = client.post(f"{BASE}/import/sigma", json={"sigma": "a: [unclosed"})
    assert r.status_code == 400


def test_api_export_sigma_and_nl(client, monkeypatch):
    import core.sigma_translate as tr

    async def fake(messages, **kwargs):
        return {"choices": [{"message": {"content":
            '{"keywords": ["supplier cost"], "patterns": []}'}}]}

    monkeypatch.setattr(tr, "async_llm_call", fake)
    client.post(f"{BASE}/import/sigma", json={"sigma": SSN_RULE_YAML})
    client.post(f"{BASE}/", json={**NL_POLICY, "stage": "input"})

    r = client.get(f"{BASE}/export/sigma")
    body = r.json()
    assert r.status_code == 200 and body["count"] == 2 and body["errors"] == []
    reloaded = load_rules(body["yaml"])
    assert {r["votal"]["source_format"] for r in reloaded} == {"sigma", "natural_language"}

    no_translate = client.get(f"{BASE}/export/sigma", params={"translate": "false"}).json()
    assert no_translate["count"] == 1 and len(no_translate["errors"]) == 1


def test_api_export_single_and_missing(client):
    pid = client.post(f"{BASE}/import/sigma", json={"sigma": SSN_RULE_YAML}).json()["created"][0]["policy_id"]
    r = client.get(f"{BASE}/{pid}/export/sigma")
    assert r.status_code == 200 and "title: SSN in prompt" in r.json()["yaml"]
    assert client.get(f"{BASE}/nope/export/sigma").status_code == 404


# ── natural-language regression guards ─────────────────────────────────────

@pytest.mark.asyncio
async def test_legacy_record_without_format_still_uses_llm(monkeypatch):
    # Records written before `format` existed must keep the LLM path.
    import guardrails.input.custom_policy as mod
    from guardrails.input.custom_policy import CustomPolicyInputGuardrail
    calls = []

    async def fake(messages, **kwargs):
        calls.append(messages)
        return {"choices": [{"message": {"content": "true,0.95,pricing,margin disclosed"}}]}

    monkeypatch.setattr(mod, "async_llm_call", fake)
    legacy = {**NL_POLICY, "policy_id": "legacy", "stage": "input", "enabled": True,
              "confidence_threshold": 0.8}
    assert "format" not in legacy
    g = CustomPolicyInputGuardrail()
    g._temp_config = {"settings": {"policies": [legacy]}, "action": "pass"}
    res = await g.check("our margin is 62%", {})
    assert len(calls) == 1 and res.passed is False and res.action == "block"
    assert NL_POLICY["prompt"] in calls[0][-1]["content"]


def test_nl_update_without_format_takes_old_path(monkeypatch):
    # The portal's NL edit payload has no `format`; nothing Sigma-related runs.
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", dict(NL_POLICY), stage="input")
    updated = cp.update_custom_policy("t1", saved["policy_id"], {
        "name": "No pricing", "description": "d2", "prompt": NL_POLICY["prompt"] + " More.",
        "action": "warn", "stage": "input", "confidence_threshold": 0.9, "priority": 5,
        "enabled": True})
    assert updated["format"] == "natural_language" and updated["action"] == "warn"
    assert "sigma_rule" not in updated and "sigma_source" not in updated


def test_sigma_rule_on_nl_policy_needs_explicit_format(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    saved = cp.save_custom_policy("t1", dict(NL_POLICY), stage="input")
    with pytest.raises(ValueError, match="set format to sigma"):
        cp.update_custom_policy("t1", saved["policy_id"], {"sigma_rule": SSN_RULE_YAML})


def test_sigma_source_kept_verbatim_and_cleared_on_switch(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    text = "# comment kept\n" + SSN_RULE_YAML
    saved = cp.save_custom_policy("t1", {"name": "s", "description": "d", "action": "block",
                                         "format": "sigma", "sigma_rule": text}, stage="input")
    assert saved["sigma_source"] == text
    back = cp.update_custom_policy("t1", saved["policy_id"],
                                   {"format": "natural_language", "prompt": NL_POLICY["prompt"]})
    assert "sigma_rule" not in back and "sigma_source" not in back


def test_object_rule_size_cap():
    big = {"title": "t", "detection": {"a": {"message|contains": ["x" * 1000] * 80},
                                       "condition": "a"}}
    with pytest.raises(SigmaRuleError, match="exceeds"):
        load_rule(big)


# ── portal API (routes_tenant_self) uses the same shared logic ─────────────

@pytest.fixture
def portal(monkeypatch):
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    import api.routes_tenant_self as routes

    _fake_tenant_store(monkeypatch)
    monkeypatch.setattr(routes, "_require_tenant", lambda request: "t1")
    monkeypatch.setattr(routes, "_actor", lambda request, tid: f"tenant:{tid}")
    monkeypatch.setattr(routes, "log_admin_action", lambda **kw: None)
    app = FastAPI()
    app.include_router(routes.router)
    return TestClient(app)


PORTAL = "/v1/tenant/me/policies/custom"


def test_portal_create_nl_with_exact_portal_payload(portal):
    r = portal.post(PORTAL, json={**NL_POLICY, "stage": "input",
                                  "confidence_threshold": 0.8, "priority": 100, "enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["policy"]["format"] == "natural_language"


def test_portal_sigma_create_validate_import_export(portal):
    ok = portal.post(f"{PORTAL}/validate-sigma", json={"sigma": SSN_RULE_YAML}).json()
    assert ok["validation"]["valid"] is True
    bad = portal.post(f"{PORTAL}/validate-sigma", json={"sigma": "title: x"}).json()
    assert bad["validation"]["valid"] is False

    r = portal.post(PORTAL, json={"name": "SSN", "description": "d", "action": "block",
                                  "stage": "input", "format": "sigma", "sigma_rule": SSN_RULE_YAML})
    assert r.status_code == 200 and r.json()["policy"]["sigma_source"] == SSN_RULE_YAML

    imp = portal.post(f"{PORTAL}/import/sigma", json={
        "sigma": "title: Key leak\ndetection:\n  k:\n    message|contains: sk-live-\n  condition: k\n",
        "stage": "output"}).json()
    assert [p["stage"] for p in imp["created"]] == ["output"]

    exp = portal.get(f"{PORTAL}/export/sigma", params={"translate": "false"}).json()
    assert exp["count"] == 2 and exp["errors"] == []
    pid = r.json()["policy"]["policy_id"]
    one = portal.get(f"{PORTAL}/{pid}/export/sigma").json()
    assert one["rule"]["title"] == "SSN in prompt"


def test_portal_nl_export_without_llm_is_reported_not_fatal(portal, monkeypatch):
    import core.sigma_translate as tr

    async def down(*a, **k):
        raise ConnectionError("All connection attempts failed")

    monkeypatch.setattr(tr, "async_llm_call", down)
    portal.post(PORTAL, json={**NL_POLICY, "stage": "input"})
    portal.post(PORTAL, json={"name": "SSN", "description": "d", "action": "block",
                              "stage": "input", "format": "sigma", "sigma_rule": SSN_RULE_YAML})
    exp = portal.get(f"{PORTAL}/export/sigma").json()
    assert exp["count"] == 1
    assert "translation failed" in exp["errors"][0]["error"]
