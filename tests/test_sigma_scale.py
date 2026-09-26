"""Sigma at scale: field compatibility, normalization, compiled + prefiltered
single-pass evaluation, stage budget, split caps, sample testing.

Spec: docs/specs/sigma-at-scale.md
"""
import asyncio
import copy
import random
import statistics
import time

import pytest

from core import sigma
from core.sigma import (
    SigmaRuleError,
    check_fields,
    compile_rule,
    evaluate_rules,
    load_rule,
    match_rule,
    policy_event,
    translate_fields,
)

SSN = {"title": "SSN", "logsource": {"category": "llm_input"},
       "detection": {"ssn": {"message|re": r"\b\d{3}-\d{2}-\d{4}\b"}, "condition": "ssn"},
       "level": "high"}


def _fake_tenant_store(monkeypatch):
    import storage.custom_policies as cp
    store = {"tenant_id": "t1"}
    monkeypatch.setattr(cp, "get_tenant", lambda tid: store)
    monkeypatch.setattr(cp, "set_tenant_policies", lambda tid, **kw: store.update(kw))
    return cp


def _sigma(rule, name="s"):
    return {"name": name, "description": "d", "action": "block", "format": "sigma", "sigma_rule": rule}


NL = {"name": "nl", "description": "d", "action": "block",
      "prompt": "Flag any disclosure of internal margins or supplier costs."}


# ── field compatibility and translation ────────────────────────────────────

def test_foreign_field_rejected_on_save(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    windows = {"title": "win", "detection": {"s": {"CommandLine|contains": "powershell"}, "condition": "s"}}
    with pytest.raises(ValueError, match="CommandLine"):
        cp.save_custom_policy("t1", _sigma(windows), stage="input")


def test_aliases_translate_to_shield_fields(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    rule = {"title": "alias", "detection": {
        "a": {"prompt|contains": "secret"}, "b": {"tool_args|contains": "rm -rf"},
        "c": {"Role": "contractor"}, "condition": "a or b or c"}}
    saved = cp.save_custom_policy("t1", _sigma(rule), stage="input")
    det = saved["sigma_rule"]["detection"]
    assert det["a"] == {"message|contains": "secret"}
    assert det["b"] == {"tool_input|contains": "rm -rf"}
    assert det["c"] == {"user_role": "contractor"}
    assert match_rule(saved["sigma_rule"], policy_event("a secret here", {}, "input")).matched


def test_field_map_on_import_and_invalid_target(monkeypatch):
    from core.sigma_io import import_sigma
    _fake_tenant_store(monkeypatch)
    rule = {"title": "mapped", "logsource": {"category": "llm_input"},
            "detection": {"s": {"CommandLine|contains": "curl"}, "condition": "s"}}
    assert import_sigma("t1", rule)["errors"], "unmapped foreign field must be an error"
    ok = import_sigma("t1", rule, field_map={"CommandLine": "message"})
    assert ok["errors"] == [] and ok["created"][0]["sigma_rule"]["detection"]["s"] == {"message|contains": "curl"}
    with pytest.raises(SigmaRuleError, match="not a Shield field"):
        translate_fields(rule, {"CommandLine": "EventID"})


def test_dry_run_reports_foreign_fields_without_saving(monkeypatch):
    from core.sigma_io import import_sigma
    cp = _fake_tenant_store(monkeypatch)
    rule = {"title": "win", "logsource": {"category": "llm_input"},
            "detection": {"s": {"Image|endswith": "\\powershell.exe"}, "condition": "s"}}
    result = import_sigma("t1", rule, dry_run=True)
    assert "Image" in result["errors"][0]["error"] and result["would_create"] == []
    assert cp.get_tenant_custom_policies("t1", enabled_only=False) == []


def test_translation_collision_is_an_error():
    rule = {"title": "c", "detection": {"s": {"prompt": "a", "message": "b"}, "condition": "s"}}
    with pytest.raises(SigmaRuleError, match="two fields map"):
        translate_fields(rule)


def test_keyword_rules_need_no_fields():
    check_fields({"title": "k", "detection": {"kw": ["password"], "condition": "kw"}})


@pytest.mark.asyncio
async def test_legacy_stored_rule_with_foreign_field_still_evaluates(monkeypatch):
    # Written before the check existed: it must keep evaluating (as a no-match), not error.
    import guardrails.input.custom_policy as mod
    from guardrails.input.custom_policy import CustomPolicyInputGuardrail

    async def boom(*a, **k):
        raise AssertionError("no LLM for Sigma")
    monkeypatch.setattr(mod, "async_llm_call", boom)
    legacy = {"policy_id": "old", "name": "old", "description": "d", "prompt": "", "action": "block",
              "stage": "input", "enabled": True, "format": "sigma",
              "sigma_rule": {"title": "old", "detection": {"s": {"CommandLine": "x"}, "condition": "s"}}}
    g = CustomPolicyInputGuardrail()
    g._temp_config = {"settings": {"policies": [legacy]}, "action": "pass"}
    res = await g.check("hello", {})
    assert res.passed is True and not res.details.get("errors")


# ── normalization ──────────────────────────────────────────────────────────

def test_zero_width_and_fullwidth_evasions_are_caught(monkeypatch):
    monkeypatch.delenv("SHIELD_SIGMA_NORMALIZE", raising=False)
    kw = load_rule({"title": "k", "detection": {"kw": ["password"], "condition": "kw"}})
    assert match_rule(kw, policy_event("my pass​word is x", {}, "input")).matched
    ssn = load_rule(SSN)
    assert match_rule(ssn, policy_event("ssn １２３-４５-６７８９", {}, "input")).matched


def test_normalization_escape_hatch(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGMA_NORMALIZE", "0")
    kw = load_rule({"title": "k", "detection": {"kw": ["password"], "condition": "kw"}})
    assert not match_rule(kw, policy_event("my pass​word is x", {}, "input")).matched


def test_tool_input_is_normalized_too(monkeypatch):
    monkeypatch.delenv("SHIELD_SIGMA_NORMALIZE", raising=False)
    rule = load_rule({"title": "t", "detection": {"s": {"tool_input|contains": "rm -rf"}, "condition": "s"}})
    ev = policy_event("x", {"tool_input": {"cmd": "rm​ -rf /"}}, "output")
    assert match_rule(rule, ev).matched


# ── compiled, prefiltered single-pass engine ───────────────────────────────

WORDS = ["password", "secret", "token", "ignore", "previous", "instructions", "admin", "root",
         "drop", "table", "ssn", "key", "Straße", "café", "ПАРОЛЬ", "ﬁle", "x", "y", "AKIA", "pass"]


def _rand_value(rng):
    w = rng.choice(WORDS)
    r = rng.random()
    if r < 0.15 and len(w) > 2:
        return w[:1] + "*" + w[2:]
    if r < 0.25 and len(w) > 2:
        return w[:1] + "?" + w[2:]
    return w


def _rand_search(rng):
    kind = rng.random()
    if kind < 0.3:
        return [_rand_value(rng) for _ in range(rng.randint(1, 3))]
    fields = {}
    for _ in range(rng.randint(1, 2)):
        choice = rng.random()
        if choice < 0.55:
            mods = rng.choice(["contains", "startswith", "endswith", "", "contains|all",
                               "contains|cased", "re"])
            key = "message" + (f"|{mods}" if mods else "")
            if mods == "re":
                val = rng.choice([r"p[a@]ss", r"t\w+n", r"\bkey\b", r"^ignore", r"(?i)admin"])
            elif "all" in mods:
                val = [_rand_value(rng), _rand_value(rng)]
            else:
                val = _rand_value(rng) if rng.random() < 0.7 else [_rand_value(rng), _rand_value(rng)]
            fields[key] = val
        elif choice < 0.8:
            fields["user_role"] = rng.choice(["admin", "contractor", "analyst"])
        else:
            fields["tool_name|exists"] = rng.random() < 0.5
    return fields if rng.random() < 0.8 else [fields, {"message|contains": _rand_value(rng)}]


def _rand_rule(rng, i):
    n = rng.randint(1, 3)
    det = {f"sel_{j}": _rand_search(rng) for j in range(n)}
    names = list(det)
    cond = rng.choice([
        " or ".join(names), " and ".join(names), f"1 of sel_*", f"all of sel_*",
        f"{names[0]} and not {names[-1]}" if n > 1 else f"not {names[0]}",
        f"({' or '.join(names)}) and not sel_0" if n > 1 else names[0],
    ])
    det["condition"] = cond
    return load_rule({"title": f"r{i}", "detection": det})


def _rand_text(rng):
    words = [rng.choice(WORDS + ["the", "and", "hello", "world", "please"]) for _ in range(rng.randint(0, 12))]
    words = [w.upper() if rng.random() < 0.2 else w for w in words]
    return " ".join(words)


def test_prefilter_never_changes_a_verdict_randomized():
    rng = random.Random(1234)
    rules = [_rand_rule(rng, i) for i in range(300)]
    texts = [_rand_text(rng) for _ in range(40)]
    skipped = 0
    for text in texts:
        ctx = {"user_role": rng.choice(["admin", "contractor", "analyst"]),
               "tool_name": rng.choice([None, "db.query"])}
        ev = policy_event(text, ctx, "input")
        on = evaluate_rules(rules, ev, use_prefilter=True)
        off = evaluate_rules(rules, ev, use_prefilter=False)
        assert [o.matched for o in on] == [o.matched for o in off], text
        assert not any(o.error for o in on + off)
        skipped += sum(o.skipped for o in on)
    assert skipped > 1000, f"prefilter is barely active ({skipped} skips)"


def test_prefilter_absent_library_falls_back_to_full_evaluation(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_aho(name, *a, **k):
        if name == "ahocorasick":
            raise ImportError("not installed")
        return real_import(name, *a, **k)

    rules = [load_rule({"title": "k", "detection": {"kw": ["password"], "condition": "kw"}}), load_rule(SSN)]
    ev = policy_event("hello world", {}, "input")
    monkeypatch.setattr(builtins, "__import__", no_aho)
    fallback = evaluate_rules(rules, ev)
    monkeypatch.setattr(builtins, "__import__", real_import)
    assert [o.matched for o in fallback] == [False, False]
    assert not any(o.skipped for o in fallback)


def test_compile_cache_is_content_addressed():
    rule = load_rule(SSN)
    assert compile_rule(rule) is compile_rule(copy.deepcopy(rule))
    edited = copy.deepcopy(rule)
    edited["detection"]["ssn"]["message|re"] = r"\b\d{9}\b"   # same policy, edited in place
    assert compile_rule(edited) is not compile_rule(rule)
    assert match_rule(edited, policy_event("id 123456789", {}, "input")).matched


def test_stage_budget_turns_overflow_into_errors_not_passes():
    slow = load_rule({"title": "slow", "detection": {"s": {"message|re": "(a+)+$"}, "condition": "s"}})
    later = [load_rule(SSN) for _ in range(3)]
    outcomes = evaluate_rules([slow] + later, policy_event("a" * 5000 + "!", {}, "input"),
                              rule_timeout_s=1.0, stage_budget_s=0.05, use_prefilter=False)
    assert outcomes[0].error and not outcomes[0].matched
    assert all(o.error and "budget" in o.error for o in outcomes[1:])


@pytest.mark.asyncio
async def test_all_sigma_policies_share_one_worker_thread_hop(monkeypatch):
    import guardrails.input.custom_policy as mod
    import guardrails.output.custom_policy as out
    from guardrails.input.custom_policy import CustomPolicyInputGuardrail

    async def boom(*a, **k):
        raise AssertionError("no LLM for Sigma")
    monkeypatch.setattr(mod, "async_llm_call", boom)
    hops = []
    real = asyncio.to_thread

    async def counting(fn, *a, **k):
        hops.append(fn)
        return await real(fn, *a, **k)
    monkeypatch.setattr(out.asyncio, "to_thread", counting)

    policies = [{"policy_id": f"p{i}", "name": f"p{i}", "description": "d", "prompt": "",
                 "action": "block", "stage": "input", "enabled": True, "format": "sigma",
                 "sigma_rule": load_rule({"title": f"k{i}", "detection": {"kw": [f"word{i}"], "condition": "kw"}})}
                for i in range(25)]
    g = CustomPolicyInputGuardrail()
    g._temp_config = {"settings": {"policies": policies}, "action": "pass"}
    res = await g.check("this has word7 in it", {})
    assert len(hops) == 1, f"expected one thread hop for 25 Sigma policies, got {len(hops)}"
    assert res.passed is False
    assert res.details["primary_violation"]["policy_id"] == "p7"


def test_hundred_rules_stay_fast():
    rng = random.Random(7)
    words = ["password", "api_key", "secret", "ssn", "passport", "iban", "salary", "margin",
             "supplier", "merger", "confidential", "internal only", "root access", "drop table"]
    rules = []
    for i in range(100):
        k = i % 4
        if k == 0:
            det = {"kw": rng.sample(words, 3), "condition": "kw"}
        elif k == 1:
            det = {"s": {"message|contains": rng.sample(words, 2)}, "condition": "s"}
        elif k == 2:
            det = {"s": {"message|re": r"\b\d{3}-\d{2}-%04d\b" % i}, "condition": "s"}
        else:
            det = {"a": {"message|contains": rng.choice(words)}, "b": {"user_role": "contractor"},
                   "condition": "a and b"}
        rules.append(load_rule({"title": f"r{i}", "detection": det}))
    ev = policy_event(("Please summarise the quarterly planning notes for the team. " * 35)[:2000],
                      {"user_role": "analyst"}, "input")
    for _ in range(5):
        evaluate_rules(rules, ev)
    samples = []
    for _ in range(40):
        t0 = time.perf_counter()
        evaluate_rules(rules, ev)
        samples.append((time.perf_counter() - t0) * 1000)
    median = statistics.median(samples)
    print(f"\n100 rules x 2 KB prompt: median {median:.3f} ms")
    assert median < 25, f"100 rules took {median:.1f} ms (budget: well under 1 ms typical)"


# ── caps ───────────────────────────────────────────────────────────────────

def test_nl_and_sigma_caps_are_separate(monkeypatch):
    cp = _fake_tenant_store(monkeypatch)
    monkeypatch.setenv("SHIELD_SIGMA_MAX_POLICIES_PER_STAGE", "3")
    for i in range(10):
        cp.save_custom_policy("t1", {**NL, "name": f"nl{i}"}, stage="input")
    with pytest.raises(ValueError, match="Maximum 10 policies"):
        cp.save_custom_policy("t1", {**NL, "name": "nl-over"}, stage="input")
    for i in range(3):   # NL cap full, Sigma still has room
        cp.save_custom_policy("t1", _sigma(load_rule(SSN), f"s{i}"), stage="input")
    with pytest.raises(ValueError, match="Sigma policies"):
        cp.save_custom_policy("t1", _sigma(load_rule(SSN), "s-over"), stage="input")
    stats = cp.get_policy_stats("t1")
    assert stats["remaining_input_slots"] == 0 and stats["remaining_sigma_input_slots"] == 0
    assert stats["max_sigma_per_stage"] == 3


def test_default_sigma_cap_is_100(monkeypatch):
    monkeypatch.delenv("SHIELD_SIGMA_MAX_POLICIES_PER_STAGE", raising=False)
    from storage.custom_policies import sigma_max_policies_per_stage
    assert sigma_max_policies_per_stage() == 100


# ── sample testing (both APIs) ─────────────────────────────────────────────

def test_validate_sigma_samples_run_through_the_live_engine():
    from core.sigma_io import validate_sigma
    v = validate_sigma(SSN, samples=["my ssn is 123-45-6789", "nothing here",
                                     {"message": "ssn １２３-４５-６７８９", "stage": "input"}])
    assert v["valid"]
    assert [r["matched"] for r in v["sample_results"]] == [True, False, True]


def test_validate_sigma_reports_foreign_fields():
    from core.sigma_io import validate_sigma
    v = validate_sigma({"title": "w", "detection": {"s": {"EventID": 4688}, "condition": "s"}})
    assert v["valid"] is False and "EventID" in v["errors"][0]["error"]


def test_validate_sigma_sample_limits():
    from core.sigma_io import MAX_SAMPLE_CHARS, validate_sigma
    v = validate_sigma(SSN, samples=["x" * (MAX_SAMPLE_CHARS + 1), 42])
    assert all(r.get("error") for r in v["sample_results"])


@pytest.fixture(params=["data_plane", "portal"])
def api(request, monkeypatch):
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    _fake_tenant_store(monkeypatch)
    app = FastAPI()
    if request.param == "data_plane":
        import api.routes_custom_policies as routes
        monkeypatch.setattr(routes, "get_tenant_from_request", lambda r: "t1")
        monkeypatch.setattr(routes, "log_admin_action", lambda **kw: None)
        base = "/v1/tenant/me/custom-policies"
    else:
        import api.routes_tenant_self as routes
        monkeypatch.setattr(routes, "_require_tenant", lambda r: "t1")
        monkeypatch.setattr(routes, "_actor", lambda r, t: f"tenant:{t}")
        monkeypatch.setattr(routes, "log_admin_action", lambda **kw: None)
        base = "/v1/tenant/me/policies/custom"
    app.include_router(routes.router)
    return TestClient(app), base


def test_api_validate_with_samples(api):
    client, base = api
    r = client.post(f"{base}/validate-sigma", json={"sigma": SSN, "samples": ["ssn 123-45-6789", "hi"]})
    assert r.status_code == 200, r.text
    assert [s["matched"] for s in r.json()["validation"]["sample_results"]] == [True, False]


def test_api_import_field_map(api):
    client, base = api
    rule = {"title": "cmd", "logsource": {"category": "llm_input"},
            "detection": {"s": {"CommandLine|contains": "curl"}, "condition": "s"}}
    r = client.post(f"{base}/import/sigma", json={"sigma": rule, "field_map": {"CommandLine": "message"}})
    assert r.status_code == 200 and len(r.json()["created"]) == 1


def test_api_create_rejects_foreign_field(api):
    client, base = api
    rule = {"title": "w", "detection": {"s": {"CommandLine|contains": "x"}, "condition": "s"}}
    path = f"{base}/" if base.endswith("custom-policies") else base
    r = client.post(path, json={"name": "w", "description": "d", "action": "block",
                                "stage": "input", "format": "sigma", "sigma_rule": rule})
    assert r.status_code == 400 and "CommandLine" in r.text
