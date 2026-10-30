"""Policy scopes, task 1: normalize, select, merge, validate, memo.

Pure functions only; the guard-path wiring is tested in
test_policy_scopes_guard_path.py (task 3). Spec: docs/specs/policy-scopes.md.

The property every merge test protects: no header value, real or spoofed, gets
below the tenant's global policy.
"""

import copy
import time

import pytest

from core import policy_scopes as ps
from core.policy_scopes import (
    INVALID, MISSING, REJECT_BINDING, REJECT_MISSING, RULE_GLOBAL, RULE_UNMATCHED,
    SCOPE_MARKER, merge_stage, normalize_header_values, normalize_value, resolve,
    validate_rule, validate_scopes,
)


def kw(keywords, action="block", **extra):
    return {"enabled": True, "action": action, "settings": {"keywords": list(keywords)}, **extra}


def tenant(scopes=None, input_guardrails=None, output_guardrails=None):
    cfg = {
        "tenant_id": "acme",
        "input_guardrails": input_guardrails if input_guardrails is not None
        else {"keyword_blocklist": kw(["ssn"])},
    }
    if output_guardrails is not None:
        cfg["output_guardrails"] = output_guardrails
    if scopes is not None:
        cfg["policy_scopes"] = scopes
    return cfg


def scopes(**over):
    base = {
        "enabled": True,
        "selectors": [{"header": "X-Org-Id"}],
        "missing": "global",
        "rules": [
            {"id": "team-a", "match": {"exact": ["team-a", "teama"]},
             "input_guardrails": {"keyword_blocklist": kw(["zebra"])}},
            {"id": "engineering", "match": {"glob": ["eng-*"]},
             "input_guardrails": {"keyword_blocklist": kw(["payroll"])}},
        ],
        "unmatched": {"input_guardrails": {"keyword_blocklist": kw(["internal draft"])}},
    }
    base.update(over)
    return base


def headers(**values):
    """A header accessor: headers(**{"X-Org-Id": "a"}) or a list for repeats."""
    lower = {k.lower(): (v if isinstance(v, list) else [v]) for k, v in values.items()}
    return lambda name: lower.get(name.lower(), [])


def keywords(resolution, stage="input_guardrails"):
    return resolution.config[stage]["keyword_blocklist"]["settings"]["keywords"]


@pytest.fixture(autouse=True)
def _fresh_memo(monkeypatch):
    ps._compiled.clear()
    monkeypatch.delenv(ps.DISABLE_ENV, raising=False)
    yield
    ps._compiled.clear()


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("team-a", "team-a"),
    ("  TEAM-A ", "team-a"),
    ("Eng.Payments:EU@corp/x", "eng.payments:eu@corp/x"),
    ("", MISSING),
    ("   ", MISSING),
    (None, MISSING),
    ("team a", INVALID),
    ("team-a, eng-search", INVALID),
    ("(missing)", INVALID),
    ("x" * 64, "x" * 64),
    ("x" * 65, INVALID),
    ("téam", INVALID),
])
def test_normalize_value(raw, expected):
    assert normalize_value(raw) == expected


def test_repeated_header_with_different_values_is_invalid():
    assert normalize_header_values(["team-a", "eng-search"]) == INVALID


def test_repeated_header_with_the_same_value_is_fine():
    assert normalize_header_values(["team-a", " TEAM-A "]) == "team-a"


def test_empty_occurrences_are_ignored():
    assert normalize_header_values(["", "team-a"]) == "team-a"
    assert normalize_header_values([]) == MISSING


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def test_exact_value_and_alias_select_the_rule():
    cfg = tenant(scopes())
    for value in ("team-a", "TeamA", "  TEAM-A "):
        r = resolve(cfg, headers(**{"X-Org-Id": value}))
        assert r.decision.rule == "team-a", value
        assert keywords(r) == ["ssn", "zebra"]


def test_glob_covers_values_never_configured():
    r = resolve(tenant(scopes()), headers(**{"X-Org-Id": "eng-brand-new"}))
    assert r.decision.rule == "engineering"
    assert keywords(r) == ["ssn", "payroll"]


def test_exact_beats_glob_even_when_the_glob_rule_comes_first():
    s = scopes(rules=[
        {"id": "everyone-eng", "match": {"glob": ["eng-*"]}, "input_guardrails": {}},
        {"id": "eng-core", "match": {"exact": ["eng-core"]}, "input_guardrails": {}},
    ])
    assert resolve(tenant(s), headers(**{"X-Org-Id": "eng-core"})).decision.rule == "eng-core"


def test_first_matching_glob_wins():
    s = scopes(rules=[
        {"id": "first", "match": {"glob": ["eng-*"]}, "input_guardrails": {}},
        {"id": "second", "match": {"glob": ["eng-pay*"]}, "input_guardrails": {}},
    ])
    assert resolve(tenant(s), headers(**{"X-Org-Id": "eng-payments"})).decision.rule == "first"


def test_unknown_value_gets_unmatched():
    r = resolve(tenant(scopes()), headers(**{"X-Org-Id": "sales-emea"}))
    assert r.decision.rule == RULE_UNMATCHED
    assert keywords(r) == ["ssn", "internal draft"]


def test_unknown_value_without_unmatched_gets_global():
    cfg = tenant(scopes(unmatched=None))
    r = resolve(cfg, headers(**{"X-Org-Id": "sales-emea"}))
    assert r.decision.rule == RULE_GLOBAL
    assert r.config is cfg


def test_missing_header_gets_global_not_unmatched():
    cfg = tenant(scopes())
    r = resolve(cfg, headers())
    assert (r.decision.rule, r.decision.value) == (RULE_GLOBAL, MISSING)
    assert r.config is cfg


def test_missing_header_rejected_when_configured():
    r = resolve(tenant(scopes(missing="reject")), headers())
    assert r.decision.outcome == REJECT_MISSING


@pytest.mark.parametrize("value", [["team-a", "eng-search"], "team-a, eng-search", "x" * 65])
def test_invalid_values_get_unmatched_never_a_rule(value):
    r = resolve(tenant(scopes()), headers(**{"X-Org-Id": value}))
    assert (r.decision.rule, r.decision.value) == (RULE_UNMATCHED, INVALID)


def test_reserved_values_are_not_matched_by_a_catch_all_glob():
    s = scopes(rules=[{"id": "all", "match": {"glob": ["*"]}, "input_guardrails": {}}])
    assert resolve(tenant(s), headers(**{"X-Org-Id": "bad value"})).decision.rule == RULE_UNMATCHED
    assert resolve(tenant(s), headers()).decision.rule == RULE_GLOBAL


def test_first_selector_present_wins_for_header_renames():
    s = scopes(selectors=[{"header": "X-Team-Id"}, {"header": "X-Org-Id"}])
    both = resolve(tenant(s), headers(**{"X-Team-Id": "eng-x", "X-Org-Id": "team-a"}))
    assert (both.decision.rule, both.decision.header) == ("engineering", "X-Team-Id")
    old = resolve(tenant(s), headers(**{"X-Org-Id": "team-a"}))
    assert (old.decision.rule, old.decision.header) == ("team-a", "X-Org-Id")


def test_credential_headers_are_never_selectors():
    s = scopes(selectors=[{"header": "Authorization"}, {"header": "X-Org-Id"}])
    r = resolve(tenant(s), headers(Authorization="Bearer team-a", **{"X-Org-Id": "eng-x"}))
    assert r.decision.header == "X-Org-Id"


# ---------------------------------------------------------------------------
# Key bindings
# ---------------------------------------------------------------------------

def test_bound_key_cannot_claim_another_team():
    s = scopes(key_bindings={"sk-acme-team": ["team-a"]})
    r = resolve(tenant(s), headers(**{"X-Org-Id": "eng-x"}), key_prefix="sk-acme-team")
    assert r.decision.outcome == REJECT_BINDING


def test_bound_key_may_claim_its_own_values_and_globs():
    s = scopes(key_bindings={"sk-acme-team": ["team-a", "eng-*"]})
    for value, rule in (("team-a", "team-a"), ("eng-x", "engineering")):
        r = resolve(tenant(s), headers(**{"X-Org-Id": value}), key_prefix="sk-acme-team")
        assert r.decision.rule == rule


def test_bound_key_with_one_value_defaults_to_it():
    s = scopes(missing="reject", key_bindings={"sk-acme-team": ["team-a"]})
    r = resolve(tenant(s), headers(), key_prefix="sk-acme-team")
    assert (r.decision.rule, r.decision.value) == ("team-a", "team-a")


def test_bound_key_with_several_values_follows_missing():
    s = scopes(missing="reject", key_bindings={"sk-acme-team": ["team-a", "eng-*"]})
    r = resolve(tenant(s), headers(), key_prefix="sk-acme-team")
    assert r.decision.outcome == REJECT_MISSING


def test_bound_key_sending_garbage_is_rejected():
    s = scopes(key_bindings={"sk-acme-team": ["team-a"]})
    r = resolve(tenant(s), headers(**{"X-Org-Id": "bad value"}), key_prefix="sk-acme-team")
    assert r.decision.outcome == REJECT_BINDING


def test_unbound_key_may_claim_any_value():
    s = scopes(key_bindings={"sk-acme-team": ["team-a"]})
    r = resolve(tenant(s), headers(**{"X-Org-Id": "eng-x"}), key_prefix="sk-other-key")
    assert r.decision.rule == "engineering"


# ---------------------------------------------------------------------------
# Merge: the floor
# ---------------------------------------------------------------------------

def test_global_block_holds_for_every_value():
    cfg = tenant(scopes())
    for value in ("team-a", "eng-x", "sales-emea", "bad value", "anything-i-want"):
        r = resolve(cfg, headers(**{"X-Org-Id": value}))
        g = r.config["input_guardrails"]["keyword_blocklist"]
        assert g["enabled"] and g["action"] == "block" and "ssn" in g["settings"]["keywords"]


def test_local_cannot_disable_a_global_guardrail():
    merged = merge_stage({"keyword_blocklist": kw(["ssn"])},
                         {"keyword_blocklist": {"enabled": False}})
    assert merged["keyword_blocklist"]["enabled"] is True


def test_local_cannot_disable_a_guardrail_global_does_not_name():
    # On the chat proxies (UNION mode) a disabled entry switches off a server
    # default the tenant never configured. That is a weakening; drop it.
    merged = merge_stage({"keyword_blocklist": kw(["ssn"])},
                         {"toxicity": {"enabled": False}})
    assert "toxicity" not in merged


@pytest.mark.parametrize("g_action,l_action,expected", [
    ("warn", "block", "block"),
    ("block", "warn", "block"),
    ("block", "pass", "block"),
    ("log", "warn", "warn"),
    ("warn", "redact", "redact"),
    ("block", "nonsense", "block"),
])
def test_stricter_action_wins(g_action, l_action, expected):
    merged = merge_stage({"toxicity": {"enabled": True, "action": g_action}},
                         {"toxicity": {"action": l_action}})
    assert merged["toxicity"]["action"] == expected


def test_local_may_enable_what_global_has_off():
    merged = merge_stage({"toxicity": {"enabled": False, "action": "warn"}},
                         {"toxicity": {"enabled": True, "action": "block",
                                       "settings": {"threshold": 0.5}}})
    assert merged["toxicity"] == {"enabled": True, "action": "block",
                                  "settings": {"threshold": 0.5}}


def test_local_only_guardrail_is_added():
    merged = merge_stage({"keyword_blocklist": kw(["ssn"])},
                         {"toxicity": {"enabled": True, "action": "block"}})
    assert merged["toxicity"]["action"] == "block"
    assert merged["keyword_blocklist"] == kw(["ssn"])


def test_tool_allowlist_is_never_taken_from_a_local_policy():
    global_stage = {"tool_allowlist": {"enabled": True, "settings": {"tools": ["a"]}}}
    merged = merge_stage(global_stage,
                         {"tool_allowlist": {"enabled": True, "settings": {"tools": ["a", "b"]}}})
    assert merged["tool_allowlist"] == global_stage["tool_allowlist"]


def test_local_stage_ignored_when_global_has_none():
    # A tenant stage replaces the server defaults on /guardrails/*. A one
    # guardrail local stage standing in for a missing global one would drop them.
    cfg = tenant(scopes(rules=[{"id": "team-a", "match": {"exact": ["team-a"]},
                                "output_guardrails": {"toxicity": {"enabled": True}}}]))
    r = resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    assert "output_guardrails" not in r.config


# ---------------------------------------------------------------------------
# Merge: settings
# ---------------------------------------------------------------------------

def test_denylists_are_unioned_without_duplicates():
    merged = merge_stage({"keyword_blocklist": kw(["ssn", "pin"])},
                         {"keyword_blocklist": kw(["pin", "zebra"])})
    assert merged["keyword_blocklist"]["settings"]["keywords"] == ["ssn", "pin", "zebra"]


def test_denylists_of_objects_are_unioned():
    g = {"regex_pattern": {"enabled": True, "settings": {"patterns": [{"pattern": "a"}]}}}
    l = {"regex_pattern": {"settings": {"patterns": [{"pattern": "a"}, {"pattern": "b"}]}}}
    assert merge_stage(g, l)["regex_pattern"]["settings"]["patterns"] == [
        {"pattern": "a"}, {"pattern": "b"}]


def test_allowlists_are_intersected():
    g = {"language_detection": {"enabled": True, "settings": {"allowed_languages": ["en", "fr"]}}}
    l = {"language_detection": {"settings": {"allowed_languages": ["en", "de"]}}}
    assert merge_stage(g, l)["language_detection"]["settings"]["allowed_languages"] == ["en"]


def test_allowlist_cannot_be_widened():
    g = {"language_detection": {"enabled": True, "settings": {"allowed_languages": ["en"]}}}
    l = {"language_detection": {"settings": {"allowed_languages": ["en", "fr"]}}}
    assert merge_stage(g, l)["language_detection"]["settings"]["allowed_languages"] == ["en"]


def test_empty_global_allowlist_means_unrestricted_so_local_narrows_it():
    g = {"topic_enforcement": {"enabled": True, "settings": {"allowed_topics": []}}}
    l = {"topic_enforcement": {"settings": {"allowed_topics": ["billing"]}}}
    assert merge_stage(g, l)["topic_enforcement"]["settings"]["allowed_topics"] == ["billing"]


def test_disjoint_allowlists_keep_global_rather_than_unrestricted():
    g = {"language_detection": {"enabled": True, "settings": {"allowed_languages": ["en"]}}}
    l = {"language_detection": {"settings": {"allowed_languages": ["fr"]}}}
    assert merge_stage(g, l)["language_detection"]["settings"]["allowed_languages"] == ["en"]


def test_scalars_are_locked_to_global():
    g = {"toxicity": {"enabled": True, "action": "block", "settings": {"threshold": 0.8}}}
    l = {"toxicity": {"settings": {"threshold": 0.99, "new_knob": True}}}
    assert merge_stage(g, l)["toxicity"]["settings"] == {"threshold": 0.8}


def test_delegable_guardrail_takes_local_settings():
    g = {"toxicity": {"enabled": True, "action": "block", "delegable": True,
                      "settings": {"threshold": 0.8, "slot": 1}}}
    l = {"toxicity": {"action": "pass", "settings": {"threshold": 0.6}}}
    merged = merge_stage(g, l)["toxicity"]
    assert merged["settings"] == {"threshold": 0.6, "slot": 1}
    assert merged["action"] == "block"      # delegable is settings only, never the action


# ---------------------------------------------------------------------------
# Merge: custom policies
# ---------------------------------------------------------------------------

def cp(policy_id, action="block", fmt="nl", enabled=True):
    return {"policy_id": policy_id, "action": action, "format": fmt, "enabled": enabled}


def custom(*policies):
    return {"custom_policy_input": {"enabled": True, "action": "pass",
                                    "settings": {"policies": list(policies)}}}


def policy_ids(stage):
    return [p["policy_id"] for p in stage["custom_policy_input"]["settings"]["policies"]]


def test_custom_policies_union_by_id():
    merged = merge_stage(custom(cp("g1")), custom(cp("t1")))
    assert policy_ids(merged) == ["g1", "t1"]


def test_shared_custom_policy_keeps_the_stricter_action():
    merged = merge_stage(custom(cp("g1", "warn")), custom(cp("g1", "block")))
    assert merged["custom_policy_input"]["settings"]["policies"][0]["action"] == "block"
    merged = merge_stage(custom(cp("g1", "block")), custom(cp("g1", "pass")))
    assert merged["custom_policy_input"]["settings"]["policies"][0]["action"] == "block"


def test_custom_policy_cap_keeps_every_global_policy(monkeypatch):
    monkeypatch.setenv("SHIELD_MAX_POLICIES_PER_STAGE", "10")
    g = custom(*[cp(f"g{i}") for i in range(9)])
    l = custom(cp("t1"), cp("t2"), cp("t3"))
    assert policy_ids(merge_stage(g, l)) == [f"g{i}" for i in range(9)] + ["t1"]


def test_sigma_policies_have_their_own_cap(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGMA_MAX_POLICIES_PER_STAGE", "1")
    g = custom(*[cp(f"g{i}") for i in range(10)])
    l = custom(cp("s1", fmt="sigma"), cp("s2", fmt="sigma"))
    assert policy_ids(merge_stage(g, l))[-1] == "s1"


def test_team_only_custom_policies_are_capped_too(monkeypatch):
    monkeypatch.setenv("SHIELD_MAX_POLICIES_PER_STAGE", "10")
    l = custom(*[cp(f"t{i}") for i in range(12)])
    merged = merge_stage({"keyword_blocklist": kw(["ssn"])}, l)
    assert len(policy_ids(merged)) == 10


# ---------------------------------------------------------------------------
# Resolve: memo, isolation, kill switch, failure
# ---------------------------------------------------------------------------

def test_cached_tenant_config_is_never_mutated():
    cfg = tenant(scopes())
    before = copy.deepcopy(cfg)
    resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    resolve(cfg, headers(**{"X-Org-Id": "sales-emea"}))
    assert cfg == before


def test_scoped_config_carries_the_marker_for_this_request():
    cfg = tenant(scopes())
    a = resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    b = resolve(cfg, headers(**{"X-Org-Id": "teama"}))
    assert a.config[SCOPE_MARKER] == {"rule": "team-a", "value": "team-a", "header": "X-Org-Id"}
    assert b.config[SCOPE_MARKER]["value"] == "teama"
    assert ps.is_scoped(a.config) and not ps.is_scoped(cfg)


def test_same_config_object_reuses_the_memo():
    cfg = tenant(scopes())
    resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    compiled = ps._compiled["acme"][0]
    effective = compiled.effective["team-a"]
    resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    assert ps._compiled["acme"] == [compiled]
    assert compiled.effective["team-a"] is effective
    assert compiled.value_memo["team-a"] == "team-a"


def test_new_config_object_recomputes_and_sees_global_edits():
    cfg = tenant(scopes())
    assert keywords(resolve(cfg, headers(**{"X-Org-Id": "team-a"}))) == ["ssn", "zebra"]
    reloaded = copy.deepcopy(cfg)
    reloaded["input_guardrails"]["keyword_blocklist"]["settings"]["keywords"].append("pin")
    assert keywords(resolve(reloaded, headers(**{"X-Org-Id": "team-a"}))) == ["ssn", "pin", "zebra"]


def test_memo_keeps_a_few_objects_per_tenant():
    for _ in range(10):
        resolve(tenant(scopes()), headers(**{"X-Org-Id": "team-a"}))
    assert len(ps._compiled["acme"]) == ps._PER_TENANT


def test_value_memo_is_bounded(monkeypatch):
    monkeypatch.setattr(ps, "MAX_MEMO_VALUES", 3)
    cfg = tenant(scopes())
    for i in range(10):
        resolve(cfg, headers(**{"X-Org-Id": f"eng-{i}"}))
    assert len(ps._compiled["acme"][0].value_memo) == 3
    assert resolve(cfg, headers(**{"X-Org-Id": "eng-9"})).decision.rule == "engineering"


def test_preview_mode_skips_the_memo():
    resolve(tenant(scopes()), headers(**{"X-Org-Id": "team-a"}), memo=False)
    assert ps._compiled == {}


def test_tenant_without_scopes_is_untouched():
    cfg = tenant()
    r = resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    assert r.config is cfg and r.decision is None


def test_disabled_scopes_are_untouched():
    cfg = tenant(scopes(enabled=False))
    r = resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    assert r.config is cfg and r.decision is None


def test_kill_switch(monkeypatch):
    monkeypatch.setenv(ps.DISABLE_ENV, "1")
    cfg = tenant(scopes())
    r = resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    assert r.config is cfg and r.decision is None


def test_any_failure_falls_back_to_global(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(ps, "_select", boom)
    cfg = tenant(scopes())
    r = resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    assert r.config is cfg
    assert r.decision.rule == RULE_GLOBAL and r.decision.degraded


def test_garbage_scope_config_never_raises():
    cfg = tenant({"enabled": True, "selectors": "nope", "rules": [1, None, {"id": 3}],
                  "key_bindings": {"x": "nope"}, "unmatched": []})
    r = resolve(cfg, headers(**{"X-Org-Id": "team-a"}))
    assert r.decision.rule == RULE_GLOBAL


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def rule(**over):
    base = {"id": "team-b", "match": {"exact": ["team-b"]},
            "input_guardrails": {"keyword_blocklist": kw(["zebra"])}}
    base.update(over)
    return base


def test_valid_config_has_no_errors():
    assert validate_scopes(scopes(), tenant()) == []


@pytest.mark.parametrize("local,needle", [
    ({"keyword_blocklist": {"enabled": False}}, "can't disable"),
    ({"keyword_blocklist": kw([], action="pass")}, "can't lower it to pass"),
    ({"keyword_blocklist": kw([], action="nope")}, "unknown action"),
    ({"tool_allowlist": {"enabled": True}}, "only be set in the global policy"),
    ({"toxicity": {"enabled": False}}, "can't disable"),
])
def test_weakening_rules_are_rejected_with_a_reason(local, needle):
    errors = validate_rule(rule(input_guardrails=local), tenant())
    assert any(needle in e for e in errors), errors


def test_locked_scalar_is_rejected_unless_delegable():
    g = {"toxicity": {"enabled": True, "action": "block", "settings": {"threshold": 0.8}}}
    local = {"toxicity": {"settings": {"threshold": 0.9}}}
    errors = validate_rule(rule(input_guardrails=local), tenant(input_guardrails=g))
    assert any("delegable" in e for e in errors)
    g["toxicity"]["delegable"] = True
    assert validate_rule(rule(input_guardrails=local), tenant(input_guardrails=g)) == []


def test_allowlist_widening_and_disjoint_lists_are_rejected():
    g = {"language_detection": {"enabled": True, "settings": {"allowed_languages": ["en", "fr"]}}}
    wider = {"language_detection": {"settings": {"allowed_languages": ["en", "de"]}}}
    disjoint = {"language_detection": {"settings": {"allowed_languages": ["de"]}}}
    narrower = {"language_detection": {"settings": {"allowed_languages": ["en"]}}}
    t = tenant(input_guardrails=g)
    assert any("only narrow" in e for e in validate_rule(rule(input_guardrails=wider), t))
    assert any("shares nothing" in e for e in validate_rule(rule(input_guardrails=disjoint), t))
    assert validate_rule(rule(input_guardrails=narrower), t) == []


def test_custom_policy_rules_are_validated(monkeypatch):
    monkeypatch.setenv("SHIELD_MAX_POLICIES_PER_STAGE", "10")
    t = tenant(input_guardrails=custom(*[cp(f"g{i}") for i in range(9)]))
    lowered = custom(cp("g1", "pass"))
    too_many = custom(cp("t1"), cp("t2"))
    no_id = custom({"action": "block"})
    assert any("can't lower it" in e for e in validate_rule(rule(input_guardrails=lowered), t))
    assert any("the limit is 10" in e for e in validate_rule(rule(input_guardrails=too_many), t))
    assert any("needs a policy_id" in e for e in validate_rule(rule(input_guardrails=no_id), t))


def test_default_natural_language_cap_is_25(monkeypatch):
    monkeypatch.delenv("SHIELD_MAX_POLICIES_PER_STAGE", raising=False)
    g = custom(*[cp(f"g{i}") for i in range(10)])
    l = custom(*[cp(f"t{i}") for i in range(20)])
    assert len(policy_ids(merge_stage(g, l))) == 25
    t = tenant(input_guardrails=custom(*[cp(f"g{i}") for i in range(10)]))
    assert validate_rule(rule(input_guardrails=custom(*[cp(f"t{i}") for i in range(15)])), t) == []
    errors = validate_rule(rule(input_guardrails=custom(*[cp(f"t{i}") for i in range(16)])), t)
    assert any("26 enabled custom policies" in e and "the limit is 25" in e for e in errors)


def test_disabled_global_policies_leave_room_for_teams(monkeypatch):
    # The customer's case: 10 global policies, one switched off, cap 10.
    monkeypatch.setenv("SHIELD_MAX_POLICIES_PER_STAGE", "10")
    off = cp("g9")
    off["enabled"] = False
    g = custom(*[cp(f"g{i}") for i in range(9)], off)
    t = tenant(input_guardrails=g)
    assert validate_rule(rule(input_guardrails=custom(cp("t1"))), t) == []
    assert "t1" in policy_ids(merge_stage(g, custom(cp("t1"))))
    assert any("the limit is 10" in e for e in
               validate_rule(rule(input_guardrails=custom(cp("t1"), cp("t2"))), t))


def test_team_can_turn_on_a_policy_that_is_off_globally(monkeypatch):
    monkeypatch.delenv("SHIELD_MAX_POLICIES_PER_STAGE", raising=False)
    off = cp("weapons", "warn")
    off["enabled"] = False
    g = custom(cp("g1"), off)
    mine = cp("weapons", "block")              # same id, on, stricter action
    merged = merge_stage(g, custom(mine))
    pol = {p["policy_id"]: p for p in merged["custom_policy_input"]["settings"]["policies"]}
    assert pol["weapons"]["enabled"] is True and pol["weapons"]["action"] == "block"
    assert policy_ids(merged) == ["g1", "weapons"]          # not added twice
    # The global policy itself is untouched.
    assert off["enabled"] is False and g["custom_policy_input"]["settings"]["policies"][1]["enabled"] is False
    # A team can't turn a global policy off.
    team_off = cp("g1")
    team_off["enabled"] = False
    merged = merge_stage(g, custom(team_off))
    assert merged["custom_policy_input"]["settings"]["policies"][0]["enabled"] is not False


def test_turning_on_a_global_policy_counts_against_the_cap(monkeypatch):
    monkeypatch.setenv("SHIELD_MAX_POLICIES_PER_STAGE", "2")
    off = cp("g3")
    off["enabled"] = False
    g = custom(cp("g1"), cp("g2"), off)
    t = tenant(input_guardrails=g)
    assert any("3 enabled custom policies" in e for e in
               validate_rule(rule(input_guardrails=custom(cp("g3"))), t))
    merged = merge_stage(g, custom(cp("g3")))
    assert merged["custom_policy_input"]["settings"]["policies"][2]["enabled"] is False


def test_local_stage_needs_a_global_stage():
    errors = validate_rule(rule(output_guardrails={"toxicity": {"enabled": True}}), tenant())
    assert any("set a global output_guardrails first" in e for e in errors)


@pytest.mark.parametrize("over,needle", [
    ({"id": "Team B"}, "rule id"),
    ({"id": "global"}, "rule id"),
    ({"id": "unmatched"}, "rule id"),
    ({"match": {}}, "at least one exact value or glob"),
    ({"match": {"exact": ["bad value"]}}, "not a valid value"),
    ({"match": {"exact": [f"v{i}" for i in range(21)]}}, "at most 20"),
    ({"match": {"glob": ["x" * 65]}}, "1 to 64 chars"),
])
def test_bad_rule_shapes_are_rejected(over, needle):
    assert any(needle in e for e in validate_rule(rule(**over), tenant()))


def test_config_level_limits():
    t = tenant()
    many_globs = [{"id": f"r{i}", "match": {"glob": [f"a{i}-*", f"b{i}-*"]}} for i in range(51)]
    cases = [
        (scopes(selectors=[]), "name at least one header"),
        (scopes(selectors=[{"header": "X-API-Key"}]), "carries credentials"),
        (scopes(selectors=[{"header": "bad header"}]), "not a valid header name"),
        (scopes(selectors=[{"header": f"X-H{i}"} for i in range(6)]), "at most 5"),
        (scopes(missing="drop"), "'global' or 'reject'"),
        (scopes(rules=many_globs), "the limit is 100"),
        (scopes(rules=[rule(), rule()]), "duplicate rule id"),
        (scopes(rules=[rule(), rule(id="team-c")]), "already belongs to rule team-b"),
        (scopes(key_bindings={"sk-x": []}), "at least one value"),
        (scopes(key_bindings={"sk-x": ["bad value"]}), "not a valid value"),
        (scopes(unmatched={"input_guardrails": {"keyword_blocklist": {"enabled": False}}}),
         "can't disable"),
    ]
    for cfg, needle in cases:
        errors = validate_scopes(cfg, t)
        assert any(needle in e for e in errors), (needle, errors)


def test_oversized_config_is_rejected():
    big = scopes(rules=[rule(id=f"r{i}", match={"exact": [f"v{i}"]},
                             input_guardrails={"keyword_blocklist": kw(["x" * 2000])})
                        for i in range(150)])
    assert any("bytes, the limit" in e for e in validate_scopes(big, tenant()))


# ---------------------------------------------------------------------------
# Latency budget (spec section 2: under 50 us p99 for a known value)
# ---------------------------------------------------------------------------

def test_known_value_lookup_stays_within_budget():
    rules = [{"id": f"r{i}", "match": {"exact": [f"team-{i}-{j}" for j in range(20)]},
              "input_guardrails": {"keyword_blocklist": kw([f"k{i}"])}} for i in range(199)]
    rules.append({"id": "globs", "match": {"glob": [f"g{i}-*" for i in range(100)]}})
    cfg = tenant(scopes(rules=rules))
    h = headers(**{"X-Org-Id": "team-150-7"})
    resolve(cfg, h)
    samples = []
    for _ in range(2000):
        t = time.perf_counter()
        resolve(cfg, h)
        samples.append(time.perf_counter() - t)
    samples.sort()
    p99_us = samples[int(len(samples) * 0.99)] * 1e6
    # 50 us is the budget; CI runners are noisy, so assert 10x headroom and
    # leave the real number to the benchmark in the spec.
    assert p99_us < 500, f"p99 {p99_us:.1f} us"
