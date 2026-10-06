"""The prompt check (task 1 of docs/specs/agent-hooks-prompt-check.md):
`hook_policies.check_prompt` and the profile keys that turn it on.

The custom policy guard is the real one, run through the real tenant
pipeline; only its per-policy model call is faked. That is what proves the
policy list reaches the guard: run without the per-request config, the guard
sees no policies and passes silently (core/tenant_pipeline.py).
"""
import asyncio
import hashlib

import pytest

from core.runtime_policy import hook_policies as hp
from core.runtime_policy.model import validate_profile
from guardrails.input.custom_policy import CustomPolicyInputGuardrail

SECRET_WORD = "zebracorn" + "falcon77"        # a prompt token a reason must not echo


def _policy(pid, name, action="block", fmt=None, enabled=True, stage="input"):
    p = {"policy_id": pid, "name": name, "description": name, "prompt": f"{name} policy text",
         "action": action, "stage": stage, "enabled": enabled, "confidence_threshold": 0.8,
         "priority": 100}
    if fmt:
        p["format"] = fmt
    return p


ENCRYPT = _policy("pol-encrypt", "No file encryption")
PRICING = _policy("pol-pricing", "Pricing data", action="warn")
OTHER = _policy("pol-chat", "Chat app only rule")


def _tenant(*policies, mode=None, extra=None):
    cfg = {"input_guardrails": {"custom_policy_input": {
        "enabled": True, "action": "pass", "settings": {"policies": list(policies)}},
        **(extra or {})}}
    if mode:
        cfg["policy_mode"] = mode
    return cfg


def _settings(**kw):
    return hp.Settings(**{"before_prompt": True, **kw})


@pytest.fixture
def model(monkeypatch):
    """The per-policy model call: a policy is violated when the last word of
    its name is in the prompt. Records which policies were asked."""
    asked = []

    async def fake(self, text, policy, context):
        asked.append(policy["policy_id"])
        hit = policy["name"].split()[-1].lower() in text.lower()
        return {"passed": not hit, "action": policy["action"] if hit else "pass",
                "confidence": 0.95, "suppressed": False, "error": None,
                "message": f"Custom input policy '{policy['name']}': matched",
                "details": {"policy_id": policy["policy_id"], "policy_name": policy["name"],
                            "violation_type": "x",
                            "reasoning": f"the request asks for this ({SECRET_WORD})",
                            "confidence": 0.95, "threshold": 0.8}}

    monkeypatch.setattr(CustomPolicyInputGuardrail, "_evaluate_policy_with_llm", fake)
    monkeypatch.setattr(hp, "_prompt_fail_closed", lambda tenant: False)
    return asked


def _check(prompt, tenant_config, **kw):
    return asyncio.run(hp.check_prompt("t1", prompt, tenant_config, _settings(**kw)))


# ── decisions ────────────────────────────────────────────────────────────


def test_a_block_policy_refuses_the_prompt(model):
    d = _check("please do file encryption on a.txt", _tenant(ENCRYPT))
    assert d.action == hp.BLOCK and d.policies == ["No file encryption"]
    assert d.reason.startswith("No file encryption: ") and d.guards == ["custom_policy_input"]
    assert model == ["pol-encrypt"]                 # the policy really reached the guard


def test_a_clean_prompt_passes(model):
    d = _check("explain how TLS works", _tenant(ENCRYPT))
    assert d.action == hp.ALLOW and not d.unjudged and d.policies == []


def test_warn_lets_it_through_and_names_the_policy(model):
    d = _check("show the pricing data", _tenant(ENCRYPT, PRICING))
    assert (d.action, d.policies) == (hp.WARN, ["Pricing data"])


def test_redact_is_a_block_because_a_prompt_cannot_be_rewritten(model):
    pol = _policy("pol-pii", "No personal data", action="redact")
    d = _check("here is personal data", _tenant(pol))
    assert d.action == hp.BLOCK
    assert d.reason == "No personal data: remove the sensitive data and send it again"


def test_the_reason_never_echoes_the_prompt(model):
    d = _check(f"file encryption for {SECRET_WORD}", _tenant(ENCRYPT))
    assert SECRET_WORD not in d.reason and "[value]" in d.reason
    assert SECRET_WORD not in repr(d.event_fields())


# ── which policies and guards run ────────────────────────────────────────


def test_prompt_policy_ids_limit_the_policies_asked(model):
    d = _check("file encryption", _tenant(ENCRYPT, OTHER), prompt_policy_ids=["pol-chat"])
    assert d.action == hp.ALLOW and model == ["pol-chat"]


def test_disabled_and_output_policies_are_not_asked(model):
    off = _policy("pol-off", "Off encryption", enabled=False)
    out = _policy("pol-out", "Out encryption", stage="output")
    _check("file encryption", _tenant(off, out, ENCRYPT))
    assert model == ["pol-encrypt"]


def test_no_prompt_policy_means_no_model_call(model):
    d = _check("file encryption", _tenant())
    assert (d.action, d.reason, model) == (hp.ALLOW, "no prompt policy", [])
    d = _check("file encryption", _tenant(ENCRYPT), prompt_policy_ids=["pol-gone"])
    assert d.action == hp.ALLOW and model == []


def test_only_custom_policies_by_default_every_guard_with_star():
    tenant = _tenant(ENCRYPT, extra={"pii_detection": {"enabled": True, "action": "block"},
                                     "prompt_injection": {"enabled": False}})
    assert list(hp.prompt_guards(tenant["input_guardrails"], _settings())) == ["custom_policy_input"]
    every = hp.prompt_guards(tenant["input_guardrails"], _settings(prompt_guards=["*"]))
    assert sorted(every) == ["custom_policy_input", "pii_detection"]     # disabled stays off


def test_an_oversize_prompt_keeps_only_sigma_policies():
    sigma = _policy("pol-sigma", "Sigma rule", fmt="sigma")
    cut = hp.prompt_guards(_tenant(ENCRYPT, sigma)["input_guardrails"], _settings(),
                           sigma_only=True)
    assert [p["policy_id"] for p in cut["custom_policy_input"]["settings"]["policies"]] == ["pol-sigma"]


def test_an_oversize_prompt_is_unjudged_and_follows_the_fail_setting(model, monkeypatch):
    big = "file encryption " + "x" * 2000
    d = _check(big, _tenant(ENCRYPT), max_output_chars=1000)
    assert (d.action, d.unjudged, model) == (hp.ALLOW, True, [])     # no LLM policy run
    monkeypatch.setattr(hp, "_prompt_fail_closed", lambda tenant: True)
    d = _check(big, _tenant(ENCRYPT), max_output_chars=1000)
    assert d.action == hp.BLOCK and "too long to check" in d.reason


# ── failures and modes ───────────────────────────────────────────────────


def test_a_slow_check_follows_the_fail_setting(model, monkeypatch):
    async def slow(self, text, policy, context):
        await asyncio.sleep(5)

    monkeypatch.setattr(CustomPolicyInputGuardrail, "_evaluate_policy_with_llm", slow)
    d = _check("file encryption", _tenant(ENCRYPT), check_timeout_s=1)
    assert (d.action, d.unjudged) == (hp.ALLOW, True)
    monkeypatch.setattr(hp, "_prompt_fail_closed", lambda tenant: True)
    d = _check("file encryption", _tenant(ENCRYPT), check_timeout_s=1)
    assert d.action == hp.BLOCK and "could not run" in d.reason


def test_a_guard_that_crashes_is_unjudged_not_a_finding(model, monkeypatch):
    async def boom(self, text, context=None):
        raise RuntimeError("model backend down")

    monkeypatch.setattr(CustomPolicyInputGuardrail, "check", boom)
    d = _check("file encryption", _tenant(ENCRYPT))
    assert (d.action, d.unjudged, d.policies) == (hp.ALLOW, True, [])
    monkeypatch.setattr(hp, "_prompt_fail_closed", lambda tenant: True)
    assert _check("file encryption", _tenant(ENCRYPT)).action == hp.BLOCK


def test_monitor_mode_allows_and_records_what_enforce_would_do(model):
    d = _check("file encryption", _tenant(ENCRYPT, mode="monitor"))
    assert (d.action, d.monitor, d.would) == (hp.ALLOW, True, hp.BLOCK)
    assert d.event_fields()["would_decide"] == hp.BLOCK and d.policies == ["No file encryption"]


def test_off_and_empty_prompts_never_reach_the_model(model):
    assert _check("file encryption", _tenant(ENCRYPT), before_prompt=False).action == hp.ALLOW
    assert _check("   ", _tenant(ENCRYPT)).action == hp.ALLOW
    assert _check(None, _tenant(ENCRYPT)).action == hp.ALLOW
    assert model == []


def test_the_fingerprint_is_a_hash_and_a_length_only():
    fp = hp.prompt_fingerprint("encrypt a.txt")
    assert fp == {"prompt_sha256": hashlib.sha256(b"encrypt a.txt").hexdigest(), "prompt_len": 13}


# ── settings and the profile ─────────────────────────────────────────────


class _Profile:
    def __init__(self, tool_policies):
        self.raw = {"tool_policies": tool_policies}


def test_settings_turn_on_for_the_prompt_check_alone(monkeypatch):
    s = hp.settings_for(_Profile({"before_prompt": True}))
    assert s.before_prompt and not s.before_call and s.prompt_guards == ["custom_policy_input"]
    monkeypatch.setenv("SHIELD_HOOK_PROMPT_CHECK", "0")
    assert hp.settings_for(_Profile({"before_prompt": True})) is None
    s = hp.settings_for(_Profile({"before_prompt": True, "before_call": True}))
    assert s.before_call and not s.before_prompt                     # only the prompt check off


def test_the_profile_accepts_the_prompt_keys():
    p = validate_profile({"tool_policies": {"before_prompt": True, "prompt_guards": ["*"],
                                            "prompt_policy_ids": ["pol-encrypt", "pol-encrypt"]}})
    tp = p["tool_policies"]
    assert tp["before_prompt"] is True and tp["prompt_guards"] == ["*"]
    assert tp["prompt_policy_ids"] == ["pol-encrypt"]                 # de-duplicated
    again = validate_profile(p)
    assert again["tool_policies"] == tp                               # stored form validates again


def test_profiles_without_the_prompt_keys_are_stored_as_before():
    tp = validate_profile({"tool_policies": {"before_call": True}})["tool_policies"]
    assert not {"before_prompt", "prompt_guards", "prompt_policy_ids"} & set(tp)


@pytest.mark.parametrize("bad, needle", [
    ({"prompt_guards": ["Prompt Injection"]}, "input guard name"),
    ({"prompt_guards": ["g%d" % i for i in range(21)]}, "at most 20"),
    ({"prompt_policy_ids": ["bad id!"]}, "custom policy id"),
    ({"prompt_policy_ids": ["p%d" % i for i in range(51)]}, "at most 50"),
    ({"before_prompt": "yes"}, "before_prompt"),
])
def test_the_profile_rejects_bad_prompt_keys(bad, needle):
    with pytest.raises(Exception, match=needle):
        validate_profile({"tool_policies": bad})
