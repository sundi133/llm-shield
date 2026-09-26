"""Every Sigma rule Shield ships must provably work.

Rules live in config/sigma/*.yml. Each carries `votal.tests` with texts it must
match and texts it must not; they run here through the same engine as live
traffic (normalization, prefilter, single-pass evaluation). A rule that
cannot fire in Shield, has no tests, or misbehaves fails CI.

Secret-shaped samples are stored as templates ({{an:N}}, {{AN:N}}, {{d:N}},
{{rep:X:N}}) and expanded here, in memory only, so the pack file never holds a
real-format credential for secret scanners (or a leak) to trip on.
"""
import re
from pathlib import Path

import pytest

from core.sigma import evaluate_rules, load_rules, policy_event, compile_rule
from core.sigma_io import import_sigma, prepare_rule
from core.sigma_policy import rule_to_policy_data

PACK_DIR = Path(__file__).resolve().parent.parent / "config" / "sigma"
PACK_FILES = sorted(PACK_DIR.glob("*.yml"))
STAGE_OF = {"llm_input": "input", "llm_output": "output"}

# Everyday traffic no shipped rule may fire on (false-positive guard).
BENIGN = [
    "Please summarise the quarterly planning notes for the team meeting on Friday.",
    "What's the capital of Australia, and how many people live there?",
    "Write a short poem about autumn leaves falling in the park.",
    "Explain the difference between TCP and UDP for a beginner.",
    "Draft a polite email asking to reschedule our call to next Tuesday at 3pm.",
    "How do I reverse a list in Python without using slicing?",
    "Translate 'good morning, how are you?' into Spanish and French.",
    "Our order #4521 shipped on 2026-09-12; can you confirm the delivery window?",
    "Give me three tips for writing a clear system design document.",
    "The meeting notes mention the previous release and the team's guidelines.",
]


def _rules():
    out = []
    for f in PACK_FILES:
        for rule in load_rules(f.read_text()):
            out.append(pytest.param(rule, id=f"{f.stem}:{rule['title']}"))
    return out


RULES = _rules()


_TEMPLATE = re.compile(r"\{\{(AN|an|d|rep):([^}:]*)(?::(\d+))?\}\}")
_CHARSETS = {
    "AN": "A1B2C3D4E5F6G7H8J9K0LMNPQRSTUVWXYZ",
    "an": "a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ",
    "d": "4815162342",
}


def _expand(value):
    """Expand sample templates to real-format values (test time only)."""
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if not isinstance(value, str):
        return value

    def sub(m):
        kind, arg, count = m.group(1), m.group(2), m.group(3)
        if kind == "rep":
            return arg * int(count)
        n, chars = int(arg), _CHARSETS[kind]
        return (chars * (n // len(chars) + 1))[:n]
    return _TEMPLATE.sub(sub, value)


def _event(rule, sample):
    sample = _expand(sample)
    stage = STAGE_OF[rule["logsource"]["category"]]
    if isinstance(sample, str):
        return policy_event(sample, {}, stage)
    ctx = {k: v for k, v in sample.items() if k not in ("message", "stage")}
    return policy_event(sample.get("message", ""), ctx, sample.get("stage", stage))


def _matches(rule, sample) -> bool:
    outcome = evaluate_rules([prepare_rule(rule)], _event(rule, sample))[0]
    assert outcome.error is None, f"{rule['title']}: evaluation error {outcome.error}"
    return outcome.matched


def test_pack_exists_and_is_not_trivial():
    assert PACK_FILES, "no Sigma packs in config/sigma"
    assert len(RULES) >= 15


def test_titles_and_ids_are_unique():
    titles = [p.values[0]["title"] for p in RULES]
    ids = [p.values[0]["id"] for p in RULES]
    assert len(set(titles)) == len(titles), "duplicate rule titles"
    assert len(set(ids)) == len(ids), "duplicate rule ids"


@pytest.mark.parametrize("rule", RULES)
def test_rule_can_work_in_shield(rule):
    # Valid Sigma, only Shield fields, a stage Shield can resolve, a level.
    prepare_rule(rule)
    assert rule["logsource"]["category"] in STAGE_OF
    assert rule.get("level") in ("informational", "low", "medium", "high", "critical")
    rule_to_policy_data(rule)


@pytest.mark.parametrize("rule", RULES)
def test_rule_has_positive_and_negative_samples(rule):
    tests = (rule.get("votal") or {}).get("tests") or {}
    assert tests.get("match"), f"{rule['title']}: no should-match samples"
    assert tests.get("no_match"), f"{rule['title']}: no should-not-match samples"


@pytest.mark.parametrize("rule", RULES)
def test_rule_behaves_as_declared(rule):
    tests = rule["votal"]["tests"]
    for sample in tests["match"]:
        assert _matches(rule, sample), f"{rule['title']} should match: {sample!r}"
    for sample in tests["no_match"]:
        assert not _matches(rule, sample), f"{rule['title']} should NOT match: {sample!r}"


def test_no_rule_fires_on_benign_traffic():
    rules = [prepare_rule(p.values[0]) for p in RULES]
    for text in BENIGN:
        for stage in ("input", "output"):
            outcomes = evaluate_rules(rules, policy_event(text, {}, stage))
            fired = [r["title"] for r, o in zip(rules, outcomes) if o.matched]
            assert not fired, f"false positive on {text!r}: {fired}"


def test_prefilter_changes_no_verdict_on_the_pack():
    rules = [prepare_rule(p.values[0]) for p in RULES]
    samples = []
    for p in RULES:
        rule = p.values[0]
        for s in rule["votal"]["tests"]["match"] + rule["votal"]["tests"]["no_match"]:
            samples.append(_event(rule, s))
    samples += [policy_event(t, {}, "input") for t in BENIGN]
    for event in samples:
        with_pf = [o.matched for o in evaluate_rules(rules, event, use_prefilter=True)]
        without = [o.matched for o in evaluate_rules(rules, event, use_prefilter=False)]
        assert with_pf == without


def test_pack_imports_cleanly_through_the_real_import_path(monkeypatch):
    import storage.custom_policies as cp
    store = {"tenant_id": "t1"}
    monkeypatch.setattr(cp, "get_tenant", lambda tid: store)
    monkeypatch.setattr(cp, "set_tenant_policies", lambda tid, **kw: store.update(kw))
    for f in PACK_FILES:
        result = import_sigma("t1", f.read_text())
        assert result["errors"] == [], result["errors"]
        assert len(result["created"]) == len(load_rules(f.read_text()))
        assert all(p["format"] == "sigma" for p in result["created"])


def test_templates_expand_to_the_documented_shapes():
    assert _expand("sk_live_{{an:24}}") == "sk_live_" + _CHARSETS["an"][:24]
    assert len(_expand("ghp_{{an:36}}")) == len("ghp_") + 36
    assert _expand("{{rep:-:5}}BEGIN") == "-----BEGIN"
    assert re.fullmatch(r"AKIA[A-Z0-9]{16}", _expand("AKIA{{AN:16}}"))


def test_pack_files_hold_no_secret_shaped_literals():
    """The pack's own secret rules must find nothing in the raw files, or a
    push is blocked by secret scanning (and a real key could slip in)."""
    secret_rules = [prepare_rule(p.values[0]) for p in RULES
                    if "votal.secrets" in (p.values[0].get("tags") or [])]
    assert len(secret_rules) >= 8
    for f in PACK_FILES:
        outcomes = evaluate_rules(secret_rules, policy_event(f.read_text(), {}, "input"))
        leaked = [r["title"] for r, o in zip(secret_rules, outcomes) if o.matched]
        assert not leaked, f"{f.name} contains secret-shaped literals: {leaked}"


def test_every_rule_compiles_and_caches():
    for p in RULES:
        rule = prepare_rule(p.values[0])
        assert compile_rule(rule) is compile_rule(rule)
