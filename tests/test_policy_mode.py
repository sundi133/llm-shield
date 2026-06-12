"""Unit tests for core.policy_mode — runnable offline (no server, no GPU).

    python -m pytest tests/test_policy_mode.py
    # or, with no pytest installed:
    python tests/test_policy_mode.py
"""

from core.policy_mode import (
    ENFORCE,
    MONITOR,
    MONITORED,
    resolve_mode,
    would_block,
    apply,
    apply_to_response,
)


def _results(blocking=False, warn=False):
    rs = [{"guardrail": "rbac_guard", "passed": True, "action": "pass"}]
    if warn:
        rs.append({"guardrail": "pii_detection", "passed": False, "action": "warn"})
    if blocking:
        rs.append({"guardrail": "toxicity", "passed": False, "action": "block"})
    return rs


def test_resolve_mode_defaults_to_enforce():
    assert resolve_mode(None) == ENFORCE
    assert resolve_mode({}) == ENFORCE
    assert resolve_mode({"policy_mode": "enforce"}) == ENFORCE
    # Unknown values fall back to the safe (blocking) default.
    assert resolve_mode({"policy_mode": "bogus"}) == ENFORCE
    assert resolve_mode({"policy_mode": "monitor"}) == MONITOR


def test_would_block():
    assert would_block({"passed": False, "action": "block"})
    assert would_block({"passed": False, "action": "pending_confirmation"})
    assert not would_block({"passed": True, "action": "block"})
    assert not would_block({"passed": False, "action": "warn"})


def test_enforce_returns_inputs_unchanged():
    # The core safety property: enforce mode must not alter the decision.
    rs = _results(blocking=True)
    d = apply(rs, allowed=False, action="block", mode=ENFORCE)
    assert d["allowed"] is False
    assert d["action"] == "block"
    assert d["mode"] == ENFORCE
    assert d["would_block"] == ["toxicity"]
    # results not mutated (no 'enforced' key added) in enforce mode
    assert all("enforced" not in r for r in rs)


def test_monitor_suppresses_block():
    rs = _results(blocking=True)
    d = apply(rs, allowed=False, action="block", mode=MONITOR)
    assert d["allowed"] is True                  # never blocks
    assert d["action"] == MONITORED
    assert d["would_block"] == ["toxicity"]
    # the would-be-blocking result is tagged as not enforced
    tox = next(r for r in rs if r["guardrail"] == "toxicity")
    assert tox["enforced"] is False


def test_monitor_with_no_block_keeps_action():
    rs = _results(blocking=False, warn=True)
    d = apply(rs, allowed=True, action="warn", mode=MONITOR)
    assert d["allowed"] is True
    assert d["action"] == "warn"                 # nothing would block → unchanged
    assert d["would_block"] == []


def test_monitor_does_not_suppress_administrative_block():
    # An operator kill (agent disabled / kill switch) enforces even in
    # monitor mode — dry-run applies to policy findings, not admin actions.
    rs = [
        {"guardrail": "rbac_guard", "passed": False, "action": "block",
         "details": {"agent_status": "disabled", "administrative": True}},
    ]
    d = apply(rs, allowed=False, action="block", mode=MONITOR)
    assert d["allowed"] is False
    assert d["action"] == "block"
    assert d["mode"] == MONITOR
    assert d["would_block"] == ["rbac_guard"]


def test_apply_to_response_enforce_unchanged():
    resp = {"safe": False, "action": "block", "guardrail_results": _results(blocking=True)}
    out = apply_to_response(resp, ENFORCE)
    assert out["safe"] is False
    assert out["action"] == "block"
    assert out["mode"] == ENFORCE
    assert out["would_block"] == ["toxicity"]


def test_apply_to_response_monitor():
    resp = {"safe": False, "action": "block", "guardrail_results": _results(blocking=True)}
    out = apply_to_response(resp, MONITOR)
    assert out["safe"] is True
    assert out["action"] == MONITORED
    assert out["mode"] == MONITOR
    assert out["would_block"] == ["toxicity"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
