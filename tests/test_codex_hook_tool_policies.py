"""Codex hooks and the shared command hook script (task 3 of
docs/specs/agent-hooks-tool-policies.md).

Part 1: POST /v1/shield/hooks/codex on the real app. Same decisions as Claude
Code; Codex's shapes: a redaction or a withheld result is a PostToolUse
`decision: "block"` whose reason becomes the result (verified against Codex
0.155.1 in task 0), and an `ask` is a deny (Codex runs the tool on `ask`).

Part 2: claude_code_hook.sh, run for real under sh and dash against a fake
Shield: `--target codex` posts to /codex; after a call Shield's answer is
passed through, and a failure lets the result through unless
ON_UNREACHABLE_RESULT=withhold. Before a call every failure still exits 2.
"""
import json
from types import SimpleNamespace

import pytest

from tests.test_claude_code_hook import (  # noqa: F401  (fixture: shield)
    CALL, DENY, SHELLS, _conf, _ok_conf, _run, shield)
from tests.test_claude_code_hook_tool_policies import (  # noqa: F401  (fixtures)
    AWS_ID, _Result, _clean, _post_event, _pre, _tenant, app, events, guards)

# ── part 1: the Codex route ──────────────────────────────────────────────


def _codex(t, body):
    return t.c.post("/v1/shield/hooks/codex", content=json.dumps(body),
                    headers={"Content-Type": "application/json", "X-Agent-Key": "claude-code",
                             "X-Shield-User": "dev"})


def test_codex_gets_the_same_deny(app, guards):
    t = _tenant(app)
    guards.call = _Result(False, "block", "Payload policy blocked 'Bash': bulk export")
    out = _codex(t, _pre("Bash", {"command": "python manage.py dumpdata --all"})).json()
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "bulk export" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_an_ask_is_a_deny_for_codex(app, guards):
    from tests.test_claude_code_hook_tool_policies import BASE_PROFILE, TOOL_POLICIES
    from starlette.testclient import TestClient  # noqa: F401
    t = _tenant(app)
    profile = dict(BASE_PROFILE, process={"deny_commands": [], "ask_commands": ["git push*"]},
                   tool_policies=TOOL_POLICIES)
    assert t.c.put("/v1/tenant/me/runtime-profiles/laptop", json=profile).status_code == 200
    from core.runtime_policy import check as rc
    rc.invalidate()
    out = _codex(t, _pre("Bash", {"command": "git push origin main"})).json()["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "Codex hooks cannot ask" in out["permissionDecisionReason"]
    # Claude Code still gets the ask.
    r = t.c.post("/v1/shield/hooks/claude-code", content=json.dumps(_pre("Bash", {"command": "git push origin main"})),
                 headers={"Content-Type": "application/json", "X-Agent-Key": "claude-code"})
    assert r.json()["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_a_redaction_becomes_the_result_codex_sees(app, guards, events):
    t = _tenant(app)
    guards.result = _Result(True, "redact", details={
        "sanitized_output": "Alice, card **** **** **** 1111", "findings": "card"})
    out = _codex(t, _post_event("Bash", "Alice, card 4111 1111 1111 1111")).json()
    assert out["decision"] == "block"
    assert out["reason"].endswith("Result:\nAlice, card **** **** **** 1111")
    assert "4111 1111 1111 1111" not in out["reason"]
    assert events[-1]["detail"]["verdict"] == "redact"


def test_a_withheld_result_is_a_note_for_codex(app, guards):
    t = _tenant(app)
    guards.result = _Result(False, "block", "x", {
        "sanitized_output": "[CONTENT BLOCKED DUE TO DATA POLICY]", "findings": "injected instructions"})
    out = _codex(t, _post_event("Read", {"content": "IGNORE ALL PREVIOUS"})).json()
    assert out == {"decision": "block",
                   "reason": "[Shield withheld this result: injected instructions]"}


def test_a_clean_result_is_left_alone_for_codex(app, guards):
    t = _tenant(app)
    assert _codex(t, _post_event("Bash", "ok")).json() == {}


def test_secret_patterns_apply_for_codex_without_the_model(app, guards):
    t = _tenant(app)
    out = _codex(t, _post_event("apply_patch", f"wrote KEY={AWS_ID}")).json()
    assert out["decision"] == "block" and AWS_ID not in out["reason"]
    assert guards.results == []


def test_the_device_agent_is_not_accepted_on_the_codex_route(app, monkeypatch):
    import core.dlp.devices as dv
    monkeypatch.setattr(dv, "caller_device_cached", lambda request: ("t", "dev-1", {"fleet": ""}))
    from starlette.testclient import TestClient
    r = TestClient(app).post("/v1/shield/hooks/codex", json=_pre("Bash", {"command": "ls"}))
    assert r.status_code == 400 and "Codex" in r.json()["detail"]


# ── part 2: the script ───────────────────────────────────────────────────

RESULT = {"session_id": "s-1", "cwd": "/Users/dev/proj", "hook_event_name": "PostToolUse",
          "tool_name": "Bash", "tool_input": {"command": "cat a"}, "tool_response": "x",
          "tool_use_id": "t1"}
CLAUDE_REDACTED = {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                          "updatedToolOutput": "card **** 1111",
                                          "additionalContext": "redacted"}}
CODEX_REDACTED = {"decision": "block", "reason": "Result:\ncard **** 1111"}


@pytest.mark.parametrize("shell", SHELLS)
def test_target_codex_posts_to_the_codex_route(shell, shield, tmp_path):
    conf = _ok_conf(tmp_path, shield)
    r = _run(conf, shell, args=["--target", "codex", "--config", conf])
    assert r.returncode == 0 and shield.seen[-1]["path"] == "/v1/shield/hooks/codex"
    shield.body = DENY
    r = _run(conf, shell, args=["--config", conf, "--target", "codex"])     # either order
    assert r.returncode == 2 and b"openssl enc*" in r.stderr


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("target, answer", [("claude-code", CLAUDE_REDACTED),
                                            ("codex", CODEX_REDACTED)])
def test_after_a_call_the_answer_is_passed_through(shell, shield, tmp_path, target, answer):
    conf = _ok_conf(tmp_path, shield)
    shield.body = answer
    r = _run(conf, shell, payload=RESULT, args=["--config", conf, "--target", target])
    assert r.returncode == 0 and json.loads(r.stdout) == answer
    assert json.loads(shield.seen[-1]["body"]) == RESULT        # forwarded unchanged
    shield.body = {}
    r = _run(conf, shell, payload=RESULT, args=["--config", conf, "--target", target])
    assert (r.returncode, r.stdout) == (0, b"")


@pytest.mark.parametrize("shell", SHELLS)
def test_after_a_call_a_failure_lets_the_result_through_by_default(shell, shield, tmp_path):
    conf = _ok_conf(tmp_path, shield)
    shield.status = 500
    r = _run(conf, shell, payload=RESULT)
    assert (r.returncode, r.stdout) == (0, b"")
    # ...but the same failure BEFORE a call still denies.
    r = _run(conf, shell, payload=CALL)
    assert r.returncode == 2


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("target", ["claude-code", "codex"])
def test_after_a_call_withhold_on_failure_withholds(shell, shield, tmp_path, target):
    conf = _ok_conf(tmp_path, shield, "ON_UNREACHABLE_RESULT=withhold\n")
    shield.status = 500
    r = _run(conf, shell, payload=RESULT, args=["--config", conf, "--target", target])
    assert r.returncode == 0
    out = json.loads(r.stdout)
    note = (out["reason"] if target == "codex" else out["hookSpecificOutput"]["updatedToolOutput"])
    assert note == "[Shield withheld this result: Shield could not check it]"


@pytest.mark.parametrize("shell", SHELLS)
def test_after_a_call_an_answer_not_understood_is_a_failure(shell, shield, tmp_path):
    conf = _ok_conf(tmp_path, shield, "ON_UNREACHABLE_RESULT=withhold\n")
    shield.body = {"something": "else"}
    r = _run(conf, shell, payload=RESULT)
    assert r.returncode == 0 and "withheld" in r.stdout.decode()


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("args", [["--target"], ["--target", "cursor"], ["--config"]])
def test_bad_arguments_never_fail_open(shell, shield, tmp_path, args):
    """A truncated or unknown argument must still exit 2 before a call: any
    other exit code lets the call through."""
    r = _run(_ok_conf(tmp_path, shield), shell, payload=CALL, args=args)
    assert r.returncode == 2


def test_the_windows_twin_has_the_same_rules():
    """No PowerShell on the CI runners: the twin is checked for the same
    branches, not run."""
    from tests.test_claude_code_hook import PS1
    src = open(PS1, encoding="utf-8").read()
    for needle in ('[ValidateSet("claude-code", "codex")][string]$Target',
                   '/v1/shield/hooks/$Target', 'ON_UNREACHABLE_RESULT',
                   '"PostToolUse"', 'updatedToolOutput', 'decision = "block"'):
        assert needle in src, needle
