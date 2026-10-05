"""The reference files in examples/agent-hooks must stay usable: valid JSON,
a profile Shield accepts, and hook commands that keep the fail-closed rules
(docs/specs/agent-hook-adapter.md 4.3: `|| exit 2` before a call)."""
import json
import os

from core.runtime_policy.model import validate_profile

DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "examples", "agent-hooks")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


def test_the_profile_is_one_shield_accepts():
    p = validate_profile(_load("runtime-profile.json"))
    assert p["tool_policies"]["before_call"] and p["tool_policies"]["after_call"]


def test_claude_http_hooks_point_at_the_hook_route_for_both_events():
    hooks = _load("claude-settings.json")["hooks"]
    for event in ("PreToolUse", "PostToolUse"):
        h = hooks[event][0]["hooks"][0]
        assert h["type"] == "http" and h["url"].endswith("/v1/shield/hooks/claude-code")
        assert "$SHIELD_TENANT_KEY" in h["headers"]["X-API-Key"]
        assert "SHIELD_TENANT_KEY" in h["allowedEnvVars"]


def test_command_hooks_fail_closed_before_a_call_and_name_their_target():
    for name, target in (("claude-settings-fail-closed.json", "claude-code"),
                         ("codex-hooks.json", "codex")):
        hooks = _load(name)["hooks"]
        pre = hooks["PreToolUse"][0]["hooks"][0]["command"]
        post = hooks["PostToolUse"][0]["hooks"][0]["command"]
        assert pre.endswith("|| exit 2") and f"--target {target}" in pre
        assert f"--target {target}" in post and not post.endswith("|| exit 2")


def test_the_example_config_has_no_real_key():
    with open(os.path.join(DIR, "hook.conf.example"), encoding="utf-8") as f:
        assert "SHIELD_API_KEY=<your tenant key>" in f.read()
