"""The prompt check in the command hook script and the settings files (task 3
of docs/specs/agent-hooks-prompt-check.md).

claude_code_hook.sh runs for real under sh and dash against a fake Shield:
on UserPromptSubmit Shield's refusal or note is passed through unchanged, and
a failure follows ON_UNREACHABLE_PROMPT (allow by default). Exit 0 always:
exit 2 would also refuse the prompt, but with the internal failure as the
message. Tool calls keep their own failure rules.
"""
import json
import os

import pytest

from tests.test_claude_code_hook import (  # noqa: F401  (fixture: shield)
    CALL, PS1, SHELLS, _ok_conf, _run, shield)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples", "agent-hooks")

PROMPT = {"session_id": "s-1", "cwd": "/Users/dev/proj", "hook_event_name": "UserPromptSubmit",
          "permission_mode": "default", "prompt": "encrypt a.txt", "prompt_id": "p-1"}
BLOCK = {"decision": "block", "reason": "Blocked by Votal Shield: No file encryption: asks to encrypt"}
NOTE = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                               "additionalContext": "Votal Shield: this request falls under ..."}}


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("target", ["claude-code", "codex"])
@pytest.mark.parametrize("answer", [BLOCK, NOTE])
def test_shields_answer_is_passed_through(shell, shield, tmp_path, target, answer):
    conf = _ok_conf(tmp_path, shield)
    shield.body = answer
    r = _run(conf, shell, payload=PROMPT, args=["--config", conf, "--target", target])
    assert r.returncode == 0 and json.loads(r.stdout) == answer
    assert shield.seen[-1]["path"] == f"/v1/shield/hooks/{target}"
    assert json.loads(shield.seen[-1]["body"]) == PROMPT          # forwarded unchanged


@pytest.mark.parametrize("shell", SHELLS)
def test_an_empty_answer_lets_the_prompt_through(shell, shield, tmp_path):
    r = _run(_ok_conf(tmp_path, shield), shell, payload=PROMPT)
    assert (r.returncode, r.stdout) == (0, b"")


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("status, body", [(500, {}), (200, {"something": "else"})])
def test_a_failure_lets_the_prompt_through_by_default(shell, shield, tmp_path, status, body):
    conf = _ok_conf(tmp_path, shield)
    shield.status, shield.body = status, body
    r = _run(conf, shell, payload=PROMPT)
    assert (r.returncode, r.stdout) == (0, b"")
    # ...while the same failure before a tool call still denies it.
    assert _run(conf, shell, payload=CALL).returncode == 2


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("target", ["claude-code", "codex"])
def test_on_unreachable_prompt_block_refuses_it(shell, shield, tmp_path, target):
    conf = _ok_conf(tmp_path, shield, "ON_UNREACHABLE_PROMPT=block\n")
    shield.status = 500
    r = _run(conf, shell, payload=PROMPT, args=["--config", conf, "--target", target])
    assert r.returncode == 0
    assert json.loads(r.stdout) == {"decision": "block",
                                    "reason": "Votal Shield could not check this request"}


@pytest.mark.parametrize("shell", SHELLS)
def test_a_missing_config_lets_the_prompt_through(shell, tmp_path):
    """No config, so no ON_UNREACHABLE_PROMPT to read: the default applies."""
    r = _run(str(tmp_path / "absent.conf"), shell, payload=PROMPT)
    assert (r.returncode, r.stdout) == (0, b"")


def test_the_windows_twin_has_the_same_rules():
    src = open(PS1, encoding="utf-8").read()
    for needle in ('"UserPromptSubmit"', "ON_UNREACHABLE_PROMPT", "$script:OnUnreachablePrompt",
                   'reason = "Votal Shield could not check this request"',
                   "$hso.additionalContext", '[string]$answer.decision -eq "block"'):
        assert needle in src, needle


# ── the settings files and the plugin ────────────────────────────────────

FILES = {"claude-settings.json": None, "claude-settings-fail-closed.json": "claude-code",
         "codex-hooks.json": "codex",
         "plugin/votal-shield-hooks/hooks/hooks.json": "claude-code"}


@pytest.mark.parametrize("name, target", sorted(FILES.items()))
def test_every_settings_file_registers_the_prompt_hook(name, target):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        [group] = json.load(f)["hooks"]["UserPromptSubmit"]
    assert "matcher" not in group                       # no matcher on this event
    [hook] = group["hooks"]
    if target is None:                                  # Claude Code HTTP hooks
        assert hook["type"] == "http" and hook["url"].endswith("/v1/shield/hooks/claude-code")
        return
    cmd = hook["command"]
    assert f"--target {target}" in cmd
    # A failure is ON_UNREACHABLE_PROMPT's to decide, not a blanket exit 2.
    assert not cmd.endswith("|| exit 2")


def test_the_plugin_and_the_settings_file_send_prompts_the_same_way():
    def hook(name):
        with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
            return json.load(f)["hooks"]["UserPromptSubmit"][0]["hooks"][0]
    plugin = hook("plugin/votal-shield-hooks/hooks/hooks.json")["command"]
    settings = hook("claude-settings-fail-closed.json")["command"]
    assert plugin.replace('${CLAUDE_PLUGIN_ROOT}/scripts', '$HOME/.votal') == settings


def test_the_example_profile_turns_the_prompt_check_on():
    from core.runtime_policy.model import validate_profile
    with open(os.path.join(EXAMPLES, "runtime-profile.json"), encoding="utf-8") as f:
        assert validate_profile(json.load(f))["tool_policies"]["before_prompt"] is True
