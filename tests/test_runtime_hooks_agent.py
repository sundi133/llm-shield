"""Coding-agent guardrails as a fleet switch, task 3: the Votal device agent
installs Claude Code's hook from the signed bundle and answers it with the
device key. Spec: docs/specs/claude-code-fleet-rollout.md section 4.5.
"""

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from tests.test_device_agent import (LAPTOP, SK, make_policy, ollama, pub, shield,  # noqa: F401
                                     shield_app, signed)
from votal_device_agent import agent_hooks as vh
from votal_device_agent import hook_scripts
from votal_device_agent import sync as vsync
from votal_device_agent.agent import Agent
from votal_device_agent.local_api import LocalApi

ROOT = Path(__file__).resolve().parents[1]
ON = {"agents": {"claude_code": "claude-code"}, "mode": "enforce", "on_unreachable": "deny"}
CALL = {"session_id": "s-1", "cwd": "/Users/ana/proj", "tool_name": "Bash",
        "transcript_path": "/Users/ana/.claude/projects/p/s.jsonl",
        "tool_input": {"command": "openssl enc -in a.txt"}}
DENY = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                               "permissionDecisionReason": "Blocked by Votal Shield: x"}}


def _hooks(tmp_path, os_name="macos", port=47823):
    paths = vh.HookPaths(tmp_path / "ClaudeCode" / "managed-settings.json", tmp_path / "hooks")
    return vh.AgentHooks(paths, tmp_path / "state", local_port=port, os_name=os_name)


def _settings(h):
    return json.loads(h.paths.managed_settings.read_text())


# ── the files ────────────────────────────────────────────────────────


def test_enforce_writes_hook_conf_and_managed_settings(tmp_path):
    h = _hooks(tmp_path)
    report = h.apply(ON)["claude_code"]
    assert report["state"] == "active" and report["settings_hash"].startswith("sha256:")
    assert h.script_path.read_text() == hook_scripts.CLAUDE_CODE_HOOK_SH
    assert os.access(h.script_path, os.X_OK)
    conf = h.conf_path.read_text()
    assert "SHIELD_URL=http://127.0.0.1:47823\n" in conf and "ON_UNREACHABLE=deny\n" in conf
    assert f"SHIELD_LOCAL_SECRET_FILE={tmp_path / 'state' / 'local_secret'}\n" in conf
    s = _settings(h)
    (entry,) = s["hooks"]["PreToolUse"]
    (hook,) = entry["hooks"]
    assert s["allowManagedHooksOnly"] is True and entry["matcher"] == vh.MATCHER
    assert hook["type"] == "command" and hook["command"].endswith(" || exit 2")
    assert str(h.script_path) in hook["command"] and str(h.conf_path) in hook["command"]
    assert hook["timeout"] > vh.SCRIPT_TIMEOUT_S


def test_mode_changes_rewrite_at_most_hook_conf(tmp_path):
    h = _hooks(tmp_path)
    h.apply(ON)
    before = h.paths.managed_settings.read_text()
    h.apply({**ON, "mode": "monitor", "on_unreachable": "allow"})
    assert h.paths.managed_settings.read_text() == before
    assert "ON_UNREACHABLE=allow\n" in h.conf_path.read_text()


def test_off_keeps_the_file_as_empty_settings_and_on_again_restores(tmp_path):
    h = _hooks(tmp_path)
    assert h.apply({**ON, "mode": "off"})["claude_code"]["state"] == "off"
    assert not h.paths.managed_settings.exists()                 # never on: nothing written
    h.apply(ON)
    assert h.apply({**ON, "mode": "off"})["claude_code"]["state"] == "off"
    assert h.paths.managed_settings.read_text() == "{}\n"        # kept, so running sessions follow
    assert h.apply(None)["claude_code"]["state"] == "off"         # setting removed: same
    assert h.apply(ON)["claude_code"]["state"] == "active"
    assert "hooks" in _settings(h)


def test_settings_someone_else_wrote_are_never_touched(tmp_path):
    h = _hooks(tmp_path)
    h.paths.managed_settings.parent.mkdir(parents=True)
    theirs = '{"permissions": {"deny": ["Bash(curl:*)"]}}\n'
    h.paths.managed_settings.write_text(theirs)
    report = h.apply(ON)["claude_code"]
    assert report["state"] == "conflict" and "did not write" in report["reason"]
    assert h.paths.managed_settings.read_text() == theirs
    assert h.apply({**ON, "mode": "off"})["claude_code"]["state"] == "off"
    assert h.paths.managed_settings.read_text() == theirs        # never ours, never rewritten
    h.paths.managed_settings.unlink()                            # once theirs is gone...
    assert h.apply(ON)["claude_code"]["state"] == "active"       # ...the agent takes over


def test_our_file_edited_by_hand_becomes_a_conflict(tmp_path):
    h = _hooks(tmp_path)
    h.apply(ON)
    h.paths.managed_settings.write_text('{"hooks": {}}\n')
    assert h.apply({**ON, "mode": "off"})["claude_code"]["state"] == "conflict"
    assert h.paths.managed_settings.read_text() == '{"hooks": {}}\n'


def test_identical_content_is_adopted(tmp_path):
    h = _hooks(tmp_path)
    h.paths.managed_settings.parent.mkdir(parents=True)
    h.paths.managed_settings.write_text(h.settings_text())       # e.g. an earlier install
    assert h.apply(ON)["claude_code"]["state"] == "active"
    assert h.apply({**ON, "mode": "off"})["claude_code"]["state"] == "off"


def test_a_failure_is_reported_not_raised(tmp_path):
    h = _hooks(tmp_path)
    (tmp_path / "ClaudeCode").write_text("a file where a folder should be")
    report = h.apply(ON)["claude_code"]
    assert report["state"] == "error" and report["reason"]


def test_windows_uses_the_powershell_hook(tmp_path):
    h = _hooks(tmp_path, os_name="windows")
    h.apply(ON)
    assert h.script_path.name == "claude_code_hook.ps1"
    assert h.script_path.read_text() == hook_scripts.CLAUDE_CODE_HOOK_PS1
    cmd = _settings(h)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd.startswith("powershell.exe ") and f'-Config "{h.conf_path}"' in cmd
    assert cmd.endswith(" || exit 2")


def test_bundled_scripts_match_the_canonical_ones():
    """The installers bundle modules, not data files, so the scripts ship as
    constants. Regenerate with packages/votal-device-agent/packaging/sync_hook_scripts.py."""
    src = ROOT / "core" / "runtime_policy" / "hook_scripts"
    assert hook_scripts.CLAUDE_CODE_HOOK_SH == (src / "claude_code_hook.sh").read_text()
    assert hook_scripts.CLAUDE_CODE_HOOK_PS1 == (src / "claude_code_hook.ps1").read_text()
    from core.runtime_policy import hook_kit
    assert vh.MATCHER == hook_kit.MATCHER
    assert vh.SCRIPT_TIMEOUT_S == hook_kit.SCRIPT_TIMEOUT_S


# ── the agent ────────────────────────────────────────────────────────


def _agent(tmp_path, ollama, *, port=47823, http=None, hook_http=None, fleet="sales"):
    cfg = vsync.AgentConfig(shield_url="https://shield.test", tenant_id="acme", fleet=fleet,
                            pinned_public_key=pub(SK), state_dir=str(tmp_path / "agent"),
                            model_inline="always", local_port=port)
    return Agent(cfg, http=http or (lambda *a: (_ for _ in ()).throw(OSError("offline"))),
                 model_http=ollama, hook_paths=vh.HookPaths(
                     tmp_path / "ClaudeCode" / "managed-settings.json", tmp_path / "hooks"),
                 hook_http=hook_http)


def test_hooks_follow_a_verified_bundle_only(tmp_path, ollama):
    agent = _agent(tmp_path, ollama)
    agent.reload()                                     # fallback: no bundle yet
    assert not (tmp_path / "ClaudeCode" / "managed-settings.json").exists()
    agent.store.accept(signed({**make_policy(), "agent_hooks": ON}))
    agent.reload()
    assert agent.hooks.report["claude_code"]["state"] == "active"
    assert agent.heartbeat_payload()["agent_hooks"]["claude_code"]["state"] == "active"
    # A tampered bundle falls back; the last applied state stays.
    bad = signed({**make_policy(), "agent_hooks": {**ON, "mode": "off"}})
    bad["policy"]["agent_hooks"]["mode"] = "enforce"
    agent.store.bundle_path.write_text(json.dumps(bad))
    agent.reload()
    assert agent.engine.trust.status != "verified"
    assert "hooks" in json.loads((tmp_path / "ClaudeCode" / "managed-settings.json").read_text())


def _with_policy(agent, hooks_setting):
    agent.store.accept(signed({**make_policy(), "agent_hooks": hooks_setting}))
    agent.reload()


def test_hook_calls_are_forwarded_with_the_device_key(tmp_path, ollama):
    seen = []

    def hook_http(method, url, headers, body):
        seen.append((url, headers, json.loads(body)))
        return 200, {}, json.dumps(DENY).encode()

    agent = _agent(tmp_path, ollama, hook_http=hook_http)
    agent.creds = vsync.Credentials(device_id="dev_1", api_key="vdk_test", fleet="sales",
                                    tenant_id="acme")
    _with_policy(agent, ON)
    assert agent.claude_code_hook(CALL, user="ana") == DENY
    url, headers, body = seen[0]
    assert url == "https://shield.test/v1/shield/hooks/claude-code"
    assert headers["X-API-Key"] == "vdk_test" and headers["X-Shield-User"] == "ana"
    assert body == CALL


@pytest.mark.parametrize("answer", [
    OSError("down"), (500, b"boom"), (401, b"{}"), (200, b"not json"), (200, b'{"x": 1}')])
@pytest.mark.parametrize("on_unreachable", ["deny", "allow"])
def test_no_usable_answer_gets_the_fleets_unreachable_decision(tmp_path, ollama, answer,
                                                               on_unreachable):
    def hook_http(*a):
        if isinstance(answer, Exception):
            raise answer
        return answer[0], {}, answer[1]

    agent = _agent(tmp_path, ollama, hook_http=hook_http)
    agent.creds = vsync.Credentials(device_id="dev_1", api_key="vdk_test", fleet="sales",
                                    tenant_id="acme")
    _with_policy(agent, {**ON, "on_unreachable": on_unreachable})
    out = agent.claude_code_hook(CALL)
    if on_unreachable == "deny":
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "could not be reached" in out["hookSpecificOutput"]["permissionDecisionReason"]
    else:
        assert out == {}
    assert agent.engine.counters["hook_unreachable"] == 1


def test_off_fleet_answers_without_asking_shield(tmp_path, ollama):
    def hook_http(*a):
        raise AssertionError("Shield asked")
    agent = _agent(tmp_path, ollama, hook_http=hook_http)
    _with_policy(agent, {**ON, "mode": "off"})
    assert agent.claude_code_hook(CALL) == {}


def test_local_route_checks_secret_origin_and_size(tmp_path, ollama):
    from starlette.testclient import TestClient  # noqa: F401  (http.client below)
    import http.client
    agent = _agent(tmp_path, ollama, hook_http=lambda *a: (200, {}, b"{}"))
    agent.creds = vsync.Credentials(device_id="dev_1", api_key="vdk_test", fleet="sales",
                                    tenant_id="acme")
    _with_policy(agent, ON)
    api = LocalApi(agent, secret="s" * 43, port=0)
    port = api.start()
    try:
        def post(headers, body=json.dumps(CALL).encode()):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("POST", "/v1/local/claude-code/hook", body=body,
                      headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json",
                               **headers})
            r = c.getresponse()
            return r.status, r.read()
        assert post({})[0] == 401
        assert post({"X-Votal-Local-Secret": "s" * 43, "Origin": "https://evil.example"})[0] == 403
        assert post({"X-Votal-Local-Secret": "s" * 43}) == (200, b"{}")
        big = json.dumps({**CALL, "tool_input": {"file_path": "a", "content": "x" * (2 << 20)}})
        assert post({"X-Votal-Local-Secret": "s" * 43}, big.encode())[0] == 200
    finally:
        api.stop()


# ── end to end: Shield, the signed bundle, the agent and the real hook script ──


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.skipif(not shutil.which("curl"), reason="needs curl")
def test_end_to_end_through_the_installed_hook(tmp_path, shield, ollama):
    shield.put("/v1/tenant/me/runtime-profiles/laptop", json={
        "filesystem": {"read_write": ["@project"], "kernel_enforcement": "best_effort"},
        "process": {"deny_commands": ["openssl enc*"]}})
    shield.post("/v1/agents/registry", json={"agent_id": "claude-code", "runtime_profile": "laptop"})
    assert shield.post("/v1/tenant/me/hooks/enable", json={"profile": "laptop"}).status_code == 200
    assert shield.put("/v1/tenant/me/hooks/fleets", json={
        "fleets": {"eng": {"mode": "enforce", "on_unreachable": "deny"}}}).status_code == 200
    token = shield.post("/v1/tenant/me/devices/enrollment-tokens",
                        json={"fleet": "eng"}).json()["enrollment_token"]

    port = _free_port()
    cfg = vsync.AgentConfig(shield_url="https://shield.test", tenant_id=shield.tenant_id,
                            fleet="eng", pinned_public_key=pub(SK),
                            state_dir=str(tmp_path / "agent"), model_inline="always",
                            local_port=port)
    agent = Agent(cfg, http=shield.http, model_http=ollama, hook_http=shield.http,
                  hook_paths=vh.HookPaths(tmp_path / "ClaudeCode" / "managed-settings.json",
                                          tmp_path / "hooks"))
    agent.enroll_if_needed(token, LAPTOP)
    from votal_device_agent.local_api import load_or_create_secret
    api = LocalApi(agent, load_or_create_secret(cfg.state_dir), port=port)
    api.start()
    try:
        out = agent.sync_once()                         # bundle -> hooks applied -> heartbeat
        assert out["bundle"] == "updated" and out["heartbeat"] == 204
        assert agent.hooks.report["claude_code"]["state"] == "active"
        cmd = json.loads((tmp_path / "ClaudeCode" / "managed-settings.json").read_text()) \
            ["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

        def run(command):
            payload = {**CALL, "tool_input": {"command": command}}
            return subprocess.run(["/bin/sh", "-c", cmd], input=json.dumps(payload).encode(),
                                  capture_output=True, timeout=30,
                                  env={"PATH": os.environ["PATH"], "USER": "ana"})

        r = run("openssl enc -in a.txt")
        assert r.returncode == 2 and b"openssl enc*" in r.stderr
        assert run("git status").returncode == 0
        fleets = {f["fleet"]: f for f in shield.get("/v1/tenant/me/hooks/fleets").json()["fleets"]}
        assert fleets["eng"]["states"]["claude_code"] == {"active": 1}
        laptops = shield.get("/v1/tenant/me/hooks/claude-code").json()["laptops"]
        assert laptops and laptops[0]["hostname"] == "ana-mbp" and laptops[0]["fleet"] == "eng"

        # Monitor: everything goes through, what enforce would do is recorded.
        shield.put("/v1/tenant/me/hooks/fleets", json={"fleets": {"eng": {"mode": "monitor"}}})
        assert run("openssl enc -in a.txt").returncode == 0
    finally:
        api.stop()
    # The agent stopped: the script follows ON_UNREACHABLE (deny here).
    r = run("git status")
    assert r.returncode == 2 and b"could not be reached" in r.stderr
