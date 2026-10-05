"""The reference files in examples/agent-hooks must stay usable: valid JSON,
a profile Shield accepts, and hook commands that keep the fail-closed rules
(docs/specs/agent-hook-adapter.md 4.3: `|| exit 2` before a call).

The plugin (examples/agent-hooks/plugin) carries the same hooks for Claude
Code and Cowork, which loads hooks only from plugins; its commands are run
here for real, the way Claude Code runs them."""
import json
import os
import subprocess

import pytest

from core.runtime_policy.model import validate_profile
from tests.test_claude_code_hook import CALL, DENY, shield  # noqa: F401  (fixture: shield)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIR = os.path.join(ROOT, "examples", "agent-hooks")
MARKETPLACE = os.path.join(DIR, "plugin")
PLUGIN = os.path.join(MARKETPLACE, "votal-shield-hooks")


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


# ── the plugin ───────────────────────────────────────────────────────────


def _plugin_hooks():
    with open(os.path.join(PLUGIN, "hooks", "hooks.json"), encoding="utf-8") as f:
        return json.load(f)["hooks"]


def test_the_marketplace_lists_the_plugin_it_ships():
    with open(os.path.join(MARKETPLACE, ".claude-plugin", "marketplace.json"), encoding="utf-8") as f:
        market = json.load(f)
    with open(os.path.join(PLUGIN, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    [entry] = market["plugins"]
    assert entry["name"] == manifest["name"] == "votal-shield-hooks"
    assert entry["version"] == manifest["version"]
    assert os.path.realpath(os.path.join(MARKETPLACE, entry["source"])) == os.path.realpath(PLUGIN)


def test_the_plugin_checks_the_same_tools_as_the_settings_file():
    """Two copies of one decision: a tool added to one and not the other would
    be checked in Claude Code settings but not in Cowork, or the reverse."""
    settings = _load("claude-settings-fail-closed.json")["hooks"]
    plugin = _plugin_hooks()
    for event in ("PreToolUse", "PostToolUse"):
        assert plugin[event][0]["matcher"] == settings[event][0]["matcher"]


def test_the_plugin_fails_closed_before_a_call_and_runs_its_own_script():
    hooks = _plugin_hooks()
    pre = hooks["PreToolUse"][0]["hooks"][0]["command"]
    post = hooks["PostToolUse"][0]["hooks"][0]["command"]
    for cmd in (pre, post):
        assert '"${CLAUDE_PLUGIN_ROOT}/scripts/claude_code_hook.sh"' in cmd
        assert "--target claude-code" in cmd and '--config "$HOME/.votal/hook.conf"' in cmd
    assert pre.endswith("|| exit 2") and not post.endswith("|| exit 2")


def test_the_plugin_script_is_the_canonical_one():
    """Regenerate with packages/votal-device-agent/packaging/sync_hook_scripts.py."""
    with open(os.path.join(PLUGIN, "scripts", "claude_code_hook.sh"), "rb") as a, \
            open(os.path.join(ROOT, "core", "runtime_policy", "hook_scripts",
                              "claude_code_hook.sh"), "rb") as b:
        assert a.read() == b.read()


def _run_plugin_command(event, home, payload):
    """Run the hooks.json command string through a shell, as Claude Code does,
    with CLAUDE_PLUGIN_ROOT and HOME set."""
    cmd = _plugin_hooks()[event][0]["hooks"][0]["command"]
    env = {"PATH": os.environ["PATH"], "USER": "dev", "HOME": str(home),
           "CLAUDE_PLUGIN_ROOT": PLUGIN, "TMPDIR": os.environ.get("TMPDIR", "/tmp")}
    return subprocess.run(["/bin/sh", "-c", cmd], input=json.dumps(payload).encode(),
                          capture_output=True, env=env, timeout=40)


def _home_with_conf(tmp_path, shield):
    (tmp_path / ".votal").mkdir()
    (tmp_path / ".votal" / "hook.conf").write_text(
        f"SHIELD_URL={shield.url}/\nSHIELD_API_KEY=sk-test-key\nSHIELD_AGENT=hooks-test\n"
        "SHIELD_TIMEOUT=3\n")
    return tmp_path


def test_the_plugin_command_asks_shield_and_denies(shield, tmp_path):
    home = _home_with_conf(tmp_path, shield)
    r = _run_plugin_command("PreToolUse", home, CALL)
    assert (r.returncode, r.stdout) == (0, b"")
    seen = shield.seen[-1]
    assert seen["path"] == "/v1/shield/hooks/claude-code"
    assert {k.lower(): v for k, v in seen["headers"].items()}["x-agent-key"] == "hooks-test"
    shield.body = DENY
    r = _run_plugin_command("PreToolUse", home, CALL)
    assert r.returncode == 2 and b"Blocked by Votal Shield" in r.stderr


def test_the_plugin_command_passes_a_redaction_back(shield, tmp_path):
    home = _home_with_conf(tmp_path, shield)
    shield.body = {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                          "updatedToolOutput": "card **** 1111"}}
    result = dict(CALL, hook_event_name="PostToolUse", tool_response="card 4111 1111 1111 1111")
    r = _run_plugin_command("PostToolUse", home, result)
    assert r.returncode == 0 and json.loads(r.stdout) == shield.body


# ── packaging for a bucket (package_for_bucket.py) ───────────────────────

BASE = "https://storage.googleapis.com/votal-ai/claude-plugins"


def _packager():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "package_for_bucket", os.path.join(MARKETPLACE, "package_for_bucket.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_bucket_catalog_points_at_the_zip_and_pins_it(tmp_path):
    import hashlib
    r = _packager().package(BASE + "/", tmp_path)          # trailing slash tolerated
    hosted = json.loads(r["marketplace"].read_text())
    [entry] = hosted["plugins"]
    with open(os.path.join(PLUGIN, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        version = json.load(f)["version"]
    assert entry["source"] == {
        "source": "archive", "url": f"{BASE}/votal-shield-hooks-{version}.zip",
        "sha256": hashlib.sha256(r["zip"].read_bytes()).hexdigest()}
    assert entry["version"] == version and hosted["name"] == "votal-shield"


def test_the_zip_is_the_plugin_at_its_root_and_the_same_every_time(tmp_path):
    import zipfile
    pkg = _packager()
    first = pkg.package(BASE, tmp_path / "a")
    # A fresh checkout on another machine has other file times: same digest.
    hooks_json = os.path.join(PLUGIN, "hooks", "hooks.json")
    st = os.stat(hooks_json)
    os.utime(hooks_json, (st.st_atime, st.st_mtime + 86400))
    try:
        second = pkg.package(BASE, tmp_path / "b")
    finally:
        os.utime(hooks_json, (st.st_atime, st.st_mtime))
    assert first["sha256"] == second["sha256"]
    with zipfile.ZipFile(first["zip"]) as z:
        names = sorted(z.namelist())
        assert names == [".claude-plugin/plugin.json", "hooks/hooks.json",
                         "scripts/claude_code_hook.sh"]
        mode = z.getinfo("scripts/claude_code_hook.sh").external_attr >> 16
        assert mode & 0o777 == 0o755
        with open(os.path.join(PLUGIN, "hooks", "hooks.json"), "rb") as f:
            assert z.read("hooks/hooks.json") == f.read()


@pytest.mark.parametrize("url", ["http://storage.googleapis.com/votal-ai/p",
                                 "storage.googleapis.com/votal-ai/p",
                                 "https://storage.googleapis.com/votal-ai/p?x=1"])
def test_the_bucket_url_must_be_plain_https(tmp_path, url):
    pkg = _packager()
    with pytest.raises(pkg.PackagingError):
        pkg.package(url, tmp_path)
    assert pkg.main(["--base-url", url, "--out", str(tmp_path)]) == 2
    assert not list(tmp_path.iterdir())                   # nothing half-written


def test_a_drifted_script_is_not_packaged(tmp_path, monkeypatch):
    pkg = _packager()
    other = tmp_path / "other.sh"
    other.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(pkg, "CANONICAL_SCRIPT", other)
    with pytest.raises(pkg.PackagingError, match="sync_hook_scripts"):
        pkg.package(BASE, tmp_path / "out")


@pytest.mark.parametrize("break_it", ["no_config", "no_script"])
def test_the_plugin_denies_when_it_cannot_check(shield, tmp_path, break_it):
    """Cowork runs hooks in its own environment: if it cannot see ~/.votal or
    the plugin's script, every call must be denied, not let through."""
    home = tmp_path if break_it == "no_config" else _home_with_conf(tmp_path, shield)
    cmd = _plugin_hooks()["PreToolUse"][0]["hooks"][0]["command"]
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "USER": "dev",
           "CLAUDE_PLUGIN_ROOT": PLUGIN if break_it == "no_config" else str(tmp_path / "gone")}
    r = subprocess.run(["/bin/sh", "-c", cmd], input=json.dumps(CALL).encode(),
                       capture_output=True, env=env, timeout=40)
    assert r.returncode == 2
