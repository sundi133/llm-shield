"""The kit installed for real, as root, then the hook run as a user
(docs/specs/hooks-plugin-production.md, task 3).

Proves the installer leaves files the hook judges managed: the hook then
ignores --config, refuses a localhost Shield and, in the regulated tier,
withholds results and blocks prompts when it cannot get an answer.

Writes /opt/votal, /etc/votal and /etc/claude-code, so it runs only when
VOTAL_KIT_E2E=1 on a throwaway Linux runner with passwordless sudo (the
"hook kit install (linux)" CI job). The Windows twin is in
tests/test_hook_script_windows.py.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

from core.runtime_policy import hook_kit

pytestmark = pytest.mark.skipif(
    os.environ.get("VOTAL_KIT_E2E") != "1" or not sys.platform.startswith("linux")
    or not shutil.which("sudo"), reason="real-root install: CI only (VOTAL_KIT_E2E=1)")

P = hook_kit.PATHS["linux"]
PRE = {"session_id": "s", "cwd": "/tmp", "hook_event_name": "PreToolUse",
       "tool_name": "Bash", "tool_input": {"command": "ls"}}
POST = {**PRE, "hook_event_name": "PostToolUse", "tool_response": "result"}
PROMPT = {"session_id": "s", "hook_event_name": "UserPromptSubmit", "prompt": "hi"}


def _hook(payload, *args):
    return subprocess.run(["/bin/sh", P["script"], *args], input=json.dumps(payload).encode(),
                          capture_output=True, timeout=30,
                          env={"PATH": os.environ["PATH"], "HOME": "/tmp", "USER": "runner"})


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    files = hook_kit.build("command", "linux", shield_url="http://127.0.0.1:9",
                           key="rfy_e2e_key_0123456789", agent="claude-code",
                           tenant_id="e2e", tier="regulated")
    script = tmp_path_factory.mktemp("kit") / "install.sh"
    script.write_text(files["install-votal-claude-code.sh"]["content"])
    r = subprocess.run(["sudo", "-n", "sh", str(script)], capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    yield files
    # Exactly what the installer created, never a parent of it.
    targets = [P["dir"], os.path.dirname(P["conf"]), P["managed"]]
    assert targets == ["/opt/votal", "/etc/votal", "/etc/claude-code/managed-settings.json"]
    subprocess.run(["sudo", "-n", "rm", "-rf", *targets], capture_output=True)


def test_installed_files_are_root_owned_and_read_only_to_users(installed):
    for path in (P["conf"], P["script"], P["managed"]):
        st = os.stat(path)
        assert st.st_uid == 0 and not st.st_mode & 0o022, path
    settings = json.load(open(P["managed"]))
    assert set(settings["hooks"]) == set(hook_kit.EVENTS)
    assert settings["allowManagedHooksOnly"] is True


def test_the_hook_runs_managed_and_ignores_config(installed, tmp_path):
    other = tmp_path / "mine.conf"
    other.write_text("SHIELD_URL=https://elsewhere.example\nSHIELD_API_KEY=k\nON_UNREACHABLE=allow\n")
    for args in ((), ("--config", str(other))):
        r = _hook(PRE, *args)
        assert r.returncode == 2 and b"must be https in a managed install" in r.stderr, r.stderr


def test_regulated_withholds_results_and_blocks_prompts(installed):
    r = _hook(POST)
    assert r.returncode == 0 and b"Shield withheld this result" in r.stdout, r
    r = _hook(PROMPT)
    assert r.returncode == 0 and json.loads(r.stdout)["decision"] == "block"


def test_a_group_writable_config_refuses_every_call(installed):
    subprocess.run(["sudo", "-n", "chmod", "664", P["conf"]], check=True)
    try:
        r = _hook(PRE)
        assert r.returncode == 2 and b"must be owned by root" in r.stderr
    finally:
        subprocess.run(["sudo", "-n", "chmod", "644", P["conf"]], check=True)
