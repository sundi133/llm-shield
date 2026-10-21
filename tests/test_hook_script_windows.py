"""The PowerShell hook, run for real (docs/specs/hooks-plugin-production.md, task 1).

Runs wherever PowerShell is installed: pwsh anywhere, and Windows PowerShell 5.1
on Windows. The managed-mode cases need Windows ACLs, so they run on Windows
only; CI runs this file on windows-latest (.github/workflows/test.yml).
Self-contained, with no conftest, so that job needs only pytest.
"""

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PS1 = os.path.join(ROOT, "core", "runtime_policy", "hook_scripts", "claude_code_hook.ps1")
CALL = {"session_id": "s-1", "cwd": "C:\\proj", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "dir"}}
DENY = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                               "permissionDecisionReason": "Blocked by Votal Shield: no"}}
SHELLS = [s for s in (shutil.which("pwsh"), shutil.which("powershell") if os.name == "nt" else None)
          if s]
WINDOWS = os.name == "nt"
MANAGED_LINE = ('$ManagedConf = Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) '
                '"Votal\\hook.conf"')
OWNERS_LINE = '$ManagedOwners = @("S-1-5-32-544", "S-1-5-18",'

pytestmark = pytest.mark.skipif(not SHELLS, reason="needs PowerShell")


@pytest.fixture(params=SHELLS or ["none"])
def shell(request):
    return request.param


@pytest.fixture
def shield():
    state = {"body": b"{}", "seen": []}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            state["seen"].append({k.lower(): v for k, v in self.headers.items()})
            body = state["body"] if isinstance(state["body"], bytes) else json.dumps(state["body"]).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{srv.server_address[1]}"
    yield state
    srv.shutdown()


def _copy(tmp_path, *, managed_conf, current_user_is_owner):
    """The script with its managed path under tmp_path and, optionally, the
    current user added to the managed owners (a test cannot make SYSTEM own
    a file)."""
    src = open(PS1, encoding="utf-8").read()
    assert src.count(MANAGED_LINE) == 1 and src.count(OWNERS_LINE) == 1
    src = src.replace(MANAGED_LINE, f'$ManagedConf = "{managed_conf}"')
    if current_user_is_owner:
        src = src.replace(OWNERS_LINE, '$ManagedOwners = @([System.Security.Principal.WindowsIdentity]'
                                       '::GetCurrent().User.Value, "S-1-5-32-544", "S-1-5-18",')
    p = tmp_path / ("hook-owner.ps1" if current_user_is_owner else "hook.ps1")
    p.write_text(src, encoding="utf-8")
    return str(p)


def _run(shell, script, args):
    return subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-File", script] + args, input=json.dumps(CALL).encode(),
                          capture_output=True, timeout=60)


def _acl(shell, path):
    """The owner and access rules as SIDs, and who runs the test: why a file
    was or was not judged managed."""
    ps = (f"$a = Get-Acl -LiteralPath '{path}'; "
          "$t = [System.Security.Principal.SecurityIdentifier]; "
          "'me=' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
          "'owner=' + $a.GetOwner($t).Value; "
          "$a.GetAccessRules($true, $true, $t) | ForEach-Object { "
          "'' + $_.IdentityReference.Value + ' ' + $_.AccessControlType + ' ' + [int]$_.FileSystemRights }")
    return subprocess.run([shell, "-NoProfile", "-Command", ps], capture_output=True,
                          text=True, timeout=60).stdout


def _grant_everyone_write(path):
    subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(W)"], check=True,
                   capture_output=True)


def test_allow_deny_and_headers(shell, shield, tmp_path):
    conf = tmp_path / "hook.conf"
    conf.write_text(f"SHIELD_URL={shield['url']}\nSHIELD_API_KEY=k\n")
    if WINDOWS:
        _grant_everyone_write(conf)       # not managed, whoever owns it: user mode
    script = _copy(tmp_path, managed_conf=tmp_path / "absent" / "hook.conf",
                   current_user_is_owner=False)
    r = _run(shell, script, ["-Config", str(conf)])
    assert r.returncode == 0, r.stderr
    h = shield["seen"][-1]
    assert h["x-votal-hook-version"] == "1.2.0" and h["x-votal-hook-os"] == "windows"
    assert h["x-votal-hook-mode"] == "user"
    shield["body"] = DENY
    r = _run(shell, script, ["-Config", str(conf)])
    assert r.returncode == 2 and b"Blocked by Votal Shield: no" in r.stderr


@pytest.mark.skipif(not WINDOWS, reason="Windows ACLs")
def test_managed_conf_wins_and_refuses_localhost(shell, shield, tmp_path):
    folder = tmp_path / "managed"
    folder.mkdir()
    managed = folder / "hook.conf"
    managed.write_text(f"SHIELD_URL={shield['url']}\nSHIELD_API_KEY=k\n")
    other = tmp_path / "other.conf"
    other.write_text("SHIELD_URL=https://elsewhere.example\nSHIELD_API_KEY=k\n")
    script = _copy(tmp_path, managed_conf=managed, current_user_is_owner=True)
    r = _run(shell, script, ["-Config", str(other)])
    assert r.returncode == 2 and b"must be https in a managed install" in r.stderr, r.stderr
    assert not shield["seen"]


@pytest.mark.skipif(not WINDOWS, reason="Windows ACLs")
def test_a_managed_conf_others_can_write_refuses_every_call(shell, tmp_path):
    folder = tmp_path / "managed"
    folder.mkdir()
    managed = folder / "hook.conf"
    managed.write_text("SHIELD_URL=https://shield.example\nSHIELD_API_KEY=k\n")
    _grant_everyone_write(managed)
    script = _copy(tmp_path, managed_conf=managed, current_user_is_owner=True)
    r = _run(shell, script, [])
    assert r.returncode == 2 and b"writable by no one else" in r.stderr, r.stderr


@pytest.mark.skipif(not WINDOWS, reason="Windows ACLs")
def test_managed_mode_is_reported(shell, shield, tmp_path):
    folder = tmp_path / "agent"
    folder.mkdir()
    secret = folder / "secret"
    secret.write_text("s" * 40)
    conf = folder / "hook.conf"
    conf.write_text(f"SHIELD_URL={shield['url']}\nSHIELD_LOCAL_SECRET_FILE={secret}\n")
    script = _copy(tmp_path, managed_conf=tmp_path / "absent" / "hook.conf",
                   current_user_is_owner=True)
    r = _run(shell, script, ["-Config", str(conf)])
    assert r.returncode == 0, r.stderr
    assert shield["seen"][-1]["x-votal-hook-mode"] == "managed", _acl(shell, conf)


# ── the plugin's .sh under Git Bash hands over to the .ps1 (task 4) ──

GIT_BASH = next((p for p in (r"C:\Program Files\Git\bin\bash.exe",
                             r"C:\Program Files\Git\usr\bin\bash.exe") if os.path.exists(p)), None)
PLUGIN_SH = os.path.join(ROOT, "examples", "agent-hooks", "plugin", "votal-shield-hooks",
                         "scripts", "claude_code_hook.sh")


@pytest.mark.skipif(not (WINDOWS and GIT_BASH), reason="Git Bash on Windows")
@pytest.mark.parametrize("args", [[], ["--config", "CONF"]])
def test_git_bash_hands_over_to_powershell(shield, tmp_path, args):
    home = tmp_path / "home"
    (home / ".votal").mkdir(parents=True)
    conf = home / ".votal" / "hook.conf"
    conf.write_text(f"SHIELD_URL={shield['url']}\nSHIELD_API_KEY=k1234567\n")
    _grant_everyone_write(conf)                    # a user install, whoever owns it
    args = [str(conf) if a == "CONF" else a for a in args]
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    shield["body"] = DENY
    r = subprocess.run([GIT_BASH, "-c", '/bin/sh "$0" "$@" --target claude-code || exit 2',
                        PLUGIN_SH, *args], input=json.dumps(CALL).encode(),
                       capture_output=True, env=env, timeout=60)
    assert r.returncode == 2 and b"Blocked by Votal Shield: no" in r.stderr, r
    h = shield["seen"][-1]
    assert h["x-votal-hook-os"] == "windows" and h["x-votal-hook-mode"] == "user"
    shield["body"] = b"{}"
    r = subprocess.run([GIT_BASH, "-c", '/bin/sh "$0" "$@" --target claude-code || exit 2',
                        PLUGIN_SH, *args], input=json.dumps(CALL).encode(),
                       capture_output=True, env=env, timeout=60)
    assert r.returncode == 0, r


# ── the kit's installer, run for real (docs/specs/hooks-plugin-production.md task 3) ──
# Writes C:\Program Files\Votal, C:\ProgramData\Votal and C:\Program Files\ClaudeCode,
# so only on a throwaway runner: VOTAL_KIT_E2E=1 in the Windows CI job.

E2E = WINDOWS and os.environ.get("VOTAL_KIT_E2E") == "1"
INSTALLED_FOLDERS = (r"C:\Program Files\Votal", r"C:\ProgramData\Votal",
                     r"C:\Program Files\ClaudeCode")
PROMPT = {"session_id": "s", "hook_event_name": "UserPromptSubmit", "prompt": "hi"}
POST = {**CALL, "hook_event_name": "PostToolUse", "tool_response": "result"}


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    from core.runtime_policy import hook_kit
    files = hook_kit.build("command", "windows", shield_url="http://127.0.0.1:9",
                           key="rfy_e2e_key_0123456789", agent="claude-code",
                           tenant_id="e2e", tier="regulated")
    script = tmp_path_factory.mktemp("kit") / "install.ps1"
    script.write_text(files["install-votal-claude-code.ps1"]["content"], encoding="utf-8")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", str(script)], capture_output=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    yield hook_kit.PATHS["windows"]
    # Leave no managed config behind: it would win over every later test's.
    # Exactly the folders the installer creates, never a parent of one.
    for folder in INSTALLED_FOLDERS:
        assert folder.rstrip("\\").rsplit("\\", 1)[-1] in ("Votal", "ClaudeCode"), folder
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", folder], capture_output=True)


def _installed_hook(shell, paths, payload, *args):
    return subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-File", paths["script"], *args], input=json.dumps(payload).encode(),
                          capture_output=True, timeout=60)


@pytest.mark.skipif(not E2E, reason="real install: Windows CI only (VOTAL_KIT_E2E=1)")
def test_installed_kit_runs_managed(shell, installed, tmp_path):
    other = tmp_path / "mine.conf"
    other.write_text("SHIELD_URL=https://elsewhere.example\nSHIELD_API_KEY=k\nON_UNREACHABLE=allow\n")
    for args in ((), ("-Config", str(other))):
        r = _installed_hook(shell, installed, CALL, *args)
        assert r.returncode == 2 and b"must be https in a managed install" in r.stderr, r.stderr


@pytest.mark.skipif(not E2E, reason="real install: Windows CI only (VOTAL_KIT_E2E=1)")
def test_installed_regulated_kit_withholds_and_blocks(shell, installed):
    r = _installed_hook(shell, installed, POST)
    assert r.returncode == 0 and b"Shield withheld this result" in r.stdout, r
    r = _installed_hook(shell, installed, PROMPT)
    assert r.returncode == 0 and json.loads(r.stdout)["decision"] == "block", r
    settings = json.loads(open(installed["managed"], encoding="utf-8").read())
    assert set(settings["hooks"]) == {"PreToolUse", "PostToolUse", "UserPromptSubmit"}
