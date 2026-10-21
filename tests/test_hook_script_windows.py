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
