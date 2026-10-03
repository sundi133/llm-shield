"""Coding-agent hook adapter, task 2: the fail-closed command hook.
Spec: docs/specs/agent-hook-adapter.md, section 4.3.

Claude Code lets a tool call through when a command hook exits with anything
other than 2 (task 0), so every failure must end in exit 2. The script runs
for real here, under sh and (where installed) dash, against a local server
that plays Shield.
"""

import json
import os
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, "core", "runtime_policy", "hook_scripts", "claude_code_hook.sh")
PS1 = os.path.join(ROOT, "core", "runtime_policy", "hook_scripts", "claude_code_hook.ps1")
SHELLS = [s for s in ("/bin/sh", shutil.which("dash")) if s and os.path.exists(s)]
CALL = {"session_id": "s-1", "cwd": "/Users/dev/proj", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "openssl enc -in a"}, "tool_use_id": "t1"}
DENY = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                               "permissionDecisionReason": "Blocked by Votal Shield: command "
                                                           "matches denied pattern 'openssl enc*'"}}
ASK = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                              "permissionDecisionReason": "Votal Shield: command matches pattern "
                                                          "'git push*', which needs your confirmation"}}

pytestmark = pytest.mark.skipif(not shutil.which("curl") or not SHELLS,
                                reason="needs sh and curl")


class Shield:
    """What the fake Shield answers next, and what it was sent."""

    def __init__(self):
        self.status, self.body, self.delay = 200, b"{}", 0.0
        self.seen = []


@pytest.fixture
def shield():
    state = Shield()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("content-length", 0)))
            state.seen.append({"path": self.path, "headers": dict(self.headers), "body": raw})
            time.sleep(state.delay)
            body = state.body if isinstance(state.body, bytes) else json.dumps(state.body).encode()
            self.send_response(state.status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state.url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield state
    srv.shutdown()


def _conf(tmp_path, text):
    p = tmp_path / "hook.conf"
    p.write_text(text)
    return str(p)


def _run(conf, shell=SHELLS[0], payload=CALL, env=None, args=None):
    e = {"PATH": os.environ["PATH"], "USER": "dev", "TMPDIR": os.environ.get("TMPDIR", "/tmp")}
    e.update(env or {})
    return subprocess.run([shell, HOOK] + (args if args is not None else ["--config", conf]),
                          input=json.dumps(payload).encode(), capture_output=True,
                          env=e, timeout=40)


def _ok_conf(tmp_path, shield, extra=""):
    return _conf(tmp_path, f"# Votal hook\nSHIELD_URL={shield.url}/\n"
                           f"SHIELD_API_KEY = \"sk-test-key\"\nSHIELD_TIMEOUT=3\n{extra}")


@pytest.mark.parametrize("shell", SHELLS)
def test_allow_deny_ask(shell, shield, tmp_path):
    conf = _ok_conf(tmp_path, shield)
    r = _run(conf, shell)
    assert (r.returncode, r.stdout, r.stderr) == (0, b"", b"")

    shield.body = DENY
    r = _run(conf, shell)
    assert r.returncode == 2 and r.stdout == b""
    assert r.stderr.decode() == ("Blocked by Votal Shield: command matches denied pattern "
                                 "'openssl enc*'\n")

    shield.body = ASK
    r = _run(conf, shell)
    assert r.returncode == 0
    assert json.loads(r.stdout) == ASK


@pytest.mark.parametrize("shell", SHELLS)
def test_what_shield_is_sent(shell, shield, tmp_path):
    _run(_ok_conf(tmp_path, shield, "SHIELD_AGENT=claude-code-eng\n"), shell)
    sent = shield.seen[-1]
    h = {k.lower(): v for k, v in sent["headers"].items()}
    assert sent["path"] == "/v1/shield/hooks/claude-code"
    assert json.loads(sent["body"]) == CALL              # the hook input, unchanged
    assert h["x-api-key"] == "sk-test-key" and h["x-agent-key"] == "claude-code-eng"
    assert h["x-shield-user"] == "dev" and h["x-device-id"]
    assert h["content-type"] == "application/json"


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("status, body, needle", [
    (500, b"boom", "HTTP 500"),
    (401, b'{"detail":"no key"}', "HTTP 401"),
    (404, b"{}", "HTTP 404"),
    (200, b"not json", "not understood"),
    (200, b"", "not understood"),
    (200, b'{"hookSpecificOutput":{"permissionDecision":"allow"}}', "not understood"),
    (200, b'{"unexpected": true}', "not understood"),
])
def test_every_bad_answer_denies(shell, shield, tmp_path, status, body, needle):
    shield.status, shield.body = status, body
    r = _run(_ok_conf(tmp_path, shield), shell)
    assert r.returncode == 2 and needle in r.stderr.decode(), r.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_unreachable_and_slow_shield_deny(shell, shield, tmp_path):
    r = _run(_conf(tmp_path, "SHIELD_URL=http://127.0.0.1:9\nSHIELD_API_KEY=k\n"), shell)
    assert r.returncode == 2 and "could not be reached" in r.stderr.decode()
    shield.delay = 5
    t = time.monotonic()
    r = _run(_conf(tmp_path, f"SHIELD_URL={shield.url}\nSHIELD_API_KEY=k\nSHIELD_TIMEOUT=1\n"), shell)
    assert r.returncode == 2 and "could not be reached" in r.stderr.decode()
    assert time.monotonic() - t < 4


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("text, needle", [
    (None, "missing or unreadable"),
    ("SHIELD_API_KEY=k\n", "SHIELD_URL is not set"),
    ("SHIELD_URL=https://shield.example\n", "SHIELD_API_KEY is not set"),
    ("SHIELD_URL=http://shield.example\nSHIELD_API_KEY=k\n", "must be https"),
    ("SHIELD_URL=http://127.0.0.1.evil.example\nSHIELD_API_KEY=k\n", "must be https"),
    ("SHIELD_URL=http://localhost.evil.example/\nSHIELD_API_KEY=k\n", "must be https"),
])
def test_bad_config_denies(shell, tmp_path, text, needle):
    conf = _conf(tmp_path, text) if text is not None else str(tmp_path / "absent.conf")
    r = _run(conf, shell)
    assert r.returncode == 2 and needle in r.stderr.decode(), r.stderr


def test_default_config_location_is_not_the_environment(tmp_path):
    """No --config: the root-owned default path. Nothing in the environment
    can point the hook at another Shield."""
    r = _run(None, args=[], env={"SHIELD_URL": "http://127.0.0.1:1", "SHIELD_API_KEY": "k",
                                 "VOTAL_HOOK_CONF": str(tmp_path / "x")})
    if os.path.exists("/Library/Application Support/Votal/hook.conf") or \
            os.path.exists("/etc/votal/hook.conf"):
        pytest.skip("a real hook config is installed on this machine")
    assert r.returncode == 2 and "hook config" in r.stderr.decode()


def test_config_is_parsed_not_executed(shield, tmp_path):
    marker = tmp_path / "pwned"
    conf = _conf(tmp_path, f"SHIELD_URL={shield.url}\nSHIELD_API_KEY=$(touch {marker})\n"
                           f"touch {marker}\n`touch {marker}`=1\r\n")
    r = _run(conf)
    assert r.returncode == 0 and not marker.exists()
    assert {k.lower(): v for k, v in shield.seen[-1]["headers"].items()}["x-api-key"] == \
        f"$(touch {marker})"


def test_without_curl_it_denies(shield, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("sed", "tr", "mktemp", "uname", "rm", "chmod", "cut", "id", "hostname", "cat"):
        path = shutil.which(tool)
        if path:
            os.symlink(path, bin_dir / tool)
    r = _run(_ok_conf(tmp_path, shield), env={"PATH": str(bin_dir)})
    assert r.returncode == 2 and "curl is not installed" in r.stderr.decode()


def test_reasons_with_quotes_stay_valid_json(shield, tmp_path):
    shield.body = {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "ask",
        "permissionDecisionReason": 'pattern "rm *" \\ needs\tyour\nconfirmation %s'}}
    r = _run(_ok_conf(tmp_path, shield))
    assert r.returncode == 0
    reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason == "pattern 'rm *'  needs your confirmation %s"


def test_the_key_is_not_on_the_command_line(shield, tmp_path):
    """curl reads the headers from a private file, so ps never shows the key."""
    shield.delay = 1.5
    conf = _ok_conf(tmp_path, shield)
    proc = subprocess.Popen(["/bin/sh", HOOK, "--config", conf], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdin.write(json.dumps(CALL).encode())
    proc.stdin.close()
    time.sleep(0.7)
    ps = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
    proc.wait(timeout=10)
    assert "curl" in ps and "sk-test-key" not in ps
    assert not list(tmp_path.glob("votal-hook.*"))


def test_powershell_twin_has_the_same_rules():
    """The Windows hook cannot run in CI; hold it to the same contract by
    reading it: every exit is 2 except allow and ask, which exit 0."""
    src = open(PS1).read()
    exits = [l.strip() for l in src.splitlines() if "exit " in l and not l.lstrip().startswith("#")]
    assert {e.split("exit ")[1].split()[0].strip("}") for e in exits} == {"0", "2"}
    assert sum("exit 0" in e for e in exits) == 2       # {} and ask
    assert "trap {" in src and '$ErrorActionPreference = "Stop"' in src
    assert "$env:SHIELD" not in src                     # config file only
    assert "/v1/shield/hooks/claude-code" in src
    assert "-TimeoutSec $timeout" in src


@pytest.mark.skipif(not shutil.which("pwsh"), reason="needs PowerShell")
def test_powershell_twin_runs(shield, tmp_path):
    conf = _ok_conf(tmp_path, shield)

    def run():
        return subprocess.run(["pwsh", "-NoProfile", "-File", PS1, "-Config", conf],
                              input=json.dumps(CALL).encode(), capture_output=True, timeout=40)

    assert run().returncode == 0
    shield.body = DENY
    r = run()
    assert r.returncode == 2 and b"openssl enc*" in r.stderr
    shield.body = ASK
    assert json.loads(run().stdout) == ASK
    shield.status, shield.body = 500, b"x"
    assert run().returncode == 2
