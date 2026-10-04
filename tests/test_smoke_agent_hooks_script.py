"""scripts/smoke_agent_hooks.sh decides pass and fail the way it says.

Run against a fake Shield, so the script's own logic is what is tested: a
healthy deploy passes, a deploy without the hook adapter fails, an agent not
turned on yet is skipped rather than failed, and a hook that never denies
fails (the failure the script exists to catch).
"""

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "smoke_agent_hooks.sh")
pytestmark = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("curl")
                                     and shutil.which("python3")),
                                reason="needs bash, curl and python3")


class Fake:
    def __init__(self):
        self.hooks_route = True
        self.profile = "coding-agent-baseline"
        self.denies = True
        self.seen = []


@pytest.fixture
def shield():
    state = Fake()

    class H(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            data = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            state.seen.append(("GET", self.path, dict(self.headers), b""))
            if not self.headers.get("X-API-Key"):
                return self._send(401, {"detail": "no key"})
            if self.path == "/v1/tenant/me/hooks/fleets":
                return self._send(200, {"configured": True, "fleets": [{"fleet": "eng"}]})
            if self.path == "/v1/tenant/me/hooks/claude-code":
                return self._send(200, {"shield_url": "https://shield.example",
                                        "shield_url_source": "SHIELD_PUBLIC_URL",
                                        "status": {"claude_code": {"profile": state.profile}}})
            self._send(404, {"detail": "not found"})

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            state.seen.append(("POST", self.path, dict(self.headers), raw))
            if self.path != "/v1/shield/hooks/claude-code" or not state.hooks_route:
                return self._send(404, {"detail": "not found"})
            if not self.headers.get("X-API-Key"):
                return self._send(401, {"detail": "no key"})
            if not self.headers.get("X-Agent-Key"):
                return self._send(400, {"detail": "X-Agent-Key"})
            try:
                body = json.loads(raw)
            except ValueError:
                return self._send(422, {"detail": "body"})
            cmd = body["tool_input"]["command"]
            if state.denies and state.profile and cmd.startswith("openssl enc"):
                return self._send(200, {"hookSpecificOutput": {
                    "hookEventName": "PreToolUse", "permissionDecision": "deny",
                    "permissionDecisionReason": "Blocked by Votal Shield: command matches "
                                                "denied pattern 'openssl enc*'"}})
            self._send(200, {})

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state.url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield state
    srv.shutdown()


def _run(shield, **env):
    e = {"PATH": os.environ["PATH"], "SHIELD_URL": shield.url, "TENANT_KEY": "sk-smoke", **env}
    return subprocess.run(["bash", SCRIPT], capture_output=True, text=True, env=e, timeout=60)


def test_a_healthy_deploy_passes(shield):
    r = _run(shield)
    assert r.returncode == 0, r.stdout
    assert "Result: 7 passed, 0 failed, 0 skipped" in r.stdout
    assert "denied (Blocked by Votal Shield: command matches denied pattern 'openssl enc*')" in r.stdout
    # Every hook call is tagged so its audit rows are easy to find.
    posts = [h for m, p, h, _b in shield.seen if m == "POST" and h.get("X-API-Key")]
    assert posts and all(h.get("X-Shield-User") == "smoke-check" for h in posts)
    assert all(json.loads(b)["session_id"].startswith("smoke-")
               for m, p, h, b in shield.seen if m == "POST" and b.startswith(b'{"session'))


def test_a_deploy_without_the_hook_route_fails(shield):
    shield.hooks_route = False
    r = _run(shield)
    assert r.returncode == 1 and "hook route missing (404)" in r.stdout


def test_an_agent_not_turned_on_is_skipped_not_failed(shield):
    shield.profile = ""
    r = _run(shield)
    assert r.returncode == 0, r.stdout
    assert "SKIP" in r.stdout and "has no runtime profile" in r.stdout


def test_a_hook_that_never_denies_fails(shield):
    shield.denies = False
    r = _run(shield)
    assert r.returncode == 1 and "expected deny" in r.stdout


def test_a_named_agent_must_enforce(shield):
    shield.denies = False
    r = _run(shield, SMOKE_AGENT="claude-code-eng")
    assert r.returncode == 1 and "agent claude-code-eng's profile" in r.stdout


def test_commands_with_quotes_are_sent_as_valid_json(shield):
    r = _run(shield, DENIED_COMMAND='openssl enc -in "my file.txt" \\ x')
    assert r.returncode == 0, r.stdout
    sent = [json.loads(b) for m, p, h, b in shield.seen
            if m == "POST" and b.startswith(b'{"session') and b"openssl" in b]
    assert sent[0]["tool_input"]["command"] == 'openssl enc -in "my file.txt" \\ x'


def test_needs_url_and_key():
    r = subprocess.run(["bash", SCRIPT], capture_output=True, text=True,
                       env={"PATH": os.environ["PATH"]}, timeout=30)
    assert r.returncode != 0 and "SHIELD_URL" in r.stderr
