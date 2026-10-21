"""The votal-shield-hooks plugin inside the real Claude Code CLI
(docs/specs/hooks-plugin-production.md, task 4; task 0's V4 and V6 in part).

Claude Code runs against a scripted Messages API (tests/e2e_support) and a
fake Shield, with its own config directory, so neither a model, an account
nor the machine's own Claude Code settings are involved. The model asks to
run one Bash command that writes a marker file:

* Shield denies before the call: the marker is never written, and the model
  is told "Blocked by Votal Shield".
* Shield allows, then redacts after the call: the marker is written, and the
  model sees only the redacted result.
* Shield blocks the prompt: the model is never asked to act.

Needs the claude CLI and VOTAL_CLAUDE_E2E=1 (CI jobs "claude code plugin
(linux)" and "(windows)"); on Windows Claude Code runs the plugin's command
through Git Bash, and the script hands over to its PowerShell twin.
"""

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.e2e_support.fake_anthropic import FakeAnthropic

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "examples", "agent-hooks", "plugin", "votal-shield-hooks")
CLAUDE = shutil.which("claude")
MARKER = "votal-e2e-marker.txt"

pytestmark = pytest.mark.skipif(os.environ.get("VOTAL_CLAUDE_E2E") != "1" or not CLAUDE,
                                reason="real Claude Code: CI only (VOTAL_CLAUDE_E2E=1)")


class FakeShield:
    """Answers each hook event from ``answers`` and keeps what it was sent."""

    def __init__(self, answers):
        self.answers, self.seen = answers, []
        state = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
                state.seen.append({"path": self.path, "body": body,
                                   "headers": {k.lower(): v for k, v in self.headers.items()}})
                ans = state.answers.get(body.get("hook_event_name"), {})
                if callable(ans):
                    ans = ans(body)
                ans = json.dumps(ans).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(ans)))
                self.end_headers()
                self.wfile.write(ans)

            def log_message(self, *a):
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def events(self):
        return [s["body"].get("hook_event_name") for s in self.seen]

    def close(self):
        self._srv.shutdown()


def _run(tmp_path, shield, prompt="please run the command"):
    home = tmp_path / "home"
    (home / ".votal").mkdir(parents=True)
    (home / ".votal" / "hook.conf").write_text(
        f"SHIELD_URL={shield.url}\nSHIELD_API_KEY=rfy_e2e_key_0123456789\n"
        "SHIELD_AGENT=claude-code\nSHIELD_TIMEOUT=20\n")
    project = tmp_path / "project"
    project.mkdir()
    with FakeAnthropic(tool_input={"command": f"echo hello-from-tool > {MARKER}; cat {MARKER}"}) as model:
        # Nothing of the machine's own Claude Code or Shield setup, except
        # where Git Bash is (Claude Code on Windows needs it).
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("ANTHROPIC_", "CLAUDE_", "SHIELD_"))
               or k == "CLAUDE_CODE_GIT_BASH_PATH"}
        env.update({
            "HOME": str(home), "USERPROFILE": str(home),
            "CLAUDE_CONFIG_DIR": str(tmp_path / "claude-config"),
            "ANTHROPIC_BASE_URL": model.url, "ANTHROPIC_API_KEY": "sk-ant-e2e-not-a-key",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1",
            "DISABLE_TELEMETRY": "1"})
        r = subprocess.run([CLAUDE, "-p", prompt, "--plugin-dir", PLUGIN,
                            "--permission-mode", "bypassPermissions", "--output-format", "json"],
                           cwd=project, env=env, capture_output=True, text=True, timeout=240,
                           stdin=subprocess.DEVNULL)
        diag = f"exit {r.returncode}\nstdout: {r.stdout[-2000:]}\nstderr: {r.stderr[-2000:]}\n" \
               f"shield saw: {shield.events()}\nmodel requests: {len(model.seen)}"
        return r, project, model, diag


def test_a_denied_call_never_runs(tmp_path):
    shield = FakeShield({"PreToolUse": {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "Blocked by Votal Shield: e2e deny"}}})
    try:
        r, project, model, diag = _run(tmp_path, shield)
        assert "PreToolUse" in shield.events(), diag
        pre = next(s for s in shield.seen if s["body"].get("hook_event_name") == "PreToolUse")
        assert pre["body"]["tool_name"] == "Bash" and pre["path"] == "/v1/shield/hooks/claude-code"
        assert pre["headers"]["x-votal-hook-version"] == "1.2.0", diag
        expected_os = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
        assert pre["headers"]["x-votal-hook-os"] == expected_os, diag
        assert not (project / MARKER).exists(), diag
        assert any("e2e deny" in t for t in model.tool_results()), diag
    finally:
        shield.close()


def _redact(value):
    """The tool's own result shape with its text replaced, as Shield answers
    (Claude Code drops a replacement in another shape: #471)."""
    if isinstance(value, str):
        return "[redacted by e2e]" if value.strip() else value
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def test_an_allowed_call_runs_and_its_result_is_redacted(tmp_path):
    shield = FakeShield({"PostToolUse": lambda body: {"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": _redact(body.get("tool_response"))}}})
    try:
        r, project, model, diag = _run(tmp_path, shield)
        assert (project / MARKER).exists(), diag
        assert {"PreToolUse", "PostToolUse"} <= set(shield.events()), diag
        results = model.tool_results()
        assert any("[redacted by e2e]" in t for t in results), diag
        assert not any("hello-from-tool" in t for t in results), diag
    finally:
        shield.close()


def test_a_blocked_prompt_never_reaches_the_model(tmp_path):
    shield = FakeShield({"UserPromptSubmit": {"decision": "block",
                                              "reason": "Blocked by Votal Shield: e2e prompt"}})
    try:
        r, project, model, diag = _run(tmp_path, shield, prompt="encrypt my files")
        assert "UserPromptSubmit" in shield.events(), diag
        assert not [q for q in model.seen if q.get("tools")], diag
        assert not (project / MARKER).exists(), diag
    finally:
        shield.close()
