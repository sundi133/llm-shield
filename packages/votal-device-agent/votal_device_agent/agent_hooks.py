"""Coding-agent hooks on this laptop: the fleet's `agent_hooks` setting from
the signed bundle, applied to Claude Code. Spec:
docs/specs/claude-code-fleet-rollout.md section 4.5.

On every bundle the agent trusts, apply() makes the laptop match the fleet:

  * monitor or enforce: write the hook script and hook.conf into the agent's
    hooks folder, and Claude Code's managed settings with a command hook that
    runs the script. The script asks this agent on 127.0.0.1 (local secret),
    which asks Shield with the device key (agent.claude_code_hook).
  * off, after having been on: rewrite the managed settings to {} instead of
    deleting them. A running Claude Code session follows edits to a settings
    file that exists but ignores one that appears mid-session (task 0), so
    keeping the file lets later switches reach running sessions.
  * off, never on: write nothing.

The settings content does not depend on monitor or enforce (the server decides
that per call) nor on on_unreachable (hook.conf, read per call), so a mode
change rewrites at most hook.conf.

Never overwrites a managed settings file it did not write: the checksum of
what it wrote is kept in the state folder, and any other content is reported
as `conflict` and left alone, including a file of ours edited by hand.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from votal_device_agent import hook_scripts

CLAUDE_CODE = "claude_code"
HOOK_VERSION = "1"
#: The same matcher the portal's rollout files use (core/runtime_policy/hook_kit.py).
MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Glob|Grep|WebFetch|mcp__.*"
HOOK_TIMEOUT_S = 10          # Claude Code's limit for the hook
SCRIPT_TIMEOUT_S = 4         # the script's own limit: below the hook's (agent-hook-adapter 4.3)
STATE_FILE = "agent_hooks.json"
ON_MODES = ("monitor", "enforce")


@dataclass(frozen=True)
class HookPaths:
    managed_settings: Path     # Claude Code's managed-settings.json
    hooks_dir: Path            # the hook script and hook.conf; root/SYSTEM-owned, user-readable


def default_paths(os_name: str, install_dir: Path) -> HookPaths:
    if os_name == "macos":
        return HookPaths(Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
                         install_dir / "hooks")
    if os_name == "windows":
        prog = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        return HookPaths(prog / "ClaudeCode" / "managed-settings.json", install_dir / "hooks")
    return HookPaths(Path("/etc/claude-code/managed-settings.json"), install_dir / "hooks")


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write(path: Path, text: str, mode: int) -> None:
    """Atomic: a reader sees the old file or the new one, never half."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".votal-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class AgentHooks:
    def __init__(self, paths: HookPaths, state_dir: str | Path, *, local_port: int,
                 os_name: str):
        self.paths, self.local_port, self.os_name = paths, local_port, os_name
        self.state_path = Path(state_dir) / STATE_FILE
        self.secret_path = Path(state_dir) / "local_secret"
        self.report: dict = {}          # what the heartbeat sends: {coding_agent: state}

    # ── what we wrote before ────────────────────────────────────────

    def _load(self) -> dict:
        try:
            data = json.loads(self.state_path.read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        _write(self.state_path, json.dumps(data, sort_keys=True), 0o600)

    # ── the files ───────────────────────────────────────────────────

    @property
    def script_path(self) -> Path:
        name = "claude_code_hook.ps1" if self.os_name == "windows" else "claude_code_hook.sh"
        return self.paths.hooks_dir / name

    @property
    def conf_path(self) -> Path:
        return self.paths.hooks_dir / "hook.conf"

    def hook_command(self) -> str:
        if self.os_name == "windows":
            # How Claude Code runs a command hook on Windows is task 0's open
            # check; "|| exit 2" assumes a shell that has it.
            return (f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '
                    f'"{self.script_path}" -Config "{self.conf_path}" || exit 2')
        return f"/bin/sh '{self.script_path}' --config '{self.conf_path}' || exit 2"

    def settings_text(self) -> str:
        settings = {"hooks": {"PreToolUse": [{"matcher": MATCHER, "hooks": [
                        {"type": "command", "command": self.hook_command(),
                         "timeout": HOOK_TIMEOUT_S}]}]},
                    "allowManagedHooksOnly": True}
        return json.dumps(settings, indent=2) + "\n"

    def conf_text(self, on_unreachable: str) -> str:
        return ("# Written by the Votal device agent. Read by claude_code_hook on each call.\n"
                f"SHIELD_URL=http://127.0.0.1:{self.local_port}\n"
                f"SHIELD_LOCAL_SECRET_FILE={self.secret_path}\n"
                f"ON_UNREACHABLE={'allow' if on_unreachable == 'allow' else 'deny'}\n"
                f"SHIELD_TIMEOUT={SCRIPT_TIMEOUT_S}\n")

    def _grant_users_read(self) -> None:
        if self.os_name == "windows":
            # The agent's folders admit SYSTEM and Administrators only; Claude
            # Code runs the hook as the signed-in user.
            import subprocess
            try:
                subprocess.run(["icacls", str(self.paths.hooks_dir), "/grant",
                                "*S-1-5-32-545:(OI)(CI)RX"], capture_output=True)
            except OSError:
                pass        # no icacls (not Windows): nothing to grant

    def _managed(self, text: str, mine: dict) -> tuple[str, str]:
        """Write Claude Code's managed settings unless someone else owns them.
        Returns (state, reason)."""
        path = self.paths.managed_settings
        current = None
        try:
            current = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            pass
        if current is not None and current != text and _sha(current) != mine.get("settings_sha"):
            return "conflict", (f"{path} has content this agent did not write; merge the hooks "
                                f"block shown in the portal")
        if current != text:
            _write(path, text, 0o644)
        mine["settings_sha"] = _sha(text)
        return "", ""

    # ── apply ───────────────────────────────────────────────────────

    def apply(self, setting: Optional[dict]) -> dict:
        """Make this laptop match the fleet's resolved agent_hooks setting
        ({"agents", "mode", "on_unreachable"} or None). Returns the report."""
        data = self._load()
        mine = data.setdefault(CLAUDE_CODE, {})
        on = bool(setting) and setting.get("mode") in ON_MODES and \
            CLAUDE_CODE in (setting.get("agents") or {})
        try:
            if on:
                self.paths.hooks_dir.mkdir(parents=True, exist_ok=True)
                script = (hook_scripts.CLAUDE_CODE_HOOK_PS1 if self.os_name == "windows"
                          else hook_scripts.CLAUDE_CODE_HOOK_SH)
                for path, text, mode in ((self.script_path, script, 0o755),
                                         (self.conf_path, self.conf_text(
                                             setting.get("on_unreachable", "allow")), 0o644)):
                    try:
                        same = path.read_text(encoding="utf-8") == text
                    except OSError:
                        same = False
                    if not same:
                        _write(path, text, mode)
                os.chmod(self.paths.hooks_dir, 0o755)
                self._grant_users_read()
                text = self.settings_text()
                state, reason = self._managed(text, mine)
                if not state:
                    mine["ever_on"] = True
                    state = "active"
            elif mine.get("ever_on"):
                state, reason = self._managed("{}\n", mine)
                state = state or "off"
            else:
                state, reason = "off", ""
        except OSError as e:
            state, reason = "error", f"{type(e).__name__}: {e}"[:200]
        report = {"state": state, "hook_version": HOOK_VERSION}
        if mine.get("settings_sha") and state in ("active", "off"):
            report["settings_hash"] = mine["settings_sha"]
        if reason:
            report["reason"] = reason[:200]
        try:
            self._save(data)
        except OSError:
            pass
        self.report = {CLAUDE_CODE: report}
        return self.report


__all__ = ["AgentHooks", "CLAUDE_CODE", "HookPaths", "MATCHER", "default_paths"]
