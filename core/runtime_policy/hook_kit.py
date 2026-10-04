"""Rollout files for the Claude Code hook adapter: what an admin deploys to
laptops so Claude Code asks Shield before every tool call.
Spec: docs/specs/agent-hook-adapter.md sections 4.2, 4.3 and task 3.

Two variants:
  * http: Claude Code calls Shield directly. Nothing to install; if Shield
    cannot be reached the call goes through (Claude Code's rule).
  * command: Claude Code runs hook_scripts/claude_code_hook.sh (or the
    PowerShell twin), which denies whenever Shield cannot answer.

Pure apart from reading the two hook scripts. The hook key is used to build
the files and never stored.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
import uuid
from typing import Optional

MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Glob|Grep|WebFetch|mcp__.*"
HTTP_TIMEOUT_S = 5
COMMAND_TIMEOUT_S = 10       # the hook's own SHIELD_TIMEOUT (4) must stay below this
SCRIPT_TIMEOUT_S = 4
VARIANTS = ("http", "command")
OSES = ("macos", "linux", "windows")

PATHS = {
    "macos": {"managed": "/Library/Application Support/ClaudeCode/managed-settings.json",
              "dir": "/Library/Application Support/Votal",
              "script": "/Library/Application Support/Votal/claude_code_hook.sh",
              "conf": "/Library/Application Support/Votal/hook.conf", "owner": "root:wheel"},
    "linux": {"managed": "/etc/claude-code/managed-settings.json",
              "dir": "/opt/votal", "script": "/opt/votal/claude_code_hook.sh",
              "conf": "/etc/votal/hook.conf", "owner": "root:root"},
    "windows": {"managed": "C:\\Program Files\\ClaudeCode\\managed-settings.json",
                "dir": "C:\\Program Files\\Votal",
                "script": "C:\\Program Files\\Votal\\claude_code_hook.ps1",
                "conf": "C:\\ProgramData\\Votal\\hook.conf"},
}

# Inside core/ so every image ships them (.dockerignore drops examples/).
_SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook_scripts")
SCRIPT_FILES = {"sh": os.path.join(_SCRIPTS, "claude_code_hook.sh"),
                "ps1": os.path.join(_SCRIPTS, "claude_code_hook.ps1")}
_NS = uuid.UUID("6a0f3c1e-2b7d-4f5e-9a41-c1a7d3e0b2f4")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.:+/=-]{8,256}$")
_AGENT_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,200}$")
_HEREDOC = {"sh": "VOTAL_HOOK_SCRIPT_EOF", "conf": "VOTAL_HOOK_CONF_EOF",
            "settings": "VOTAL_MANAGED_SETTINGS_EOF"}


class KitError(ValueError):
    """``errors`` lists every problem, one per field."""

    def __init__(self, errors):
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


def check_inputs(*, shield_url: str, key: str, agent: str, variant: str, os_name: str) -> None:
    errors = []
    if variant not in VARIANTS:
        errors.append(f"variant: one of {', '.join(VARIANTS)}")
    if os_name not in OSES:
        errors.append(f"os: one of {', '.join(OSES)}")
    if not isinstance(shield_url, str) or not (
            re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?$", shield_url)
            or re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/?$", shield_url)):
        errors.append("shield_url: an https URL of the Shield data plane, such as "
                      "https://api.guardrails.votal.ai")
    if not isinstance(key, str) or not _KEY_RE.match(key):
        errors.append("hook_key: the tenant key the laptops will use (8 to 256 characters, "
                      "no spaces or quotes); a key with the runtime scope is best")
    if not isinstance(agent, str) or not _AGENT_RE.match(agent):
        errors.append("agent: the registered agent id, for example claude-code")
    if errors:
        raise KitError(errors)


def _hook_entry(variant: str, os_name: str, shield_url: str, key: str, agent: str) -> dict:
    if variant == "http":
        return {"type": "http",
                "url": shield_url.rstrip("/") + "/v1/shield/hooks/claude-code",
                "headers": {"X-API-Key": key, "X-Agent-Key": agent,
                            "X-Shield-User": "$USERNAME" if os_name == "windows" else "$USER"},
                "allowedEnvVars": ["USERNAME" if os_name == "windows" else "USER"],
                "timeout": HTTP_TIMEOUT_S}
    script = PATHS[os_name]["script"]
    if os_name == "windows":
        command = (f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass '
                   f'-File "{script}" || exit 2')
    else:
        command = f"/bin/sh '{script}' || exit 2"
    return {"type": "command", "command": command, "timeout": COMMAND_TIMEOUT_S}


def managed_settings(variant: str, os_name: str, *, shield_url: str, key: str,
                     agent: str) -> dict:
    """The managed-settings.json content (or the keys of the MDM profile)."""
    return {"hooks": {"PreToolUse": [{"matcher": MATCHER, "hooks": [
                _hook_entry(variant, os_name, shield_url, key, agent)]}]},
            "allowManagedHooksOnly": True}


def hook_conf(*, shield_url: str, key: str, agent: str) -> str:
    return ("# Votal Shield hook for Claude Code. Root-owned; read by claude_code_hook.\n"
            f"SHIELD_URL={shield_url.rstrip('/')}\nSHIELD_API_KEY={key}\n"
            f"SHIELD_AGENT={agent}\nSHIELD_TIMEOUT={SCRIPT_TIMEOUT_S}\n")


def mobileconfig(settings: dict, *, tenant_id: str, agent: str) -> bytes:
    """A macOS configuration profile for the com.anthropic.claudecode
    preference domain, carrying the managed settings."""
    ident = f"ai.votal.claude-code-hook.{re.sub(r'[^A-Za-z0-9.-]', '-', tenant_id)}"
    seed = f"{tenant_id}|{agent}|{json.dumps(settings, sort_keys=True)}"
    inner = {"PayloadType": "com.anthropic.claudecode", "PayloadVersion": 1,
             "PayloadIdentifier": f"{ident}.settings",
             "PayloadUUID": str(uuid.uuid5(_NS, seed + "|settings")).upper(),
             "PayloadDisplayName": "Claude Code managed settings (Votal Shield)",
             **settings}
    return plistlib.dumps({
        "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadScope": "System",
        "PayloadIdentifier": ident, "PayloadUUID": str(uuid.uuid5(_NS, seed)).upper(),
        "PayloadDisplayName": "Votal Shield for Claude Code",
        "PayloadDescription": "Claude Code asks Votal Shield before running commands, "
                              "writing files or fetching URLs.",
        "PayloadOrganization": "Votal Shield", "PayloadContent": [inner]})


def _script(kind: str) -> str:
    with open(SCRIPT_FILES[kind], encoding="utf-8") as f:
        return f.read()


def install_script(variant: str, os_name: str, *, shield_url: str, key: str, agent: str) -> str:
    """A root install script for macOS or Linux (run by MDM). Writes the hook
    and its config (command variant) and the managed settings, refusing to
    overwrite managed settings that say something else."""
    if os_name not in ("macos", "linux"):
        raise KitError("install script: macOS or Linux; on Windows deploy the files listed "
                       "in the guide")
    p = PATHS[os_name]
    settings = json.dumps(managed_settings(variant, os_name, shield_url=shield_url, key=key,
                                           agent=agent), indent=2)
    parts = {"settings": settings}
    if variant == "command":
        parts["sh"] = _script("sh")
        parts["conf"] = hook_conf(shield_url=shield_url, key=key, agent=agent)
    for name, text in parts.items():
        if any(line.strip() == _HEREDOC[name] for line in text.splitlines()):
            raise KitError(f"{name}: contains the installer's delimiter")
    conf_dir = os.path.dirname(p["conf"])
    managed_dir = os.path.dirname(p["managed"])
    lines = [
        "#!/bin/sh",
        "# Votal Shield for Claude Code: installer. Run as root (for example by MDM).",
        f"# Variant: {variant}. Docs: docs/claude-code-runtime-guardrails.md",
        "# VOTAL_INSTALL_ROOT prefixes every path (for testing); leave it unset.",
        "set -eu",
        'R="${VOTAL_INSTALL_ROOT:-}"',
        'if [ -z "$R" ] && [ "$(id -u)" != 0 ]; then echo "run as root" >&2; exit 1; fi',
        "umask 022",
    ]
    if variant == "command":
        lines += [
            f'mkdir -p "$R{p["dir"]}" "$R{conf_dir}"',
            f"cat > \"$R{p['script']}.new\" <<'{_HEREDOC['sh']}'",
            parts["sh"].rstrip("\n"), _HEREDOC["sh"],
            f"cat > \"$R{p['conf']}.new\" <<'{_HEREDOC['conf']}'",
            parts["conf"].rstrip("\n"), _HEREDOC["conf"],
            f'chmod 755 "$R{p["script"]}.new"; chmod 644 "$R{p["conf"]}.new"',
            f'[ -n "$R" ] || chown {p["owner"]} "{p["script"]}.new" "{p["conf"]}.new"',
            f'mv -f "$R{p["script"]}.new" "$R{p["script"]}"',
            f'mv -f "$R{p["conf"]}.new" "$R{p["conf"]}"',
        ]
    # A checksum of the settings this installer wrote, so a rerun (a new key,
    # the other variant) replaces its own file but never someone else's.
    lines += [
        f'mkdir -p "$R{managed_dir}" "$R{p["dir"]}"',
        f"cat > \"$R{p['managed']}.votal\" <<'{_HEREDOC['settings']}'",
        settings, _HEREDOC["settings"],
        f'M="$R{p["managed"]}"',
        f'MARK="$R{p["dir"]}/managed-settings.cksum"',
        'if [ -f "$M" ] && ! cmp -s "$M" "$M.votal"; then',
        '  if [ ! -f "$MARK" ] || [ "$(cksum < "$M")" != "$(cat "$MARK")" ]; then',
        '    echo "Claude Code managed settings already exist at $M with other content." >&2',
        '    echo "Not overwritten. Merge the hooks and allowManagedHooksOnly keys from $M.votal into it." >&2',
        "    exit 3",
        "  fi",
        "fi",
        'chmod 644 "$M.votal"',
        f'[ -n "$R" ] || chown {p["owner"]} "$M.votal"',
        'mv -f "$M.votal" "$M"',
        'cksum < "$M" > "$MARK"',
        'echo "Votal Shield hook for Claude Code installed. Restart Claude Code sessions."',
        "",
    ]
    return "\n".join(lines)


def build(variant: str, os_name: str, *, shield_url: str, key: str, agent: str,
          tenant_id: str) -> dict:
    """Every file an admin may need, as {name: {"content", "path", "mime"}}."""
    check_inputs(shield_url=shield_url, key=key, agent=agent, variant=variant, os_name=os_name)
    settings = managed_settings(variant, os_name, shield_url=shield_url, key=key, agent=agent)
    files = {"managed-settings.json": {"content": json.dumps(settings, indent=2) + "\n",
                                       "path": PATHS[os_name]["managed"],
                                       "mime": "application/json"}}
    if os_name == "macos":
        files["votal-claude-code.mobileconfig"] = {
            "content": mobileconfig(settings, tenant_id=tenant_id, agent=agent).decode(),
            "path": "", "mime": "application/x-apple-aspen-config"}
    if os_name in ("macos", "linux"):
        files["install-votal-claude-code.sh"] = {
            "content": install_script(variant, os_name, shield_url=shield_url, key=key,
                                      agent=agent),
            "path": "", "mime": "text/x-shellscript"}
    if variant == "command":
        files["hook.conf"] = {"content": hook_conf(shield_url=shield_url, key=key, agent=agent),
                              "path": PATHS[os_name]["conf"], "mime": "text/plain"}
        kind = "ps1" if os_name == "windows" else "sh"
        files[os.path.basename(SCRIPT_FILES[kind])] = {
            "content": _script(kind), "path": PATHS[os_name]["script"], "mime": "text/plain"}
    return files


def public_url(request_base: Optional[str] = None) -> str:
    """The data-plane URL laptops should call: SHIELD_PUBLIC_URL, else the
    caller's own base URL."""
    url = (os.getenv("SHIELD_PUBLIC_URL") or "").strip() or (request_base or "")
    return url.rstrip("/")


__all__ = ["COMMAND_TIMEOUT_S", "KitError", "MATCHER", "OSES", "PATHS", "SCRIPT_FILES",
           "VARIANTS", "build", "check_inputs", "hook_conf", "install_script",
           "managed_settings", "mobileconfig", "public_url"]
