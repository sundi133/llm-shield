"""Rollout files for the Claude Code hook adapter: what an admin deploys to
laptops so Claude Code asks Shield before every tool call.
Spec: docs/specs/agent-hook-adapter.md sections 4.2, 4.3 and task 3.

Two variants:
  * http: Claude Code calls Shield directly. Nothing to install; if Shield
    cannot be reached the call goes through (Claude Code's rule).
  * command: Claude Code runs hook_scripts/claude_code_hook.sh (or the
    PowerShell twin), which denies whenever Shield cannot answer.

Two tiers (docs/specs/hooks-plugin-production.md section 5): standard, and
regulated, whose hook.conf also withholds results and blocks prompts when
Shield cannot answer. Regulated needs the command variant: an HTTP hook
cannot fail closed.

Every variant registers all three events, before a call, after it and on
the prompt; the agent's runtime profile decides which of them check anything.

Pure apart from reading the two hook scripts. The hook key is used to build
the files and never stored.
"""

from __future__ import annotations

import json
import ntpath
import os
import plistlib
import re
import uuid
from typing import Optional

MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Glob|Grep|WebFetch|mcp__.*"
POST_MATCHER = "Bash|Read|Grep|WebFetch|mcp__.*"   # the plugin's: tools whose results are read
# The plugin's timeouts. Rules judged by Shield's model take seconds (4 s
# would deny them all), so the script waits 25 s and Claude Code 30 s.
HTTP_TIMEOUT_S = 30
COMMAND_TIMEOUT_S = 30       # the hook's own SHIELD_TIMEOUT must stay below this
SCRIPT_TIMEOUT_S = 25
VARIANTS = ("http", "command")
OSES = ("macos", "linux", "windows")
TIERS = ("standard", "regulated")
EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit")

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
# Well-known SIDs for the Windows installer's ACLs: SYSTEM, Administrators, Users.
_WIN_SYSTEM, _WIN_ADMINS, _WIN_USERS = "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"


def valid_key(key: str) -> bool:
    return isinstance(key, str) and bool(_KEY_RE.match(key))


class KitError(ValueError):
    """``errors`` lists every problem, one per field."""

    def __init__(self, errors):
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


def check_inputs(*, shield_url: str, key: str, agent: str, variant: str, os_name: str,
                 tier: str = "standard") -> None:
    errors = []
    if tier not in TIERS:
        errors.append(f"tier: one of {', '.join(TIERS)}")
    elif tier == "regulated" and variant == "http":
        errors.append("tier: regulated needs the fail-closed hook (variant command); "
                      "an HTTP hook lets calls through when Shield cannot be reached")
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


def _hook_entry(variant: str, os_name: str, shield_url: str, key: str, agent: str,
                event: str = "PreToolUse") -> dict:
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
                   f'-File "{script}"')
    else:
        command = f"/bin/sh '{script}'"
    # Before a call, a missing or unrunnable script must deny: Claude Code runs
    # the call on any exit but 2. After a call and on a prompt the script
    # decides what a failure means itself (ON_UNREACHABLE_RESULT / _PROMPT).
    if event == "PreToolUse":
        command += " || exit 2"
    return {"type": "command", "command": command, "timeout": COMMAND_TIMEOUT_S}


def managed_settings(variant: str, os_name: str, *, shield_url: str, key: str,
                     agent: str) -> dict:
    """The managed-settings.json content (or the keys of the MDM profile)."""
    def entry(event):
        return _hook_entry(variant, os_name, shield_url, key, agent, event)
    return {"hooks": {
                "PreToolUse": [{"matcher": MATCHER, "hooks": [entry("PreToolUse")]}],
                "PostToolUse": [{"matcher": POST_MATCHER, "hooks": [entry("PostToolUse")]}],
                "UserPromptSubmit": [{"hooks": [entry("UserPromptSubmit")]}]},
            "allowManagedHooksOnly": True}


def hook_conf(*, shield_url: str, key: str, agent: str, tier: str = "standard") -> str:
    text = ("# Votal Shield hook for Claude Code. Root-owned; read by claude_code_hook.\n"
            f"SHIELD_URL={shield_url.rstrip('/')}\nSHIELD_API_KEY={key}\n"
            f"SHIELD_AGENT={agent}\nSHIELD_TIMEOUT={SCRIPT_TIMEOUT_S}\n"
            "# When Shield cannot answer: before a call, deny.\n"
            "ON_UNREACHABLE=deny\n")
    if tier == "regulated":
        text += ("# Regulated tier: after a call, withhold the result; a prompt is blocked.\n"
                 "ON_UNREACHABLE_RESULT=withhold\nON_UNREACHABLE_PROMPT=block\n")
    return text


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


def install_script(variant: str, os_name: str, *, shield_url: str, key: str, agent: str,
                   tier: str = "standard") -> str:
    """A root install script for macOS or Linux (run by MDM). Writes the hook
    and its config (command variant) and the managed settings, refusing to
    overwrite managed settings that say something else."""
    if os_name not in ("macos", "linux"):
        raise KitError("install script: macOS or Linux; Windows has install_script_windows")
    p = PATHS[os_name]
    settings = json.dumps(managed_settings(variant, os_name, shield_url=shield_url, key=key,
                                           agent=agent), indent=2)
    parts = {"settings": settings}
    if variant == "command":
        parts["sh"] = _script("sh")
        parts["conf"] = hook_conf(shield_url=shield_url, key=key, agent=agent, tier=tier)
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


def _ps_literal(text: str, what: str) -> str:
    """A PowerShell single-quoted here-string. Its only terminator is a line
    starting with '@, so content holding one is refused."""
    if any(line.startswith("'@") for line in text.splitlines()):
        raise KitError(f"{what}: contains the installer's delimiter")
    return "@'\n" + text.rstrip("\n") + "\n'@"


def install_script_windows(variant: str, *, shield_url: str, key: str, agent: str,
                           tier: str = "standard") -> str:
    """An administrator install script for Windows (run by MDM, for example
    Intune). Writes the hook and its config (command variant) with the ACLs
    the hook's managed check requires: owner Administrators, inheritance off,
    SYSTEM and Administrators full control, Users read only. Writes the
    managed settings, refusing to overwrite ones someone else wrote.
    -Root prefixes every path, for testing; leave it unset."""
    p = PATHS["windows"]
    settings = json.dumps(managed_settings(variant, "windows", shield_url=shield_url, key=key,
                                           agent=agent), indent=2)
    acl = (f'"*{_WIN_SYSTEM}:(OI)(CI)F" "*{_WIN_ADMINS}:(OI)(CI)F" "*{_WIN_USERS}:(OI)(CI)RX"')
    lines = [
        "# Votal Shield for Claude Code: installer for Windows. Run as an administrator",
        f"# (for example by Intune). Variant: {variant}, tier: {tier}.",
        "param([string]$Root = \"\")",
        "$ErrorActionPreference = \"Stop\"",
        "$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())",
        "if (-not $Root -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
        "    [Console]::Error.WriteLine(\"run as an administrator\"); exit 1 }",
        "# A path, under -Root without its drive when testing.",
        "function P([string]$Path) { if ($Root) { Join-Path $Root $Path.Substring(3) } else { $Path } }",
        "function Lock-Folder([string]$Dir) {",
        "    New-Item -ItemType Directory -Force -Path $Dir | Out-Null",
        f"    & icacls.exe $Dir /inheritance:r /grant:r {acl} | Out-Null",
        "    if ($LASTEXITCODE -ne 0) { throw \"icacls failed on $Dir\" }",
        f"    & icacls.exe $Dir /setowner \"*{_WIN_ADMINS}\" /T /C | Out-Null",
        "}",
        "function Write-Locked([string]$Path, [string]$Text) {",
        "    [IO.File]::WriteAllText(\"$Path.new\", $Text.Replace(\"`r`n\", \"`n\"), (New-Object Text.UTF8Encoding $false))",
        "    Move-Item -Force -LiteralPath \"$Path.new\" -Destination $Path",
        f"    & icacls.exe $Path /reset | Out-Null; & icacls.exe $Path /setowner \"*{_WIN_ADMINS}\" | Out-Null",
        "}",
    ]
    if variant == "command":
        # ntpath: these are Windows paths, built on a Linux server.
        conf_dir, script_dir = ntpath.dirname(p["conf"]), ntpath.dirname(p["script"])
        lines += [
            f"$scriptDir = (P '{script_dir}'); $confDir = (P '{conf_dir}')",
            "Lock-Folder $scriptDir; Lock-Folder $confDir",
            "$hook = " + _ps_literal(_script("ps1"), "claude_code_hook.ps1"),
            f"Write-Locked (P '{p['script']}') $hook",
            "$conf = " + _ps_literal(hook_conf(shield_url=shield_url, key=key, agent=agent,
                                               tier=tier), "hook.conf"),
            f"Write-Locked (P '{p['conf']}') $conf",
        ]
    managed_dir = ntpath.dirname(p["managed"])
    lines += [
        f"$managedDir = (P '{managed_dir}')",
        "Lock-Folder $managedDir",
        "$settings = " + _ps_literal(settings, "managed-settings.json"),
        f"$m = (P '{p['managed']}')",
        "$mark = Join-Path $managedDir 'votal-managed-settings.sha256'",
        "function Get-Sha([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash }",
        "if (Test-Path -LiteralPath $m) {",
        "    $ours = (Test-Path -LiteralPath $mark) -and ((Get-Content -Raw -LiteralPath $mark).Trim() -eq (Get-Sha $m))",
        "    $same = ((Get-Content -Raw -LiteralPath $m).Replace(\"`r`n\", \"`n\").TrimEnd() -eq $settings.Replace(\"`r`n\", \"`n\").TrimEnd())",
        "    if (-not $ours -and -not $same) {",
        "        [Console]::Error.WriteLine(\"Claude Code managed settings already exist at $m with other content. Not overwritten: merge the hooks and allowManagedHooksOnly keys into it.\")",
        "        exit 3 } }",
        "Write-Locked $m $settings",
        "Set-Content -LiteralPath $mark -Value (Get-Sha $m) -NoNewline",
        "Write-Output \"Votal Shield hook for Claude Code installed. Restart Claude Code sessions.\"",
        "",
    ]
    return "\n".join(lines)


def build(variant: str, os_name: str, *, shield_url: str, key: str, agent: str,
          tenant_id: str, tier: str = "standard") -> dict:
    """Every file an admin may need, as {name: {"content", "path", "mime"}}."""
    check_inputs(shield_url=shield_url, key=key, agent=agent, variant=variant, os_name=os_name,
                 tier=tier)
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
                                      agent=agent, tier=tier),
            "path": "", "mime": "text/x-shellscript"}
    else:
        files["install-votal-claude-code.ps1"] = {
            "content": install_script_windows(variant, shield_url=shield_url, key=key,
                                              agent=agent, tier=tier),
            "path": "", "mime": "text/plain"}
    if variant == "command":
        files["hook.conf"] = {"content": hook_conf(shield_url=shield_url, key=key, agent=agent,
                                                   tier=tier),
                              "path": PATHS[os_name]["conf"], "mime": "text/plain"}
        kind = "ps1" if os_name == "windows" else "sh"
        files[os.path.basename(SCRIPT_FILES[kind])] = {
            "content": _script(kind), "path": PATHS[os_name]["script"], "mime": "text/plain"}
    return files


def public_url(request_base: Optional[str] = None) -> str:
    return public_url_and_source(request_base)[0]


def public_url_and_source(request_base: Optional[str] = None) -> tuple[str, str]:
    """The data-plane URL laptops should call, and where it came from:
    SHIELD_DEVICE_AGENT_SHIELD_URL (the URL rollout kits already give device
    agents), else SHIELD_PUBLIC_URL, else the caller's own base URL. The last
    is often the portal, which does not serve the hook route, so the portal
    says so (docs/specs/claude-code-fleet-rollout.md section 4.4)."""
    for env in ("SHIELD_DEVICE_AGENT_SHIELD_URL", "SHIELD_PUBLIC_URL"):
        url = (os.getenv(env) or "").strip()
        if url:
            return url.rstrip("/"), env
    return (request_base or "").rstrip("/"), "request"


__all__ = ["COMMAND_TIMEOUT_S", "EVENTS", "KitError", "MATCHER", "OSES", "PATHS",
           "POST_MATCHER", "SCRIPT_FILES", "TIERS", "VARIANTS", "build", "check_inputs",
           "hook_conf", "install_script", "install_script_windows", "managed_settings",
           "mobileconfig", "public_url", "public_url_and_source", "valid_key"]
