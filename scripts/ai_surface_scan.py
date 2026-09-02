"""Find every way AI leaves this endpoint, and say which of it is governed.

The failure this exists for is small and ordinary: a connector configured to
point at a provider directly instead of at the gateway. No policy can govern
traffic that never reaches the enforcement point, so the first question is not
"what does policy say" but "what is even in scope".

Four surfaces, because AI leaves an endpoint four ways:

    MCP servers     declared in config files. The only surface where governed
                    and ungoverned are precisely distinguishable, because the
                    URL either points at a gateway route or it does not.
    Desktop apps    installed and running AI clients, each with its own network
                    stack and its own opinion about proxies.
    Browsers        extensions and profiles. The largest surface and the least
                    controllable.
    Local runtimes  Ollama, LM Studio, llama.cpp. Inference that never leaves
                    the machine at all, which is either the safest case or the
                    least visible one depending on what it is fed.

What this reads, so nobody is surprised: config files, application directories,
the process table, extension manifests, and open network sockets. It does NOT
read browser history, prompts, message contents, or any file's payload. It
reports what exists, never what was said.

    python scripts/ai_surface_scan.py            # human readable
    python scripts/ai_surface_scan.py --json     # for a fleet rollup
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

HOME = Path.home()
IS_MAC = platform.system() == "Darwin"
IS_WIN = platform.system() == "Windows"

#: A server is governed when its URL routes through a Shield gateway. This is
#: the whole test, and it is the one that catches the real mistake.
GATEWAY_MARKERS = ("/gateway/", "/v1/shield/")

#: Where MCP clients keep their server lists. Adding a client here is the main
#: maintenance cost of this script, and the reason it is data rather than code.
MCP_CONFIGS = {
    "Claude Code":      [HOME / ".claude.json", Path.cwd() / ".mcp.json"],
    "Claude Desktop":   [HOME / "Library/Application Support/Claude/claude_desktop_config.json",
                         HOME / "AppData/Roaming/Claude/claude_desktop_config.json"],
    "Cursor":           [HOME / ".cursor/mcp.json",
                         HOME / "Library/Application Support/Cursor/User/settings.json"],
    "VS Code":          [HOME / "Library/Application Support/Code/User/settings.json",
                         HOME / "AppData/Roaming/Code/User/settings.json"],
    "Windsurf":         [HOME / ".codeium/windsurf/mcp_config.json"],
    "Zed":              [HOME / ".config/zed/settings.json"],
}

#: Desktop clients that talk to a model. Matched on app bundle or process name.
AI_APPS = {
    "Claude": "Anthropic desktop client",
    "ChatGPT": "OpenAI desktop client",
    "Cursor": "AI code editor",
    "Windsurf": "AI code editor",
    "Ollama": "local inference runtime",
    "LM Studio": "local inference runtime",
    "Jan": "local inference runtime",
    "GitHub Copilot": "code assistant",
    "Perplexity": "AI search client",
    "Msty": "local model client",
}

#: Extension ids and name fragments that indicate AI in the browser. Ids are
#: more reliable than names, which vendors change.
BROWSER_AI = [
    ("chatgpt", "ChatGPT"), ("claude", "Claude"), ("copilot", "Copilot"),
    ("gemini", "Gemini"), ("perplexity", "Perplexity"), ("monica", "Monica"),
    ("sider", "Sider"), ("merlin", "Merlin"), ("harpa", "Harpa"),
    ("openai", "OpenAI"), ("anthropic", "Anthropic"), ("codeium", "Codeium"),
    ("tabnine", "Tabnine"), ("blackbox", "Blackbox"),
]

BROWSER_PROFILES = {
    "Chrome":  HOME / "Library/Application Support/Google/Chrome",
    "Edge":    HOME / "Library/Application Support/Microsoft Edge",
    "Brave":   HOME / "Library/Application Support/BraveSoftware/Brave-Browser",
    "Arc":     HOME / "Library/Application Support/Arc/User Data",
    "Chromium":HOME / "Library/Application Support/Chromium",
}
if IS_WIN:
    LOCALAPP = Path(os.environ.get("LOCALAPPDATA", HOME / "AppData/Local"))
    BROWSER_PROFILES = {
        "Chrome": LOCALAPP / "Google/Chrome/User Data",
        "Edge":   LOCALAPP / "Microsoft/Edge/User Data",
        "Brave":  LOCALAPP / "BraveSoftware/Brave-Browser/User Data",
    }

#: Hosts that indicate a model call leaving the machine. Used only against the
#: socket table, never against browsing history.
AI_HOSTS = [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "api.mistral.ai", "api.groq.com", "api.together.xyz",
    "api.perplexity.ai", "openrouter.ai", "bedrock", "openai.azure.com",
]


@dataclass
class Finding:
    surface: str            # mcp | app | browser | runtime | network
    name: str
    detail: str
    governed: Optional[bool]   # None where the question does not apply
    evidence: str
    note: str = ""


def _read_json(p: Path) -> Optional[dict]:
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _is_governed(url: str) -> bool:
    return any(m in url for m in GATEWAY_MARKERS)


# ── MCP: the surface where the answer is exact ─────────────────────────────

def scan_mcp() -> list[Finding]:
    out: list[Finding] = []
    for client, paths in MCP_CONFIGS.items():
        for path in paths:
            if not path.exists():
                continue
            data = _read_json(path)
            if not data:
                continue

            # mcpServers appears at the top level, under a project key, or
            # namespaced inside an editor's settings blob.
            blocks: list[tuple[str, dict]] = []
            if isinstance(data.get("mcpServers"), dict):
                blocks.append(("", data["mcpServers"]))
            for key in ("mcp", "mcp.servers", "context_servers"):
                v = data.get(key)
                if isinstance(v, dict):
                    blocks.append((key, v.get("servers", v)))
            for proj, cfg in (data.get("projects") or {}).items():
                if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                    blocks.append((proj, cfg["mcpServers"]))

            for scope, servers in blocks:
                for name, cfg in (servers or {}).items():
                    if not isinstance(cfg, dict):
                        continue
                    url = cfg.get("url") or ""
                    cmd = cfg.get("command") or ""
                    where = f"{path.name}{' :: ' + Path(scope).name if scope else ''}"
                    if url:
                        out.append(Finding(
                            "mcp", f"{client}/{name}", url,
                            _is_governed(url), where,
                            "" if _is_governed(url)
                            else "does not route through a gateway, so no policy applies"))
                    elif cmd:
                        args = " ".join(str(a) for a in (cfg.get("args") or [])[:3])
                        out.append(Finding(
                            "mcp", f"{client}/{name}", f"stdio: {cmd} {args}".strip(),
                            False, where,
                            "local subprocess: no URL to route, needs process "
                            "allowlisting rather than network policy"))
    return out


# ── apps and runtimes ──────────────────────────────────────────────────────

def _running() -> str:
    try:
        return subprocess.run(["ps", "axco", "command"] if IS_MAC else ["tasklist"],
                              capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""


def scan_apps() -> list[Finding]:
    out: list[Finding] = []
    procs = _running().lower()

    installed: set[str] = set()
    roots = [Path("/Applications"), HOME / "Applications"] if IS_MAC else [
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")),
        Path(os.environ.get("LOCALAPPDATA", HOME / "AppData/Local")) / "Programs"]
    for root in roots:
        if not root.exists():
            continue
        try:
            for entry in root.iterdir():
                for app in AI_APPS:
                    if app.lower().replace(" ", "") in entry.name.lower().replace(" ", ""):
                        installed.add(app)
        except Exception:
            pass

    for app, what in AI_APPS.items():
        running = app.lower().replace(" ", "") in procs.replace(" ", "")
        if app in installed or running:
            state = "running" if running else "installed"
            out.append(Finding(
                "runtime" if "local inference" in what else "app",
                app, what, None, state,
                "local inference: nothing leaves the machine, but nothing is "
                "inspected either" if "local inference" in what
                else "own network stack; a gateway only governs it if the app "
                     "is configured or forced to use one"))
    return out


# ── browsers ───────────────────────────────────────────────────────────────

def scan_browsers() -> list[Finding]:
    out: list[Finding] = []
    for browser, base in BROWSER_PROFILES.items():
        if not base.exists():
            continue
        for profile in list(base.glob("Profile *")) + [base / "Default"]:
            ext_dir = profile / "Extensions"
            if not ext_dir.exists():
                continue
            seen: set[str] = set()
            for ext in ext_dir.iterdir():
                manifests = list(ext.glob("*/manifest.json"))
                if not manifests:
                    continue
                m = _read_json(manifests[0]) or {}
                label = f"{m.get('name','')} {ext.name}".lower()
                for needle, pretty in BROWSER_AI:
                    if needle in label and pretty not in seen:
                        seen.add(pretty)
                        out.append(Finding(
                            "browser", f"{browser}/{pretty}",
                            m.get("name", ext.name)[:60], None,
                            f"{profile.name}",
                            "extension sees page content before TLS; the "
                            "largest surface and the least controllable"))
    return out


# ── live network ───────────────────────────────────────────────────────────

def scan_network() -> list[Finding]:
    out: list[Finding] = []
    if not IS_MAC:
        return out
    try:
        raw = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return out
    seen: set[tuple[str, str]] = set()
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        proc, dest = parts[0], parts[8]
        for host in AI_HOSTS:
            if host in dest.lower() and (proc, host) not in seen:
                seen.add((proc, host))
                out.append(Finding(
                    "network", f"{proc} -> {host}", dest, False, "open socket",
                    "direct to provider: not passing through a gateway"))
    return out


# ── report ─────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    findings = scan_mcp() + scan_apps() + scan_browsers() + scan_network()

    if args.json:
        print(json.dumps({
            "host": platform.node(), "platform": platform.system(),
            "findings": [asdict(f) for f in findings],
        }, indent=2))
        return 0

    print(f"AI surface on {platform.node()} ({platform.system()})")
    print("reads config, apps, extensions and sockets. Never history or content.\n")

    order = [("mcp", "MCP servers"), ("app", "Desktop AI apps"),
             ("runtime", "Local inference"), ("browser", "Browser extensions"),
             ("network", "Live connections")]
    for surface, title in order:
        group = [f for f in findings if f.surface == surface]
        if not group:
            continue
        print(f"{title}")
        for f in group:
            if f.governed is True:
                mark = "  ok  "
            elif f.governed is False:
                mark = " GAP  "
            else:
                mark = "  ?   "
            print(f"{mark}{f.name:34} {f.detail[:52]}")
            if f.note:
                print(f"      {'':34} {f.note}")
        print()

    governed = [f for f in findings if f.governed is True]
    gaps = [f for f in findings if f.governed is False]
    unknown = [f for f in findings if f.governed is None]

    print("=" * 70)
    print(f"  {len(governed)} governed   {len(gaps)} bypassing   "
          f"{len(unknown)} not determinable from config alone")
    if gaps:
        print("\n  Bypassing means no policy applies, whatever the policy says.")
        print("  For URL-based servers the fix is the gateway route. For stdio")
        print("  servers and apps there is no URL, so the lever is process")
        print("  allowlisting or network egress control, not policy.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
