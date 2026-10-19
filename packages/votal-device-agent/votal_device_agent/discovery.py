"""The AI inventory collector: which AI apps, IDE extensions, coding agents,
local model servers and MCP servers this laptop has.

Spec: docs/specs/ai-discovery.md, task 2. Off unless the device policy turns it
on (`discovery.enabled`). It matches locally against the catalog signals the
signed bundle carries and reports matches only, so it never sends an app list,
an extension list, a path outside the known MCP config files, or anything from
those files beyond the server name, the command's base name, the package and
the host. MCP `env` values and arguments are never read into a report.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import socket
from pathlib import Path
from typing import Callable, Iterable, Optional

SKIP_HOMES = {"Shared", "Guest", "Public", "Default", "Default User", "All Users", "defaultuser0"}
EXTENSION_DIRS = (".vscode/extensions", ".vscode-insiders/extensions", ".cursor/extensions",
                  ".windsurf/extensions", ".vscode-oss/extensions")
USER_BIN_DIRS = (".local/bin", ".npm-global/bin", ".bun/bin", ".cargo/bin", "bin", ".volta/bin",
                 "AppData/Roaming/npm")
SYSTEM_BIN_DIRS = ("/usr/local/bin", "/opt/homebrew/bin")
OBS_MAX = 500
_VERSION_SUFFIX = re.compile(r"-\d+(\.\d+)*([-.][\w.]+)?$")


def user_homes(os_name: str) -> list[Path]:
    root = Path("/Users") if os_name == "macos" else Path(os.environ.get("SystemDrive", "C:") + "/Users") \
        if os_name == "windows" else Path("/home")
    try:
        return [p for p in root.iterdir() if p.is_dir() and p.name not in SKIP_HOMES
                and not p.name.startswith(".")]
    except OSError:
        return []


def _port_open(port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _apps_macos(app_dirs: Iterable[Path], wanted: set) -> set:
    found = set()
    for d in app_dirs:
        try:
            bundles = list(d.glob("*.app"))
        except OSError:
            continue
        for app in bundles:
            try:
                with open(app / "Contents" / "Info.plist", "rb") as f:
                    bid = plistlib.load(f).get("CFBundleIdentifier")
            except Exception:
                continue
            if isinstance(bid, str) and bid.lower() in wanted:
                found.add(bid)
    return found


def _apps_windows(roots: Iterable[Path], wanted: set) -> set:
    """Executable names from the catalog, two folders deep under the program
    folders (vendor/app/app.exe)."""
    found = set()
    for root in roots:
        try:
            for exe in list(root.glob("*/*.exe")) + list(root.glob("*/*/*.exe")):
                if exe.name.lower() in wanted:
                    found.add(exe.name)
        except OSError:
            continue
    return found


def _extensions(homes: Iterable[Path], wanted: set) -> set:
    found = set()
    for home in homes:
        for rel in EXTENSION_DIRS:
            try:
                names = [p.name for p in (home / rel).iterdir() if p.is_dir()]
            except OSError:
                continue
            for n in names:
                ext_id = _VERSION_SUFFIX.sub("", n).lower()
                if ext_id in wanted:
                    found.add(ext_id)
    return found


def _binaries(homes: Iterable[Path], names: set, which: Callable) -> set:
    found = set()
    dirs = [Path(d) for d in SYSTEM_BIN_DIRS] + [h / rel for h in homes for rel in USER_BIN_DIRS]
    for name in names:
        if which(name):
            found.add(name)
            continue
        for d in dirs:
            if (d / name).exists() or (d / f"{name}.exe").exists() or (d / f"{name}.cmd").exists():
                found.add(name)
                break
    return found


#: Flags whose next argument is a value (often a secret or a path), never a package.
_VALUE_FLAGS = {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish",
                "--name", "-w", "--workdir", "--network", "-u", "--user", "--from", "--with",
                "--python", "--prefix", "--registry", "--cwd", "--directory", "-c", "--config"}
_SUBCOMMANDS = {"run", "dlx", "exec", "x", "tool", "start"}
_PACKAGE = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(@[\w.^~<>=*-]+)?$", re.I)
_IMAGE = re.compile(r"^[a-z0-9][\w.-]*(/[a-z0-9][\w.-]*)+(:[\w.-]+)?$", re.I)


def _strip_version(name: str) -> str:
    if name.startswith("@"):
        i = name.find("@", 1)
        return name[:i] if i > 0 else name
    return name.split("@", 1)[0]


def _package_from(command: str, args: list) -> str:
    """The package or image an MCP server runs (npx -y @scope/pkg, uvx pkg,
    python -m module, docker run ... image), and nothing else: values of flags
    that take one, and anything with "=" or a file path, are never returned."""
    args = [a for a in args if isinstance(a, str)]
    base = command.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe").removesuffix(".cmd")
    if base.startswith("python") and "-m" in args:
        i = args.index("-m")
        return args[i + 1] if i + 1 < len(args) and _PACKAGE.match(args[i + 1]) else ""
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in _VALUE_FLAGS:
            skip = True
            continue
        if a.startswith("-") or a.lower() in _SUBCOMMANDS or "=" in a:
            continue
        if base == "docker" or base == "podman":
            if _IMAGE.match(a) or _PACKAGE.match(a):
                return a
            continue
        if _PACKAGE.match(a) and not a.endswith((".js", ".py", ".ts", ".mjs", ".cjs")):
            return _strip_version(a)
        return ""
    return ""


def _host(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", str(url or "").strip().lower())
    return m.group(1) if m else ""


def _servers_from(data, key: str) -> dict:
    out = {}
    if not isinstance(data, dict):
        return out
    block = data.get(key)
    if isinstance(block, dict):
        out.update(block)
    # Claude Code keeps per-project servers under projects.<path>.mcpServers.
    for proj in (data.get("projects") or {}).values() if isinstance(data.get("projects"), dict) else []:
        if isinstance(proj, dict) and isinstance(proj.get(key), dict):
            out.update(proj[key])
    return out


def _read_config(path: Path):
    try:
        if path.stat().st_size > 5_000_000:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if path.suffix == ".toml":
        try:
            import tomllib
            return tomllib.loads(text)
        except Exception:
            return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _expand(path: str, home: Path) -> Path:
    p = path.replace("%APPDATA%", str(home / "AppData" / "Roaming")) \
            .replace("%USERPROFILE%", str(home))
    if p.startswith("~"):
        p = str(home) + p[1:]
    return Path(p)


def _mcp_servers(homes: Iterable[Path], paths: list, os_name: str) -> list:
    out, seen = [], set()
    for home in homes:
        for spec in paths:
            if spec.get("os") not in ("any", os_name):
                continue
            data = _read_config(_expand(spec["path"], home))
            for name, cfg in _servers_from(data, spec.get("key") or "mcpServers").items():
                if not isinstance(cfg, dict):
                    continue
                command = str(cfg.get("command") or "")
                mcp = {"server_name": str(name)[:100],
                       "command": command.replace("\\", "/").rsplit("/", 1)[-1][:64],
                       "package": _package_from(command, list(cfg.get("args") or []))[:200],
                       "host": _host(cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or ""),
                       "client": spec.get("client", "")}
                key = (mcp["server_name"], mcp["package"], mcp["host"], mcp["command"])
                if key in seen or not (mcp["command"] or mcp["host"]):
                    continue
                seen.add(key)
                out.append({"kind": "mcp_server", "mcp": mcp})
    return out


def collect(catalog: dict, *, os_name: str, homes: Optional[list] = None,
            app_dirs: Optional[list] = None, program_dirs: Optional[list] = None,
            which: Callable = shutil.which, port_open: Callable = _port_open) -> list[dict]:
    """Observations for the heartbeat's ai_inventory field. Never raises."""
    homes = homes if homes is not None else user_homes(os_name)
    obs: list[dict] = []
    try:
        wanted_apps = {a.lower() for e in catalog.get("apps") or [] for a in e.get("app_ids") or []}
        if os_name == "macos":
            dirs = app_dirs if app_dirs is not None else [Path("/Applications")] + [h / "Applications" for h in homes]
            for bid in sorted(_apps_macos(dirs, wanted_apps)):
                obs.append({"kind": "app", "app_id": bid})
        elif os_name == "windows":
            pf = program_dirs if program_dirs is not None else [
                Path(os.environ.get("ProgramFiles", "C:/Program Files")),
                Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))] + \
                [h / "AppData" / "Local" / "Programs" for h in homes]
            for exe in sorted(_apps_windows(pf, wanted_apps)):
                obs.append({"kind": "app", "app_id": exe})
        wanted_ext = {x.lower() for e in catalog.get("extensions") or [] for x in e.get("ids") or []}
        for ext in sorted(_extensions(homes, wanted_ext)):
            obs.append({"kind": "extension", "extension": ext})
        names = {n for e in catalog.get("binaries") or [] for n in e.get("names") or []}
        for b in sorted(_binaries(homes, names, which)):
            obs.append({"kind": "binary", "binary": b})
        for p in sorted({p for e in catalog.get("ports") or [] for p in e.get("ports") or []}):
            if port_open(p):
                obs.append({"kind": "port", "port": p})
        obs.extend(_mcp_servers(homes, catalog.get("mcp_config_paths") or [], os_name))
    except Exception:
        pass
    return obs[:OBS_MAX]


def digest(obs: list) -> str:
    return hashlib.sha256(json.dumps(obs, sort_keys=True).encode()).hexdigest()
