"""`shield-mcp discover <path>`: which AI a code base uses.

Spec: docs/specs/ai-discovery.md, task 4. Offline by default. It reads:

- dependency files (requirements*.txt, pyproject.toml, Pipfile, setup.cfg,
  package.json) for LLM SDKs and agent frameworks in Shield's AI catalog;
- MCP server definitions (.mcp.json, .cursor/mcp.json, .vscode/mcp.json,
  claude_desktop_config.json, and any *mcp*.json with an mcpServers block):
  the server name, the command's base name, the package and the host only;
- configuration and code for AI service hosts in the catalog;
- hard-coded provider keys, reported as present with the file and line. The
  key itself is never printed, stored or sent.

With --post it sends what it found to Shield as a `repo_scan` batch: catalog
sightings and MCP servers, attributed to the repository. Paths, lines and keys
stay on the machine.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from shield_mcp import ai_signals

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".next", "target", "vendor",
             ".idea", "coverage", ".terraform"}
TEXT_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".java", ".kt", ".rb",
                 ".rs", ".cs", ".php", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
                 ".env", ".properties", ".tf", ".sh", ".md", ".txt", ".example", ".sample"}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
MCP_FILES = {".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_settings.json"}

#: Provider key shapes -> catalog id. Only shapes specific to one provider.
KEY_PATTERNS = [
    ("anthropic-api", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}")),
    ("openrouter", re.compile(r"\bsk-or-v1-[A-Fa-f0-9]{32,}")),
    ("openai-api", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}")),
    ("openai-api", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("groq", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("grok", re.compile(r"\bxai-[A-Za-z0-9]{40,}")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("replicate", re.compile(r"\br8_[A-Za-z0-9]{30,}")),
    ("perplexity", re.compile(r"\bpplx-[A-Za-z0-9]{40,}")),
]
_HOSTISH = re.compile(r"(?<![A-Za-z0-9.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![A-Za-z0-9-])",
                      re.I)
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass
class Finding:
    kind: str                      # package | mcp_server | domain | key
    catalog_id: str = ""
    name: str = ""
    path: str = ""                 # repository-relative
    line: int = 0
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {k: v for k, v in {"kind": self.kind, "catalog_id": self.catalog_id, "name": self.name,
                                  "path": self.path, "line": self.line, **self.detail}.items() if v not in ("", 0, None)}


# ── matching ─────────────────────────────────────────────────────────


def _domain_matches(pattern: str, host: str) -> bool:
    p = pattern.lower()
    if p.startswith("*."):
        return host.endswith(p[1:]) and host != p[2:]
    if "*" in p:
        return re.match("^" + re.escape(p).replace(r"\*", "[a-z0-9-]+") + "$", host) is not None
    return host == p or host.endswith("." + p)


@lru_cache(maxsize=20_000)
def match_domain(host: str) -> Optional[str]:
    host = host.lower().rstrip(".")
    if host.endswith("votal.ai"):
        return None
    for p in ai_signals.DOMAINS:
        if _domain_matches(p, host):
            return p
    return None


def _pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def match_package(name: str, ecosystem: str) -> Optional[list]:
    key = _pypi(name) if ecosystem == "pypi" else "npm:" + name.lower()
    return ai_signals.PACKAGES.get(key)


# ── dependency files ─────────────────────────────────────────────────


def _requirements(text: str):
    for i, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            yield m.group(1).split("[", 1)[0], i


def _toml(text: str):
    try:
        import tomllib
    except ImportError:            # Python 3.10
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return None
    try:
        return tomllib.loads(text)
    except Exception:
        return None


def _pyproject(text: str):
    data = _toml(text) or {}
    deps = list((data.get("project") or {}).get("dependencies") or [])
    for group in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
        deps.extend(group or [])
    for group in (data.get("dependency-groups") or {}).values():
        deps.extend(d for d in group or [] if isinstance(d, str))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    deps.extend(k for k in (poetry.get("dependencies") or {}) if k.lower() != "python")
    for g in (poetry.get("group") or {}).values():
        deps.extend((g or {}).get("dependencies") or {})
    for d in deps:
        m = _REQ_LINE.match(str(d))
        if m:
            yield m.group(1).split("[", 1)[0], _line_of(text, m.group(1))


def _pipfile(text: str):
    data = _toml(text) or {}
    for section in ("packages", "dev-packages"):
        for name in data.get(section) or {}:
            yield name, _line_of(text, name)


def _setup_cfg(text: str):
    on = False
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*install_requires\s*=", line):
            on = True
            continue
        if on:
            if line and not line[0].isspace():
                on = False
                continue
            m = _REQ_LINE.match(line)
            if m:
                yield m.group(1), i


def _package_json(text: str):
    try:
        data = json.loads(text)
    except ValueError:
        return
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name in (data.get(section) or {}) if isinstance(data, dict) else {}:
            yield name, _line_of(text, f'"{name}"')


def _line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


def dependency_findings(rel: str, name: str, text: str) -> list[Finding]:
    if name == "package.json":
        eco, it = "npm", _package_json(text)
    elif name == "pyproject.toml":
        eco, it = "pypi", _pyproject(text)
    elif name == "Pipfile":
        eco, it = "pypi", _pipfile(text)
    elif name == "setup.cfg":
        eco, it = "pypi", _setup_cfg(text)
    elif re.match(r"^requirements.*\.(txt|in)$", name):
        eco, it = "pypi", _requirements(text)
    else:
        return []
    out = []
    for pkg, line in it or ():
        hit = match_package(pkg, eco)
        if hit:
            out.append(Finding("package", hit[0], hit[1], rel, line,
                               {"package": ("npm:" if eco == "npm" else "") + (pkg.lower() if eco == "npm" else _pypi(pkg))}))
    return out


# ── MCP definitions ──────────────────────────────────────────────────

_VALUE_FLAGS = {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish", "--name",
                "-w", "--workdir", "--network", "-u", "--user", "--from", "--with", "--python",
                "--prefix", "--registry", "--cwd", "--directory", "-c", "--config"}
_SUBCOMMANDS = {"run", "dlx", "exec", "x", "tool", "start"}
_PKG = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(@[\w.^~<>=*-]+)?$", re.I)
_IMAGE = re.compile(r"^[a-z0-9][\w.-]*(/[a-z0-9][\w.-]*)+(:[\w.-]+)?$", re.I)


def _strip_version(name: str) -> str:
    if name.startswith("@"):
        i = name.find("@", 1)
        return name[:i] if i > 0 else name
    return name.split("@", 1)[0]


def package_from(command: str, args: list) -> str:
    """The package or image an MCP server runs, never a flag's value, an
    assignment or a file path (same rules as the device agent's collector)."""
    args = [a for a in args if isinstance(a, str)]
    base = command.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe").removesuffix(".cmd")
    if base.startswith("python") and "-m" in args:
        i = args.index("-m")
        return args[i + 1] if i + 1 < len(args) and _PKG.match(args[i + 1]) else ""
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
        if base in ("docker", "podman"):
            if _IMAGE.match(a) or _PKG.match(a):
                return a
            continue
        if _PKG.match(a) and not a.endswith((".js", ".py", ".ts", ".mjs", ".cjs")):
            return _strip_version(a)
        return ""
    return ""


def _host(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?([^/:?#@]+)", str(url or "").strip().lower())
    return m.group(1) if m else ""


def mcp_findings(rel: str, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    servers = {}
    for key in ("mcpServers", "servers", "mcp_servers"):
        if isinstance(data.get(key), dict):
            servers.update(data[key])
    if isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), dict):
        servers.update(data["mcp"]["servers"])
    out = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        command = str(cfg.get("command") or "")
        mcp = {"server_name": str(name)[:100], "command": command.replace("\\", "/").rsplit("/", 1)[-1][:64],
               "package": package_from(command, list(cfg.get("args") or []))[:200],
               "host": _host(cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or ""),
               "client": "repo"}
        if not (mcp["command"] or mcp["host"]):
            continue
        out.append(Finding("mcp_server", "", mcp["server_name"], rel, _line_of(text, f'"{name}"'),
                           {"mcp": mcp}))
    return out


# ── text: hosts and keys ─────────────────────────────────────────────


def text_findings(rel: str, text: str) -> list[Finding]:
    out, seen = [], set()
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for m in _HOSTISH.finditer(line):
            host = m.group(1).lower()
            pat = match_domain(host)
            if pat and host not in seen:
                seen.add(host)
                out.append(Finding("domain", "", host, rel, i, {"domain": host}))
        for cid, rx in KEY_PATTERNS:
            if rx.search(line):
                out.append(Finding("key", cid, "", rel, i))
                break
    return out


# ── the walk ─────────────────────────────────────────────────────────


@dataclass
class Report:
    root: str
    repo: str
    files_scanned: int = 0
    truncated: bool = False
    findings: list = field(default_factory=list)

    def summary(self) -> dict:
        by = {}
        for f in self.findings:
            by[f.kind] = by.get(f.kind, 0) + 1
        return by

    def to_dict(self) -> dict:
        return {"root": self.root, "repo": self.repo, "catalog_version": ai_signals.VERSION,
                "files_scanned": self.files_scanned, "truncated": self.truncated,
                "summary": self.summary(), "findings": [f.as_dict() for f in self.findings]}


def _repo_name(root: Path) -> str:
    """org/repo from the git remote, without credentials; else the folder name."""
    try:
        url = subprocess.run(["git", "-C", str(root), "config", "--get", "remote.origin.url"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        url = ""
    if url:
        url = re.sub(r"^[a-z+]+://[^@/]*@", "", url)          # https://token@host/...
        url = re.sub(r"^[^@/]+@([^:]+):", r"\1/", url)        # git@host:org/repo
        url = re.sub(r"^[a-z+]+://", "", url)
        parts = url.removesuffix(".git").split("/")
        if len(parts) >= 3:
            return "/".join(parts[-2:])[:200]
    return root.resolve().name[:200]


def scan(path: str, *, repo: str = "") -> Report:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(path)
    rep = Report(root=str(root), repo=repo or _repo_name(root if root.is_dir() else root.parent))
    files = [root] if root.is_file() else None
    if files is None:
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
            for fn in filenames:
                files.append(Path(dirpath) / fn)
                if len(files) >= MAX_FILES:
                    rep.truncated = True
                    break
            if rep.truncated:
                break
    for p in sorted(files):
        name = p.name
        is_dep = name in ("package.json", "pyproject.toml", "Pipfile", "setup.cfg") or \
            re.match(r"^requirements.*\.(txt|in)$", name)
        is_mcp = name in MCP_FILES or (name.endswith(".json") and "mcp" in name.lower())
        if not (is_dep or is_mcp or p.suffix.lower() in TEXT_SUFFIXES or name.startswith(".env")):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(root)) if p != root else p.name
        rep.files_scanned += 1
        if is_dep:
            rep.findings.extend(dependency_findings(rel, name, text))
        if is_mcp:
            rep.findings.extend(mcp_findings(rel, text))
        if name not in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock"):
            rep.findings.extend(text_findings(rel, text))
    return rep


def observations(rep: Report) -> list[dict]:
    """The batch for Shield: catalog sightings and MCP servers, attributed to
    the repository. No path, line or key value."""
    subject = {"type": "repo", "id": rep.repo}
    out, seen = [], set()
    for f in rep.findings:
        if f.kind == "package":
            o = {"kind": "package", "package": f.detail["package"]}
        elif f.kind == "domain":
            o = {"kind": "domain", "domain": f.detail["domain"]}
        elif f.kind == "key":
            o = {"kind": "catalog", "catalog_id": f.catalog_id}
        elif f.kind == "mcp_server":
            o = {"kind": "mcp_server", "mcp": f.detail["mcp"]}
        else:
            continue
        k = json.dumps(o, sort_keys=True)
        if k in seen:
            continue
        seen.add(k)
        out.append({**o, "subject": subject})
    return out[:1000]


def post(rep: Report, shield_url: str, api_key: str, timeout: float = 20.0) -> dict:
    import httpx
    obs = observations(rep)
    r = httpx.post(shield_url.rstrip("/") + "/v1/shield/discovery/batch",
                   json={"source": "repo_scan", "observations": obs},
                   headers={"X-API-Key": api_key}, timeout=timeout)
    r.raise_for_status()
    return r.json()


def render_human(rep: Report) -> str:
    lines = [f"shield-mcp discover {rep.root}  (repo {rep.repo}, {rep.files_scanned} files"
             f"{', truncated' if rep.truncated else ''})", ""]
    groups = [("package", "LLM SDKs and agent frameworks"), ("mcp_server", "MCP servers"),
              ("domain", "AI service hosts"), ("key", "Hard-coded provider keys (values not shown)")]
    for kind, title in groups:
        items = [f for f in rep.findings if f.kind == kind]
        if not items:
            continue
        lines.append(f"{title}:")
        for f in items:
            where = f"{f.path}:{f.line}" if f.line else f.path
            if kind == "package":
                lines.append(f"  {f.name:<24} {f.detail['package']:<34} {where}")
            elif kind == "mcp_server":
                m = f.detail["mcp"]
                what = m["host"] or " ".join(x for x in (m["command"], m["package"]) if x)
                lines.append(f"  {f.name:<24} {what:<34} {where}")
            elif kind == "domain":
                lines.append(f"  {f.name:<58} {where}")
            else:
                name = next((v[1] for v in ai_signals.PACKAGES.values() if v[0] == f.catalog_id),
                            f.catalog_id)
                lines.append(f"  {name:<58} {where}")
        lines.append("")
    if not rep.findings:
        lines.append("No AI SDKs, MCP servers, AI hosts or provider keys found.")
    return "\n".join(lines).rstrip() + "\n"
