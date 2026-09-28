"""Hot-path runtime-boundary checks for Shield's own tool paths.

When an agent bound to a runtime profile calls a tool whose arguments name a
file path, a shell command or a URL, the call is judged against the same
profile the sandbox enforces, so the cooperative layer (/v1/shield/tool/check,
MCP tools/call) and the kernel never disagree, and a sandbox that lacks a rule
(OpenShell cannot deny a sub-path, cannot filter commands) still gets it here.

Deterministic, no LLM, precompiled. Cost contract (spec §3):
  * agent without a profile: one dict lookup, returns None;
  * otherwise: glob and string work on the call's extracted arguments only.

Honest limits, stated where they apply:
  * A command deny-list is defense in depth, not a boundary: allow_binaries
    plus the runtime's exec control is the boundary.
  * Paths are normalized lexically (~, //, ., ..); symlinks are not resolved,
    because Shield does not see the sandbox's filesystem.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import posixpath
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from core.runtime_policy.model import ProfileError, profile_hash

logger = logging.getLogger("votal.runtime_policy")

GUARDRAIL = "runtime_boundary"
_OFF = ("0", "off", "false", "no")
MAX_VALUE = 8192
MAX_VALUES = 50

_HOME_PREFIX = re.compile(r"^(/home/[^/]+|/Users/[^/]+|/root)(?=/|$)")
_WRITE_TOOL = re.compile(r"(^|[_.-])(write|edit|create|move|delete|remove|rm|mkdir|append|"
                         r"save|put|upload|patch|rename|chmod|chown)([_.-]|$)", re.I)
_SEGMENT_SPLIT = re.compile(r"\|\||&&|;|\n|\|")
#: Assignments that change which program actually runs.
_HIJACK_VARS = re.compile(r"^(path|ld_preload|ld_library_path|dyld_insert_libraries|"
                          r"dyld_library_path|pythonpath|node_options|bash_env|env)=")
_SHELL_BUILTINS = {"cd", "echo", "printf", "export", "true", "false", "test", "[", "set",
                   "unset", "exit", "return", "pwd", "read", ":", "wait", "shift"}


def enabled() -> bool:
    """SHIELD_RUNTIME_POLICY=off disables every hook (escape hatch)."""
    return os.getenv("SHIELD_RUNTIME_POLICY", "on").strip().lower() not in _OFF


# ── compiled profile ─────────────────────────────────────────────────


def _glob_re(globs) -> Optional[re.Pattern]:
    globs = list(globs)
    if not globs:
        return None
    return re.compile("|".join(f"(?:{fnmatch.translate(g.lower())})" for g in globs))


def _path_re(globs) -> Optional[re.Pattern]:
    """Path globs where ** spans directories and * does not cross '/'."""
    parts = []
    for g in globs:
        out, i = "", 0
        while i < len(g):
            if g.startswith("**", i):
                out += ".*"
                i += 2
            elif g[i] == "*":
                out += "[^/]*"
                i += 1
            elif g[i] == "?":
                out += "[^/]"
                i += 1
            else:
                out += re.escape(g[i])
                i += 1
        # "/a/**" also covers "/a" itself.
        if out.endswith("/.*"):
            out = out[:-3] + "(?:/.*)?"
        parts.append(f"(?:{out})")
    return re.compile("^(?:" + "|".join(parts) + ")$") if parts else None


@dataclass
class _Extract:
    tools: re.Pattern
    param: str
    kind: str


@dataclass
class CompiledProfile:
    name: str
    hash: str
    raw: dict
    extract: list = field(default_factory=list)
    fs_deny: Optional[re.Pattern] = None
    fs_read: list = field(default_factory=list)       # read_only + read_write roots
    fs_write: list = field(default_factory=list)      # read_write roots
    workdir: str = "/sandbox"
    bins: set = field(default_factory=set)            # full paths
    bin_names: set = field(default_factory=set)       # basenames
    deny_cmd: list = field(default_factory=list)      # (pattern, has_pipe)
    net: list = field(default_factory=list)           # (host_re, port, methods, path_re)
    classified: list = field(default_factory=list)    # (path_re, classification)
    fail_closed: bool = False


def compile_checks(name: str, profile: dict) -> CompiledProfile:
    fs, proc = profile["filesystem"], profile["process"]
    cp = CompiledProfile(name=name, hash=profile_hash(profile), raw=profile,
                         fail_closed=bool(profile.get("fail_closed")))
    for x in profile["tools"]["extract"]:
        cp.extract.append(_Extract(_glob_re(x["tools"]), x["param"], x["kind"]))
    cp.fs_deny = _path_re(fs["deny"])
    cp.classified = [(_path_re([c["path"]]), c["classification"]) for c in fs["classified"]]
    cp.fs_read = fs["read_only"] + fs["read_write"]
    cp.fs_write = list(fs["read_write"])
    cp.workdir = next((r for r in fs["read_write"] if not r.startswith("~")), "/sandbox")
    cp.bins = set(proc["allow_binaries"])
    cp.bin_names = {posixpath.basename(b) for b in proc["allow_binaries"]}
    cp.deny_cmd = [(_norm_cmd(p), "|" in p) for p in proc["deny_commands"]]
    for a in profile["network"]["allow"]:
        cp.net.append((_glob_re([a["host"]]), a["port"], set(a["methods"]),
                       _path_re(a["paths"])))
    return cp


# ── normalization ────────────────────────────────────────────────────


def normalize_path(value: str, workdir: str) -> str:
    """Lexical normalization: home prefixes -> ~, relative -> under workdir,
    '.', '..' and '//' collapsed (never above the root)."""
    v = value.strip().replace("\\", "/")
    if v.startswith("file://"):
        v = v[7:]
    v = _HOME_PREFIX.sub("~", v)
    if not (v.startswith("/") or v == "~" or v.startswith("~/")):
        v = posixpath.join(workdir, v)
    home = v.startswith("~")
    body = v[1:] if home else v
    body = posixpath.normpath("/" + body.lstrip("/"))
    if body.startswith("//"):
        body = body[1:]
    return ("~" + (body if body != "/" else "")) if home else body


def _norm_cmd(cmd: str) -> str:
    c = cmd.replace("${IFS}", " ").replace("$IFS", " ").replace("\t", " ")
    c = re.sub(r"\\\n", " ", c)
    # One spelling for operators, so "curl x|sh" and "curl x | sh" match alike.
    c = re.sub(r"\s*(\|\||&&|;|\|)\s*", r" \1 ", c)
    return re.sub(r"\s+", " ", c).strip().lower()


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _values(params: dict, param: str) -> list[str]:
    cur: Any = params
    for part in param.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return []
    if isinstance(cur, str):
        return [cur[:MAX_VALUE]]
    if isinstance(cur, list):
        return [str(v)[:MAX_VALUE] for v in cur[:MAX_VALUES] if isinstance(v, str)]
    return []


# ── decisions ────────────────────────────────────────────────────────


def _check_file(cp: CompiledProfile, value: str, tool: str) -> Optional[str]:
    path = normalize_path(value, cp.workdir)
    if cp.fs_deny is not None and cp.fs_deny.match(path):
        return f"path {path} is denied by the runtime profile"
    if cp.fs_read:
        writing = bool(_WRITE_TOOL.search(tool))
        roots = cp.fs_write if writing else cp.fs_read
        if not any(_under(path, r) for r in roots):
            what = "writable" if writing else "readable"
            return f"path {path} is outside the profile's {what} paths ({', '.join(roots) or 'none'})"
    return None


def _check_exec(cp: CompiledProfile, value: str) -> Optional[str]:
    full = _norm_cmd(value)
    segments = [s.strip() for s in _SEGMENT_SPLIT.split(full) if s.strip()]
    for pat, has_pipe in cp.deny_cmd:
        if fnmatch.fnmatchcase(full, pat):
            return f"command matches denied pattern '{pat}'"
        if not has_pipe and any(fnmatch.fnmatchcase(seg, pat) for seg in segments):
            return f"command matches denied pattern '{pat}'"
    if cp.bins:
        for seg in segments:
            try:
                tokens = shlex.split(seg)
            except ValueError:
                return "command could not be parsed (unbalanced quotes)"
            # Leading VAR=value assignments: refuse the ones that swap the
            # program (a planted /tmp/git behind PATH), skip the rest.
            while tokens and re.match(r"^[a-z_][a-z0-9_]*=", tokens[0]):
                if _HIJACK_VARS.match(tokens[0]):
                    return f"command overrides {tokens[0].split('=')[0].upper()}, which can " \
                           f"swap the program that runs"
                tokens = tokens[1:]
            if not tokens or tokens[0] in _SHELL_BUILTINS:
                continue
            prog = tokens[0]
            allowed = prog in cp.bins if prog.startswith("/") else \
                posixpath.basename(prog) in cp.bin_names
            if not allowed:
                return f"program '{prog}' is not in the profile's allowed binaries"
    return None


def _check_net(cp: CompiledProfile, value: str, method: str,
               shield_hosts: set[str]) -> Optional[str]:
    v = value.strip()
    if "://" not in v:
        v = "https://" + v
    u = urlparse(v)
    host = (u.hostname or "").lower()
    if not host:
        return "URL has no host"
    if host in shield_hosts:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    method = (method or "GET").upper()
    for host_re, p, methods, path_re in cp.net:
        if host_re.fullmatch(host) and p == port and \
                ("*" in methods or method in methods) and \
                (path_re is None or path_re.match(path)):
            return None
    return f"{method} {host}:{port}{path} is not in the profile's network allow-list"


_CLASS_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


def classify_path(cp: CompiledProfile, value: str) -> Optional[str]:
    """Classification of one path per the profile's filesystem.classified, or None."""
    path = normalize_path(value, cp.workdir)
    best = None
    for rx, cls in cp.classified:
        if rx.match(path) and (best is None or _CLASS_RANK[cls] > _CLASS_RANK[best]):
            best = cls
    return best


def classified_read(cp: CompiledProfile, tool_name: str, params: Optional[dict]) -> Optional[str]:
    """The highest classification among the files this call names, per the
    profile's filesystem.classified globs, or None."""
    params = params if isinstance(params, dict) else {}
    tool = (tool_name or "").lower()[:256]
    best = None
    for x in cp.extract:
        if x.kind != "file" or not x.tools.fullmatch(tool):
            continue
        for value in _values(params, x.param):
            path = normalize_path(value, cp.workdir)
            for rx, cls in cp.classified:
                if rx.match(path) and (best is None or _CLASS_RANK[cls] > _CLASS_RANK[best]):
                    best = cls
    return best


def evaluate(cp: CompiledProfile, tool_name: str, params: Optional[dict],
             shield_hosts: Optional[set] = None) -> list[dict]:
    """Every violation for this call: [{kind, value, reason}]. Empty = allowed."""
    params = params if isinstance(params, dict) else {}
    tool = (tool_name or "").lower()[:256]
    method = str(params.get("method") or "GET")
    out = []
    for x in cp.extract:
        if not x.tools.fullmatch(tool):
            continue
        for value in _values(params, x.param):
            if x.kind == "file":
                reason = _check_file(cp, value, tool)
            elif x.kind == "exec":
                reason = _check_exec(cp, value)
            else:
                reason = _check_net(cp, value, method, shield_hosts or set())
            if reason:
                out.append({"kind": x.kind, "param": x.param, "value": value[:300],
                            "reason": reason})
    return out


# ── per-tenant cache: agent -> compiled profile ──────────────────────

_cache: dict[str, tuple[float, dict]] = {}


def invalidate(tenant_id: Optional[str] = None) -> None:
    if tenant_id is None:
        _cache.clear()
    else:
        _cache.pop(tenant_id, None)


def _ttl() -> float:
    try:
        return max(0.0, float(os.getenv("SHIELD_RUNTIME_POLICY_CACHE_S", "5")))
    except ValueError:
        return 5.0


def _load_tenant(tenant_id: str) -> dict:
    """{"agents": {agent_id: profile_name}, "profiles": {name: CompiledProfile|None}}"""
    from core.runtime_policy import store
    from storage.tenant_store import kv_get

    agents = {}
    for agent_id, agent in (kv_get(f"agents:{tenant_id}") or {}).items():
        name = (agent or {}).get("runtime_profile")
        if name:
            agents[agent_id] = name
    profiles: dict = {}
    if agents:
        for name, rec in store.list_profiles(tenant_id).items():
            if "error" in rec:
                logger.warning("runtime profile %s/%s no longer validates; not enforced",
                               tenant_id, name)
                profiles[name] = None
                continue
            profiles[name] = compile_checks(name, rec["profile"])
    return {"agents": agents, "profiles": profiles}


def profile_for(tenant_id: Optional[str], agent_key: Optional[str]) -> Optional[CompiledProfile]:
    """The compiled profile an agent runs under, or None (no checks)."""
    if not tenant_id or not agent_key or not enabled():
        return None
    now = time.monotonic()
    hit = _cache.get(tenant_id)
    if hit is None or hit[0] <= now:
        try:
            data = _load_tenant(tenant_id)
        except Exception as e:
            logger.warning("runtime profiles for tenant %s unavailable: %s", tenant_id, e)
            data = {"agents": {}, "profiles": {}, "error": str(e)}
        hit = (now + _ttl(), data)
        _cache[tenant_id] = hit
    data = hit[1]
    name = data["agents"].get(agent_key)
    if not name:
        return None
    return data["profiles"].get(name)


def check_tool_call(tenant_id: Optional[str], *, agent_key: Optional[str], tool_name: str,
                    params: Optional[dict], shield_hosts: Optional[set] = None
                    ) -> Optional[dict]:
    """A guardrail result for this call, or None when the agent has no profile
    or the call names no path, command or URL the profile covers."""
    cp = profile_for(tenant_id, agent_key)
    if cp is None:
        return None
    start = time.perf_counter()
    try:
        violations = evaluate(cp, tool_name, params, shield_hosts)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("runtime boundary check failed for %s: %s", tool_name, e)
        violations = [{"kind": "error", "value": "", "reason": f"check failed: {e}"}] \
            if cp.fail_closed else []
    latency = round((time.perf_counter() - start) * 1000, 3)
    details = {"profile": cp.name, "profile_hash": cp.hash, "violations": violations}
    if not violations:
        return None
    first = violations[0]
    return {"guardrail": GUARDRAIL, "passed": False, "action": "block",
            "message": f"Runtime boundary ({cp.name}): {first['reason']}",
            "details": details, "latency_ms": latency}


__all__ = ["GUARDRAIL", "CompiledProfile", "ProfileError", "check_tool_call", "classified_read", "classify_path",
           "compile_checks", "enabled", "evaluate", "invalidate", "normalize_path",
           "profile_for"]
