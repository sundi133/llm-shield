"""Runtime profile: the infrastructure boundary for one class of agent.

Pure: validation, normalization, hashing and the starter templates. Nothing
here does I/O. Spec: docs/specs/infra-guardrails.md §2, §4.1.

A profile describes what the RUNTIME should enforce (network egress, file
access, processes, resources) plus what Shield itself checks on its tool paths
and at cap/mint (identity, tool-argument extraction). Compilers turn it into a
runtime's native policy; each lists what its target cannot express.

Validation is strict at every level, as in core/xflow/policy.py: a misspelled
field in a security boundary that is silently ignored is a rule that silently
never applies.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any, Optional

CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
ATTESTATION_MODES = ("off", "warn", "enforce")
EXTRACT_KINDS = ("file", "exec", "net")
HTTP_METHODS = ("*", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")

MAX_PROFILES = 100
MAX_LIST = 200
MAX_PATH = 512
MAX_TEXT = 500

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_HOST_RE = re.compile(r"^(\*\.)?([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                      r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_CPU_RE = re.compile(r"^(\d+(\.\d+)?|\d+m)$")
_MEM_RE = re.compile(r"^\d+(Ki|Mi|Gi|Ti|K|M|G|T)?$")
_GLOB_CHARS = set("*?[")

_TOP_KEYS = {"description", "network", "filesystem", "process", "tools", "identity",
             "resources", "fail_closed"}
_NET_KEYS = {"default", "allow"}
_ALLOW_KEYS = {"host", "port", "methods", "paths", "description"}
_FS_KEYS = {"read_only", "read_write", "deny", "classified", "kernel_enforcement"}
KERNEL_ENFORCEMENT = ("required", "best_effort")
_PROC_KEYS = {"run_as", "allow_binaries", "deny_commands", "no_new_privileges"}
_TOOLS_KEYS = {"from_registry", "extract"}
_EXTRACT_KEYS = {"tools", "param", "kind"}
_ID_KEYS = {"require_agent_token", "max_token_ttl_seconds", "spiffe_id",
            "require_attestation"}
_RES_KEYS = {"cpu", "memory", "gpu", "max_pids", "wall_clock_seconds",
             "llm_tokens_per_hour"}

#: Tool-argument extraction used when a profile does not declare its own:
#: the argument names common MCP filesystem, shell and fetch servers use.
DEFAULT_EXTRACT = [
    {"tools": ["read_file", "read_text_file", "read_multiple_files", "write_file",
               "edit_file", "create_directory", "list_directory", "directory_tree",
               "move_file", "search_files", "get_file_info", "*_read_file",
               "*_write_file", "fs_*", "filesystem_*"],
     "param": "path", "kind": "file"},
    {"tools": ["move_file"], "param": "source", "kind": "file"},
    {"tools": ["move_file"], "param": "destination", "kind": "file"},
    {"tools": ["run_command", "run_shell", "shell", "shell_exec", "execute_command",
               "exec", "bash", "terminal", "*_run_command", "*_shell_exec"],
     "param": "command", "kind": "exec"},
    {"tools": ["fetch", "http_get", "http_request", "web_fetch", "browse", "curl",
               "*_fetch", "*_http_get"],
     "param": "url", "kind": "net"},
]


class ProfileError(ValueError):
    """A runtime profile failed validation. ``errors`` lists every problem."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


# ── primitives ───────────────────────────────────────────────────────


def _obj(v: Any, where: str, errors: list[str]) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        errors.append(f"{where}: must be an object")
        return {}
    return v


def _unknown(obj: dict, allowed: set, where: str, errors: list[str]) -> None:
    for k in obj:
        if k not in allowed:
            errors.append(f"{where}: unknown field '{k}' (allowed: {', '.join(sorted(allowed))})")


def _bool(v: Any, default: bool, where: str, errors: list[str]) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    errors.append(f"{where}: must be true or false")
    return default


def _int(v: Any, lo: int, hi: int, where: str, errors: list[str],
         default: Optional[int] = None) -> Optional[int]:
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        errors.append(f"{where}: must be an integer")
        return default
    if not lo <= v <= hi:
        errors.append(f"{where}: must be between {lo} and {hi}")
        return default
    return v


def _list(v: Any, where: str, errors: list[str]) -> list:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        errors.append(f"{where}: must be a list")
        return []
    if len(v) > MAX_LIST:
        errors.append(f"{where}: more than {MAX_LIST} entries")
        return v[:MAX_LIST]
    return v


def _strs(v: Any, where: str, errors: list[str], *, max_len: int = 200) -> list[str]:
    out: list[str] = []
    for i, item in enumerate(_list(v, where, errors)):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{where}[{i}]: must be a non-empty string")
            continue
        item = item.strip()
        if len(item) > max_len:
            errors.append(f"{where}[{i}]: longer than {max_len} characters")
            continue
        if item not in out:
            out.append(item)
    return out


def _path(p: str, where: str, errors: list[str], *, glob_ok: bool) -> Optional[str]:
    """A filesystem path: absolute or home-relative, no '..', no NUL."""
    if "\x00" in p:
        errors.append(f"{where}: contains a NUL byte")
        return None
    if len(p) > MAX_PATH:
        errors.append(f"{where}: longer than {MAX_PATH} characters")
        return None
    if not (p.startswith("/") or p == "~" or p.startswith("~/")):
        errors.append(f"{where}: '{p}' must be absolute (/...) or home-relative (~/...)")
        return None
    if ".." in p.split("/"):
        errors.append(f"{where}: '{p}' must not contain '..'")
        return None
    if not glob_ok and _GLOB_CHARS & set(p):
        errors.append(f"{where}: '{p}' must be a literal directory (no * ? [)")
        return None
    if len(p) > 1:
        p = p.rstrip("/") or "/"
    return p


def _paths(v: Any, where: str, errors: list[str], *, glob_ok: bool) -> list[str]:
    out = []
    for i, p in enumerate(_strs(v, where, errors, max_len=MAX_PATH)):
        norm = _path(p, f"{where}[{i}]", errors, glob_ok=glob_ok)
        if norm is not None and norm not in out:
            out.append(norm)
    return out


# ── sections ─────────────────────────────────────────────────────────


def _network(raw: Any, errors: list[str]) -> dict:
    net = _obj(raw, "network", errors)
    _unknown(net, _NET_KEYS, "network", errors)
    default = net.get("default", "deny")
    if default != "deny":
        errors.append("network.default: only 'deny' is supported (allow-lists, never deny-lists)")
    allow = []
    for i, e in enumerate(_list(net.get("allow"), "network.allow", errors)):
        where = f"network.allow[{i}]"
        if not isinstance(e, dict):
            errors.append(f"{where}: must be an object")
            continue
        _unknown(e, _ALLOW_KEYS, where, errors)
        host = e.get("host")
        if not isinstance(host, str) or len(host) > 253 or not _HOST_RE.match(host):
            errors.append(f"{where}.host: must be a hostname, optionally '*.' wildcard "
                          f"(got {host!r})")
            continue
        port = _int(e.get("port"), 1, 65535, f"{where}.port", errors, default=443)
        methods = [m.upper() for m in _strs(e.get("methods"), f"{where}.methods", errors,
                                             max_len=10)] or ["*"]
        bad = [m for m in methods if m not in HTTP_METHODS]
        if bad:
            errors.append(f"{where}.methods: {bad} not in {', '.join(HTTP_METHODS)}")
            continue
        if "*" in methods and len(methods) > 1:
            methods = ["*"]
        paths = _strs(e.get("paths"), f"{where}.paths", errors) or ["/**"]
        for p in paths:
            if not p.startswith("/"):
                errors.append(f"{where}.paths: '{p}' must start with /")
        entry = {"host": host.lower(), "port": port, "methods": methods, "paths": paths}
        if isinstance(e.get("description"), str) and e["description"].strip():
            entry["description"] = e["description"][:MAX_TEXT]
        allow.append(entry)
    return {"default": "deny", "allow": allow}


def _filesystem(raw: Any, errors: list[str]) -> dict:
    fs = _obj(raw, "filesystem", errors)
    _unknown(fs, _FS_KEYS, "filesystem", errors)
    out = {
        "read_only": _paths(fs.get("read_only"), "filesystem.read_only", errors, glob_ok=False),
        "read_write": _paths(fs.get("read_write"), "filesystem.read_write", errors, glob_ok=False),
        "deny": _paths(fs.get("deny"), "filesystem.deny", errors, glob_ok=True),
        "classified": [],
        # required: the sandbox refuses to start where the kernel cannot enforce
        # these rules (no Landlock, e.g. Docker Desktop on macOS). best_effort:
        # it starts anyway, and Shield reports the degraded boundary.
        "kernel_enforcement": fs.get("kernel_enforcement", "required"),
    }
    if out["kernel_enforcement"] not in KERNEL_ENFORCEMENT:
        errors.append(f"filesystem.kernel_enforcement: must be one of {', '.join(KERNEL_ENFORCEMENT)}")
        out["kernel_enforcement"] = "required"
    both = set(out["read_only"]) & set(out["read_write"])
    if both:
        errors.append(f"filesystem: {sorted(both)} listed as both read_only and read_write")
    for i, c in enumerate(_list(fs.get("classified"), "filesystem.classified", errors)):
        where = f"filesystem.classified[{i}]"
        if not isinstance(c, dict) or set(c) - {"path", "classification"}:
            errors.append(f"{where}: must be {{path, classification}}")
            continue
        p = _path(str(c.get("path") or ""), f"{where}.path", errors, glob_ok=True)
        cls = c.get("classification")
        if cls not in CLASSIFICATIONS:
            errors.append(f"{where}.classification: must be one of {', '.join(CLASSIFICATIONS)}")
            continue
        if p:
            out["classified"].append({"path": p, "classification": cls})
    return out


def _process(raw: Any, errors: list[str]) -> dict:
    pr = _obj(raw, "process", errors)
    _unknown(pr, _PROC_KEYS, "process", errors)
    run_as = pr.get("run_as", "sandbox")
    if not isinstance(run_as, str) or not _USER_RE.match(run_as):
        errors.append("process.run_as: must be a POSIX user name")
        run_as = "sandbox"
    if run_as == "root":
        errors.append("process.run_as: 'root' is not allowed in a runtime profile")
    bins = []
    for i, b in enumerate(_strs(pr.get("allow_binaries"), "process.allow_binaries", errors,
                                max_len=MAX_PATH)):
        if not b.startswith("/") or _GLOB_CHARS & set(b) or ".." in b.split("/"):
            errors.append(f"process.allow_binaries[{i}]: '{b}' must be an absolute literal path")
            continue
        bins.append(b)
    return {
        "run_as": run_as,
        "allow_binaries": bins,
        "deny_commands": _strs(pr.get("deny_commands"), "process.deny_commands", errors),
        "no_new_privileges": _bool(pr.get("no_new_privileges"), True,
                                   "process.no_new_privileges", errors),
    }


def _tools(raw: Any, errors: list[str]) -> dict:
    t = _obj(raw, "tools", errors)
    _unknown(t, _TOOLS_KEYS, "tools", errors)
    extract_raw = t.get("extract")
    extract = []
    for i, x in enumerate(_list(extract_raw, "tools.extract", errors)
                          if extract_raw is not None else []):
        where = f"tools.extract[{i}]"
        if not isinstance(x, dict):
            errors.append(f"{where}: must be an object")
            continue
        _unknown(x, _EXTRACT_KEYS, where, errors)
        globs = _strs(x.get("tools"), f"{where}.tools", errors)
        param = x.get("param")
        kind = x.get("kind")
        if not globs:
            errors.append(f"{where}.tools: at least one tool glob")
        if not isinstance(param, str) or not param.strip() or len(param) > 100:
            errors.append(f"{where}.param: required dotted argument path")
            continue
        if kind not in EXTRACT_KINDS:
            errors.append(f"{where}.kind: must be one of {', '.join(EXTRACT_KINDS)}")
            continue
        extract.append({"tools": globs, "param": param.strip(), "kind": kind})
    return {
        "from_registry": _bool(t.get("from_registry"), True, "tools.from_registry", errors),
        "extract": extract if extract_raw is not None else copy.deepcopy(DEFAULT_EXTRACT),
    }


def _identity(raw: Any, errors: list[str]) -> dict:
    ident = _obj(raw, "identity", errors)
    _unknown(ident, _ID_KEYS, "identity", errors)
    out = {
        "require_agent_token": _bool(ident.get("require_agent_token"), False,
                                     "identity.require_agent_token", errors),
        "max_token_ttl_seconds": _int(ident.get("max_token_ttl_seconds"), 60, 86400,
                                      "identity.max_token_ttl_seconds", errors, default=900),
        "require_attestation": ident.get("require_attestation", "off"),
    }
    if out["require_attestation"] not in ATTESTATION_MODES:
        errors.append(f"identity.require_attestation: must be one of {', '.join(ATTESTATION_MODES)}")
        out["require_attestation"] = "off"
    sid = ident.get("spiffe_id")
    if sid is not None:
        if not isinstance(sid, str) or not sid.startswith("spiffe://") or len(sid) > 256:
            errors.append("identity.spiffe_id: must start with spiffe:// (≤ 256 chars)")
        else:
            out["spiffe_id"] = sid
    return out


def _resources(raw: Any, errors: list[str]) -> dict:
    r = _obj(raw, "resources", errors)
    _unknown(r, _RES_KEYS, "resources", errors)
    out: dict = {}
    if r.get("cpu") is not None:
        cpu = str(r["cpu"])
        if _CPU_RE.match(cpu):
            out["cpu"] = cpu
        else:
            errors.append("resources.cpu: e.g. \"2\", \"0.5\" or \"500m\"")
    if r.get("memory") is not None:
        mem = str(r["memory"])
        if _MEM_RE.match(mem):
            out["memory"] = mem
        else:
            errors.append("resources.memory: e.g. \"4Gi\" or \"512Mi\"")
    for key, lo, hi in (("gpu", 0, 64), ("max_pids", 1, 65536),
                        ("wall_clock_seconds", 1, 604800),
                        ("llm_tokens_per_hour", 1, 10_000_000_000)):
        v = _int(r.get(key), lo, hi, f"resources.{key}", errors)
        if v is not None:
            out[key] = v
    return out


# ── public API ───────────────────────────────────────────────────────


def valid_name(name: str) -> bool:
    return isinstance(name, str) and bool(_NAME_RE.match(name))


def validate_profile(raw: Any) -> dict:
    """Validate and normalize a profile. Raises ProfileError listing every problem.

    The result validates again unchanged (stored form == input form), so a
    profile loaded back from the store round-trips.
    """
    errors: list[str] = []
    if not isinstance(raw, dict):
        raise ProfileError(["profile: must be a JSON object"])
    _unknown(raw, _TOP_KEYS, "profile", errors)
    profile = {
        "description": "",
        "network": _network(raw.get("network"), errors),
        "filesystem": _filesystem(raw.get("filesystem"), errors),
        "process": _process(raw.get("process"), errors),
        "tools": _tools(raw.get("tools"), errors),
        "identity": _identity(raw.get("identity"), errors),
        "resources": _resources(raw.get("resources"), errors),
        "fail_closed": _bool(raw.get("fail_closed"), False, "fail_closed", errors),
    }
    desc = raw.get("description")
    if desc is not None:
        if not isinstance(desc, str) or len(desc) > MAX_TEXT:
            errors.append(f"description: string of at most {MAX_TEXT} characters")
        else:
            profile["description"] = desc
    if errors:
        raise ProfileError(errors)
    return profile


def profile_hash(profile: dict) -> str:
    """Stable content hash of a NORMALIZED profile: the bundle ETag and the
    value a sandbox attests it runs."""
    canonical = json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── templates ────────────────────────────────────────────────────────

_SYSTEM_RO = ["/usr", "/lib", "/etc", "/bin"]

TEMPLATES: dict[str, dict] = {
    "research-agent": {
        "description": "Reads the web and SaaS APIs through Shield; no local secrets, "
                       "no shell pipes to the network.",
        "network": {"default": "deny", "allow": [
            {"host": "api.github.com", "port": 443, "methods": ["GET"]},
            {"host": "*.googleapis.com", "port": 443, "methods": ["GET"]},
        ]},
        "filesystem": {
            "read_only": _SYSTEM_RO,
            "read_write": ["/sandbox", "/tmp"],
            "deny": ["~/.ssh/**", "~/.aws/**", "~/.config/gcloud/**", "/proc/*/environ",
                     "/var/run/docker.sock"],
            "classified": [{"path": "/sandbox/data/customers/**",
                            "classification": "confidential"}],
        },
        "process": {
            "run_as": "sandbox",
            "allow_binaries": ["/usr/bin/python3", "/usr/bin/curl"],
            "deny_commands": ["* | sh", "* | bash", "nc *", "ncat *", "ssh *", "scp *",
                              "rm -rf /*", "chmod 777 *"],
            "no_new_privileges": True,
        },
        "identity": {"require_agent_token": True, "max_token_ttl_seconds": 900,
                     "require_attestation": "warn"},
        "resources": {"cpu": "2", "memory": "4Gi", "gpu": 0, "max_pids": 256,
                      "wall_clock_seconds": 3600, "llm_tokens_per_hour": 200000},
    },
    "coding-agent": {
        "description": "Edits a checked-out repository and runs its tests; may push "
                       "to GitHub and fetch packages, nothing else.",
        "network": {"default": "deny", "allow": [
            {"host": "github.com", "port": 443},
            {"host": "api.github.com", "port": 443},
            {"host": "pypi.org", "port": 443, "methods": ["GET"]},
            {"host": "files.pythonhosted.org", "port": 443, "methods": ["GET"]},
            {"host": "registry.npmjs.org", "port": 443, "methods": ["GET"]},
        ]},
        "filesystem": {
            "read_only": _SYSTEM_RO,
            "read_write": ["/sandbox", "/tmp"],
            "deny": ["~/.ssh/**", "~/.aws/**", "~/.netrc", "/proc/*/environ",
                     "/var/run/docker.sock"],
        },
        "process": {
            "run_as": "sandbox",
            "allow_binaries": ["/usr/bin/git", "/usr/bin/python3", "/usr/bin/node",
                               "/usr/bin/npm", "/usr/bin/curl"],
            "deny_commands": ["curl * | sh", "curl * | bash", "wget * | sh", "nc *",
                              "ssh *", "git push --force*", "rm -rf /*"],
            "no_new_privileges": True,
        },
        "identity": {"require_agent_token": True, "max_token_ttl_seconds": 900,
                     "require_attestation": "warn"},
        "resources": {"cpu": "4", "memory": "8Gi", "gpu": 0, "max_pids": 1024,
                      "wall_clock_seconds": 7200, "llm_tokens_per_hour": 500000},
    },
    "support-bot": {
        "description": "Answers customers; talks only to Shield. No shell, no files "
                       "beyond its scratch space.",
        "network": {"default": "deny", "allow": []},
        "filesystem": {"read_only": _SYSTEM_RO, "read_write": ["/tmp"],
                       "deny": ["~/**", "/proc/*/environ"]},
        "process": {"run_as": "sandbox", "allow_binaries": ["/usr/bin/python3"],
                    "deny_commands": ["*"], "no_new_privileges": True},
        "identity": {"require_agent_token": True, "max_token_ttl_seconds": 600,
                     "require_attestation": "warn"},
        "resources": {"cpu": "1", "memory": "1Gi", "gpu": 0, "max_pids": 64,
                      "wall_clock_seconds": 1800, "llm_tokens_per_hour": 100000},
    },
}


def templates() -> dict[str, dict]:
    """Normalized copies of the starter profiles."""
    return {name: validate_profile(copy.deepcopy(t)) for name, t in TEMPLATES.items()}
