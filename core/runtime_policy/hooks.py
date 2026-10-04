"""Coding-agent hooks: a Claude Code PreToolUse call judged against the agent's
runtime profile. Spec: docs/specs/agent-hook-adapter.md.

Claude Code asks before every tool call; this maps the call to the checks the
runtime profile already has (core/runtime_policy/check.py) and answers in
Claude Code's hook format. Deterministic, no LLM, no I/O: the route
(api/routes_hooks.py) loads the profile and writes the audit afterwards.

What a laptop adds over a sandbox:
  * "@project" in filesystem paths is the session's cwd, which differs per
    call. The profile is specialised per project and cached.
  * macOS aliases: Claude Code sends cwd as the real path (/private/tmp/...)
    while a path the model typed keeps its alias (/tmp/...). Both sides are
    rewritten to /private/... before comparing, so spelling cannot dodge a rule.
  * Reads are limited by filesystem.deny only: a coding agent reads widely.
  * Bash is judged on the command (deny_commands, allow_binaries), the paths
    it names (filesystem.deny; redirect targets against the writable paths)
    and the URLs it hands to curl or wget (network.allow). The last two are
    best effort: a program the agent writes itself is not seen here.
"""

from __future__ import annotations

import dataclasses
import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Any, Optional

from core.runtime_policy import check as rc
from core.runtime_policy.model import SESSION_ROOT

SOURCE = "claude_code"
WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
               "NotebookEdit": "notebook_path"}
READ_TOOLS = {"Read", "Glob", "Grep"}
_MAC_ALIASES = ("/tmp", "/var", "/etc")
_FETCHERS = {"curl", "wget"}
_DATA_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F",
               "--form", "--json", "--post-data", "--post-file", "-T", "--upload-file"}
_REDIRECT = re.compile(r"^(?:\d|&)?>>?\|?$")            # >  >>  2>  &>  >|
_REDIRECT_JOINED = re.compile(r"^(?:\d|&)?>>?\|?(?P<target>[^>&].*)$")   # >file  2>file
_HARMLESS_TARGETS = re.compile(r"^/dev/(null|stdout|stderr|tty|fd/\d+)$")
MAX_TOKENS = 200
#: More segments than this is not a command an agent needs, and checking it
#: would cost more than the latency budget (spec section 2).
MAX_SEGMENTS = 256
_VIEW_CACHE_MAX = 2048


@dataclass
class Decision:
    decision: str                 # "allow" | "deny" | "ask"
    kind: str = ""                # "exec" | "file" | "net" | "tool" | "" (not checked)
    value: str = ""
    reason: str = ""
    op: str = ""                  # file access mode, for kind == "file"
    method: str = "GET"           # HTTP method, for kind == "net"
    checked: bool = True          # False for tools this adapter does not judge


# ── paths ────────────────────────────────────────────────────────────


def _alias(path: str) -> str:
    for a in _MAC_ALIASES:
        if path == a or path.startswith(a + "/"):
            return "/private" + path
    return path


def session_path(value: str, workdir: str, home: Optional[str] = None) -> str:
    """normalize_path, then the macOS alias rewrite. With the user's real home
    only that home becomes ~ (/Users/Shared/x stays as it is); without it,
    any /Users/<name> or /home/<name> does, as in a sandbox."""
    v = value.strip()
    if home:
        if v == home or v.startswith(home + "/"):
            v = "~" + v[len(home):]
        return _alias(rc.normalize_path(v, workdir, collapse_home=False))
    return _alias(rc.normalize_path(v, workdir))


def home_dir(payload: dict) -> Optional[str]:
    """The user's home, from Claude Code's transcript_path
    (<home>/.claude/projects/...). None when it is absent or odd."""
    t = payload.get("transcript_path")
    if not isinstance(t, str) or "/.claude/" not in t or len(t) > rc.MAX_VALUE:
        return None
    home = t.split("/.claude/", 1)[0]
    return home if rc._HOME_PREFIX.fullmatch(home) else None


def project_root(cwd: Any, home: Optional[str] = None) -> Optional[str]:
    """The session's project folder in normalized form, or None when Claude
    Code sent no usable cwd (then @project rules match nothing)."""
    if not isinstance(cwd, str) or not cwd.startswith("/") or "\x00" in cwd \
            or len(cwd) > rc.MAX_VALUE:
        return None
    return session_path(cwd, "/", home)


def _resolve(p: str, project: Optional[str]) -> Optional[str]:
    if p == SESSION_ROOT or p.startswith(SESSION_ROOT + "/"):
        return None if project is None else project + p[len(SESSION_ROOT):]
    return _alias(p)


_views: dict = {}


def session_view(cp: rc.CompiledProfile, project: Optional[str]) -> rc.CompiledProfile:
    """The compiled profile with @project and the macOS aliases resolved for
    this session. Cached per (profile, project)."""
    key = (cp.name, cp.hash, project)
    hit = _views.get(key)
    if hit is not None:
        return hit
    fs = cp.raw["filesystem"]

    def roots(paths):
        return [r for r in (_resolve(p, project) for p in paths) if r]

    view = dataclasses.replace(
        cp,
        fs_deny=rc._path_re(roots(fs["deny"])),
        fs_read=roots(fs["read_only"]) + roots(fs["read_write"]),
        fs_write=roots(fs["read_write"]),
        workdir=project or "/",
    )
    if len(_views) >= _VIEW_CACHE_MAX:
        _views.clear()
    _views[key] = view
    return view


def _denied_path(view: rc.CompiledProfile, path: str) -> Optional[str]:
    if view.fs_deny is not None and view.fs_deny.match(path):
        return f"path {path} is denied by the runtime profile"
    return None


def _check_write(view: rc.CompiledProfile, path: str) -> Optional[str]:
    why = _denied_path(view, path)
    if why:
        return why
    if view.fs_write and not any(rc._under(path, r) for r in view.fs_write):
        return (f"path {path} is outside the profile's writable paths "
                f"({', '.join(view.fs_write)})")
    if not view.fs_write and view.raw["filesystem"]["read_write"]:
        # The profile limits writes, but none of its writable paths resolved
        # (only @project, and no usable cwd): nothing is writable, never
        # everything.
        return (f"path {path} is not writable: the profile allows writes only in "
                f"{', '.join(view.raw['filesystem']['read_write'])}, and this session's "
                f"project folder is not known")
    return None


# ── Bash ─────────────────────────────────────────────────────────────


def _tokens(segment: str) -> list[str]:
    try:
        toks = shlex.split(segment)
    except ValueError:            # heredocs, stray quotes: still look at the words
        toks = segment.split()
    return toks[:MAX_TOKENS]


def _pathlike(tok: str) -> bool:
    return tok.startswith(("/", "~", "./", "../")) or ("/" in tok and "://" not in tok)


def _bash(view: rc.CompiledProfile, command: str, shield_hosts: set,
          home: Optional[str]) -> Decision:
    if len(rc._SEGMENT_SPLIT.findall(command)) >= MAX_SEGMENTS:
        return Decision("deny", "exec", command[:300], f"command has more than {MAX_SEGMENTS} "
                        f"parts; not checked, so not allowed")
    why = rc._check_exec(view, command)
    if why:
        return Decision("deny", "exec", command, why)
    # Original case for paths and URLs: rc._norm_cmd lower-cases.
    segments = [s for s in rc._SEGMENT_SPLIT.split(command) if s.strip()]
    for seg in segments:
        toks = _tokens(seg)
        method, urls = "GET", []
        prog = posixpath.basename(toks[0]) if toks else ""
        for i, tok in enumerate(toks):
            target = None
            if _REDIRECT.match(tok) and i + 1 < len(toks):
                target = toks[i + 1]
            else:
                m = _REDIRECT_JOINED.match(tok)
                if m:
                    target = m.group("target")
            if target and not _HARMLESS_TARGETS.match(target):
                path = session_path(target, view.workdir, home)
                why = _check_write(view, path)
                if why:
                    return Decision("deny", "file", path, why, op="write")
            word = tok.split("=", 1)[1] if tok.startswith("-") and "=" in tok else tok
            if _pathlike(word):
                path = session_path(word, view.workdir, home)
                why = _denied_path(view, path)
                if why:
                    return Decision("deny", "file", path, why, op="read")
            if prog in _FETCHERS:
                if tok in ("-X", "--request", "--method") and i + 1 < len(toks):
                    method = toks[i + 1].upper()[:10]
                elif tok.split("=", 1)[0] in _DATA_FLAGS and method == "GET":
                    method = "POST"
                elif "://" in tok and not tok.startswith("-"):
                    urls.append(tok)
        for url in urls:
            why = rc._check_net(view, url, method, shield_hosts)
            if why:
                return Decision("deny", "net", url, why, method=method)
    pat = rc.match_command(view.ask_cmd, command)
    if pat is not None:
        return Decision("ask", "exec", command, f"command matches pattern '{pat}', which needs "
                                                 f"your confirmation")
    return Decision("allow", "exec", command)


# ── the decision ─────────────────────────────────────────────────────


def _str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def decide(cp: Optional[rc.CompiledProfile], payload: dict,
           shield_hosts: Optional[set] = None) -> Decision:
    """Allow, deny or ask for one PreToolUse call. cp None = no profile."""
    hosts = shield_hosts or set()
    tool = _str(payload.get("tool_name")) or ""
    ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    if cp is None:
        return Decision("allow", reason="agent has no runtime profile", checked=False)
    home = home_dir(payload)
    view = session_view(cp, project_root(payload.get("cwd"), home))

    def too_long(kind, value):
        return Decision("deny", kind, value[:300], f"value longer than {rc.MAX_VALUE} "
                        f"characters; not checked, so not allowed")

    if tool == "Bash":
        cmd = _str(ti.get("command"))
        if cmd is None:
            return Decision("deny", "exec", "", "command missing or not text")
        if len(cmd) > rc.MAX_VALUE:
            return too_long("exec", cmd)
        return _bash(view, cmd, hosts, home)

    if tool in WRITE_TOOLS:
        raw = _str(ti.get(WRITE_TOOLS[tool])) or _str(ti.get("file_path"))
        if not raw:
            return Decision("deny", "file", "", "file path missing", op="write")
        if len(raw) > rc.MAX_VALUE:
            return too_long("file", raw)
        path = session_path(raw, view.workdir, home)
        why = _check_write(view, path)
        return Decision("deny" if why else "allow", "file", path, why or "", op="write")

    if tool in READ_TOOLS:
        values = [_str(ti.get("file_path")) or _str(ti.get("path")) or view.workdir]
        pattern = _str(ti.get("pattern"))
        if tool == "Glob" and pattern and pattern.startswith(("/", "~")):
            values.append(pattern)
        for raw in values:
            if len(raw) > rc.MAX_VALUE:
                return too_long("file", raw)
            path = session_path(raw, view.workdir, home)
            why = _denied_path(view, path)
            if why:
                return Decision("deny", "file", path, why, op="read")
        return Decision("allow", "file", session_path(values[0], view.workdir, home), op="read")

    if tool == "WebFetch":
        url = _str(ti.get("url"))
        if not url:
            return Decision("deny", "net", "", "URL missing")
        if len(url) > rc.MAX_VALUE:
            return too_long("net", url)
        why = rc._check_net(view, url, "GET", hosts)
        return Decision("deny" if why else "allow", "net", url, why or "")

    if tool.startswith("mcp__"):
        bare = tool.split("__", 2)[-1]
        # The file arguments the profile extracts, alias-rewritten like every
        # other path here, so /tmp/... and the cwd's /private/tmp/... agree.
        params = dict(ti)
        for x in view.extract:
            if x.kind != "file" or "." in x.param or not x.tools.fullmatch(bare.lower()):
                continue
            v = params.get(x.param)
            if isinstance(v, str):
                params[x.param] = session_path(v[:rc.MAX_VALUE], view.workdir, home)
            elif isinstance(v, list):
                params[x.param] = [session_path(i[:rc.MAX_VALUE], view.workdir, home)
                                   if isinstance(i, str) else i for i in v]
        violations = rc.evaluate(view, bare, params, hosts)
        if violations:
            v = violations[0]
            return Decision("deny", "tool", tool, f"{v['reason']} ({v['kind']} {v['value']})")
        return Decision("allow", "tool", tool)

    return Decision("allow", "", tool, "not checked by the hook adapter", checked=False)


# ── file changes, for per-session limits (core/runtime_policy/hook_limits.py) ──

_WRITE_PROGS = {"cp", "mv", "tee", "touch", "install", "ln", "rsync", "dd", "truncate"}
_DELETE_PROGS = {"rm", "rmdir", "unlink", "shred", "srm", "trash"}
_WRAPPERS = {"sudo", "xargs", "env", "nohup", "time", "command", "exec", "nice", "doas"}
_DELETE_TOOL = re.compile(r"(^|[_.-])(delete|remove|rm|unlink|trash)([_.-]|$)", re.I)


def _program(toks: list[str]) -> tuple[str, list[str]]:
    """The program a segment runs, looking through sudo, xargs, env and the
    like, and its arguments."""
    i = 0
    while i < len(toks):
        name = posixpath.basename(toks[i])
        if name in _WRAPPERS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i]) or \
                (i > 0 and toks[i].startswith("-")):
            i += 1
            continue
        return name, toks[i + 1:]
    return "", []


def file_changes(payload: dict) -> tuple[int, int]:
    """(writes, deletes) this call would make, counted per tool call, Bash
    redirect or command segment, never per file."""
    tool = _str(payload.get("tool_name")) or ""
    ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    if tool in WRITE_TOOLS:
        return 1, 0
    if tool.startswith("mcp__"):
        bare = tool.split("__", 2)[-1]
        if _DELETE_TOOL.search(bare):
            return 0, 1
        return (1, 0) if rc._WRITE_TOOL.search(bare) else (0, 0)
    if tool != "Bash" or not isinstance(ti.get("command"), str):
        return 0, 0
    writes = deletes = 0
    for seg in rc._SEGMENT_SPLIT.split(ti["command"][:rc.MAX_VALUE]):
        toks = _tokens(seg)
        for i, tok in enumerate(toks):
            target = toks[i + 1] if _REDIRECT.match(tok) and i + 1 < len(toks) else None
            m = None if target else _REDIRECT_JOINED.match(tok)
            target = target or (m.group("target") if m else None)
            if target and not _HARMLESS_TARGETS.match(target):
                writes += 1
        prog, args = _program(toks)
        if prog in _DELETE_PROGS or (prog == "find" and ("-delete" in args or any(
                posixpath.basename(a) in _DELETE_PROGS for a in args))) or \
                (prog == "git" and args[:1] in (["rm"], ["clean"])):
            deletes += 1
        elif prog in _WRITE_PROGS:
            writes += 1
    return writes, deletes


def hook_response(d: Decision) -> dict:
    """Claude Code's PreToolUse answer. Allow is {}: Shield never grants a
    permission Claude Code would otherwise ask for."""
    if d.decision == "allow":
        return {}
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": d.decision,
        "permissionDecisionReason": f"Blocked by Votal Shield: {d.reason}" if d.decision == "deny"
        else f"Votal Shield: {d.reason}",
    }}


_KIND_EVENT = {"exec": "process", "file": "file", "net": "network", "tool": "action", "": "action"}


def runtime_event(d: Decision, payload: dict, *, agent_id: str, profile: Optional[rc.CompiledProfile],
                  user: str = "", device_id: str = "", fleet: str = "",
                  monitor: bool = False) -> dict:
    """The runtime event (core/runtime_policy/events.py shape) for this
    decision. Never file contents or the command's output: the command line,
    path or URL only, capped. `ask` is recorded as an audit decision; so is a
    deny in monitor mode, which did not block anything (detail.monitor and
    detail.would_decide say what enforce would have done)."""
    tool = (_str(payload.get("tool_name")) or "")[:200]
    detail: dict = {"tool": tool, "hook": "PreToolUse", "user": user[:200],
                    "device_id": device_id[:200],
                    "permission_mode": (_str(payload.get("permission_mode")) or "")[:40],
                    "tool_use_id": (_str(payload.get("tool_use_id")) or "")[:200],
                    "cwd": (_str(payload.get("cwd")) or "")[:500]}
    if d.reason:
        detail["reason"] = d.reason[:500]
    if d.kind == "exec":
        detail["command"] = d.value[:1000]
    elif d.kind == "file":
        detail["path"], detail["op"] = d.value[:500], d.op or "read"
    elif d.kind == "net":
        from urllib.parse import urlparse
        u = urlparse(d.value if "://" in d.value else "https://" + d.value)
        detail.update(url=d.value[:500], host=(u.hostname or "")[:253],
                      port=u.port or (443 if u.scheme == "https" else 80),
                      path=(u.path or "/")[:300], method=d.method)
    if d.decision == "ask":
        detail["asked"] = True
    if fleet:
        detail["fleet"] = fleet[:64]
    decision = {"allow": "allow", "deny": "deny", "ask": "audit"}[d.decision]
    if monitor:
        detail["monitor"], detail["would_decide"] = True, d.decision
        decision = "allow" if d.decision == "allow" else "audit"
    return {"source": SOURCE, "kind": _KIND_EVENT[d.kind],
            "decision": decision,
            "severity": "medium" if decision == "deny" else "info",
            "agent_id": agent_id[:200], "agent_instance_id": device_id[:200],
            "session_id": (_str(payload.get("session_id")) or "")[:512],
            "profile": profile.name if profile else "",
            "profile_hash": profile.hash if profile else "", "detail": detail}


def reset_cache_for_tests() -> None:
    _views.clear()


__all__ = ["Decision", "SOURCE", "decide", "file_changes", "hook_response", "project_root",
           "runtime_event", "session_path", "session_view"]
