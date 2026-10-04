"""Agent OS events at ingest: osquery and Sysmon events that the Votal device
agent attributed to an AI agent's process tree, labelled with the agent
(AgentId) and checked against its runtime profile (ShieldProfileVerdict).
Spec: docs/specs/agent-os-events.md sections 3 and 4.2.

Runs in the ingest's background task (core/runtime_policy/events.ingest),
never on a request path. A verdict never blocks anything: it decides where an
event goes. `outside_profile` goes to the decision audit (action log) and the
alerts list; every event goes to telemetry and the hourly counters the portal
reads.

The verdict uses the same checks as the Claude Code hook route
(core/runtime_policy/hooks.py), with the agent root's cwd as @project, so
"expected" means exactly what a hook would have allowed.
"""

from __future__ import annotations

import json
import re
import threading
import time
from typing import Optional

SOURCES = ("osquery", "sysmon")
KINDS = ("process", "file", "network")
FILE_OPS = ("create", "write", "rename", "delete", "read")
VERDICTS = ("expected", "outside_profile", "no_profile")
ALERTS_MAX = 500
ALERTS_TTL_S = 7 * 86400
COUNTS_TTL_S = 26 * 3600
_LABEL = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_RUN = re.compile(r"^\d{1,10}:\d{1,13}$")
_CAPS = {"command_line": 1024, "image": 1024, "path": 1024, "cwd": 1024, "user": 200,
         "dest_host": 253, "dest_ip": 64}


class OsEventError(ValueError):
    pass


def clean_detail(kind: str, detail: dict) -> dict:
    """The detail of an osquery or sysmon event, its known fields checked and
    capped. Raises OsEventError."""
    if kind not in KINDS:
        raise OsEventError(f"kind for osquery and sysmon events: one of {', '.join(KINDS)}")
    label = detail.get("agent_label")
    if not isinstance(label, str) or not _LABEL.match(label):
        raise OsEventError("detail.agent_label: the agent's label (lowercase, digits, _)")
    out = {k: v for k, v in detail.items() if k not in _CAPS}
    for k, n in _CAPS.items():
        v = detail.get(k)
        if v is None:
            continue
        if not isinstance(v, str):
            raise OsEventError(f"detail.{k}: text")
        out[k] = v[:n]
    for k in ("pid", "ppid", "dest_port"):
        v = detail.get(k)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
            raise OsEventError(f"detail.{k}: a non-negative integer")
    run = detail.get("run")
    if run is not None and (not isinstance(run, str) or not _RUN.match(run)):
        raise OsEventError("detail.run: \"<root pid>:<root start time>\"")
    if kind == "file":
        if not out.get("path"):
            raise OsEventError("detail.path: required for file events")
        if detail.get("op") not in FILE_OPS:
            raise OsEventError(f"detail.op: one of {', '.join(FILE_OPS)}")
    if kind == "network" and not (out.get("dest_host") or out.get("dest_ip")):
        raise OsEventError("detail.dest_host or dest_ip: required for network events")
    # Never contents: a sender that adds them has them dropped, not stored.
    for k in ("content", "contents", "body", "payload", "text"):
        out.pop(k, None)
    return out


# ── one spelling for every OS (the profile is written in POSIX form) ──

_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_WIN_HOME = re.compile(r"^[A-Za-z]:/Users/[^/]+(?=/|$)", re.I)
_WIN_EXT = re.compile(r"\.(exe|com|cmd|bat)$", re.I)
_TOKEN = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')


def norm_path(p: str) -> str:
    """POSIX form for a path from any OS. Windows: C:\\Users\\<name>\\x is
    ~/x, other drive paths are /<drive>/x. macOS and Linux paths are left to
    the hook's normalizer (which collapses /Users/<name> and /home/<name>)."""
    if not isinstance(p, str) or not _WIN_DRIVE.match(p):
        return p
    q = p.replace("\\", "/")
    m = _WIN_HOME.match(q)
    if m:
        return "~" + q[m.end():]
    return "/" + q[0].lower() + q[2:]


def norm_command(cmd: str) -> str:
    """The command line as a person would type it, so profile patterns written
    for the hook (`openssl enc*`) match OS events too: the program by name, not
    by path (/usr/bin/openssl, "C:\\...\\openssl.exe"), and Windows paths in
    the arguments in POSIX form."""
    tokens = _TOKEN.findall(cmd or "")
    if not tokens:
        return cmd or ""
    out = []
    for i, tok in enumerate(tokens):
        quoted = len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'"
        word = tok[1:-1] if quoted else tok
        if i == 0:
            word = _WIN_EXT.sub("", word.replace("\\", "/").rsplit("/", 1)[-1])
        elif _WIN_DRIVE.match(word):
            word = norm_path(word)
        if " " in word:
            word = "'" + word.replace("'", "'\\''") + "'"
        out.append(word)
    return " ".join(out)


# ── the verdict ──────────────────────────────────────────────────────


def _net_allowed(view, host: str, port: int, shield_hosts: set) -> bool:
    host = (host or "").lower()
    if host in shield_hosts:
        return True
    return any(host_re.fullmatch(host) and p == port for host_re, p, _m, _path in view.net)


def verdict(cp, kind: str, detail: dict, shield_hosts: Optional[set] = None) -> tuple[str, str]:
    """(verdict, reason) for one event under a compiled runtime profile."""
    from core.runtime_policy import hooks

    if cp is None:
        return "no_profile", "the agent has no runtime profile"
    cwd = norm_path(detail.get("cwd") or "")
    project = hooks.session_path(cwd, "/") if cwd.startswith(("/", "~")) else None
    view = hooks.session_view(cp, project)
    hosts = shield_hosts or set()
    if kind == "process":
        cmd = norm_command(detail.get("command_line") or "")
        if not cmd:
            return "expected", ""
        d = hooks._bash(view, cmd, hosts, None)
        return ("outside_profile", d.reason) if d.decision == "deny" else ("expected", "")
    if kind == "file":
        path = hooks.session_path(norm_path(detail["path"]), view.workdir)
        why = hooks._denied_path(view, path) if detail.get("op") == "read" \
            else hooks._check_write(view, path)
        return ("outside_profile", why) if why else ("expected", "")
    host = detail.get("dest_host") or detail.get("dest_ip") or ""
    port = int(detail.get("dest_port") or 443)
    if _net_allowed(view, host, port, hosts):
        return "expected", ""
    return "outside_profile", f"{host}:{port} is not in the profile's network allow-list"


def join(tenant_id: str, ev: dict, shield_hosts: Optional[set] = None) -> dict:
    """The event with AgentId, ShieldProfileVerdict and its reason in detail,
    and the decision set from the verdict."""
    from core.dlp import agent_os_events
    from core.runtime_policy import check as rc

    d = ev["detail"]
    block = agent_os_events.block_for(tenant_id) or {}
    agent_id = (block.get("agents") or {}).get(d["agent_label"], "")
    cp = rc.profile_for(tenant_id, agent_id) if agent_id else None
    v, reason = verdict(cp, ev["kind"], d, shield_hosts)
    d["AgentId"], d["ShieldProfileVerdict"] = agent_id, v
    if reason:
        d["reason"] = reason[:500]
    ev["agent_id"] = ev["agent_id"] or agent_id
    ev["profile"] = cp.name if cp else ""
    ev["profile_hash"] = cp.hash if cp else ""
    ev["decision"] = "audit" if v == "outside_profile" else "allow"
    ev["severity"] = "medium" if v == "outside_profile" else "info"
    return ev


# ── alerts and counters (the portal's read route) ────────────────────

_mem_lock = threading.Lock()
_mem_lists: dict[str, list] = {}
_mem_hashes: dict[str, dict] = {}


def _redis():
    from storage import tenant_store
    return tenant_store._get_redis()


def _alerts_key(tenant_id: str) -> str:
    return f"agent_os_alerts:{tenant_id}"


def _counts_key(tenant_id: str, hour: int) -> str:
    return f"agent_os_counts:{tenant_id}:{hour}"


def _value(ev: dict) -> str:
    d = ev["detail"]
    if ev["kind"] == "process":
        return d.get("command_line") or d.get("image") or ""
    if ev["kind"] == "file":
        return f"{d.get('op', '')} {d.get('path', '')}"
    return f"{d.get('dest_host') or d.get('dest_ip') or ''}:{d.get('dest_port') or ''}"


def record(tenant_id: str, events: list[dict], now: Optional[float] = None) -> None:
    """Alerts for outside_profile events, and per-laptop, per-agent hourly
    counts for all. One round trip per batch where the store allows."""
    now = time.time() if now is None else now
    hour = int(now // 3600)
    counts: dict[str, int] = {}
    alerts = []
    for ev in events:
        d = ev["detail"]
        device = (d.get("device_id") or ev.get("agent_instance_id") or "unknown")[:200]
        who = d.get("AgentId") or d.get("agent_label") or "?"
        key = f"{device}|{who}|{ev['kind']}"
        counts[key] = counts.get(key, 0) + 1
        if d.get("ShieldProfileVerdict") == "outside_profile":
            counts[f"{device}|{who}|outside"] = counts.get(f"{device}|{who}|outside", 0) + 1
            alerts.append(json.dumps({
                "at": int(ev.get("at") or now), "device": device, "agent": who,
                "agent_label": d.get("agent_label", ""), "kind": ev["kind"],
                "value": _value(ev)[:300], "reason": d.get("reason", "")[:300],
                "user": d.get("user", ""), "source": ev["source"]}, separators=(",", ":")))
    r = _redis()
    if r is None:
        with _mem_lock:
            lst = _mem_lists.setdefault(_alerts_key(tenant_id), [])
            for a in alerts:
                lst.insert(0, a)
            del lst[ALERTS_MAX:]
            h = _mem_hashes.setdefault(_counts_key(tenant_id, hour), {})
            for k, n in counts.items():
                h[k] = h.get(k, 0) + n
        return
    try:
        if alerts:
            r.lpush(_alerts_key(tenant_id), *alerts)
            r.ltrim(_alerts_key(tenant_id), 0, ALERTS_MAX - 1)
            r.expire(_alerts_key(tenant_id), ALERTS_TTL_S)
        for k, n in counts.items():
            r.hincrby(_counts_key(tenant_id, hour), k, n)
        if counts:
            r.expire(_counts_key(tenant_id, hour), COUNTS_TTL_S)
    except Exception:
        pass


def summary(tenant_id: str, since: float = 0, now: Optional[float] = None) -> dict:
    """{alerts: newest first since `since`, laptops: [{device, agent, process,
    file, network, outside}] over the last 24 hours}."""
    now = time.time() if now is None else now
    r = _redis()
    hours = [int(now // 3600) - i for i in range(24)]
    if r is None:
        with _mem_lock:
            raw_alerts = list(_mem_lists.get(_alerts_key(tenant_id), []))
            hashes = [dict(_mem_hashes.get(_counts_key(tenant_id, h), {})) for h in hours]
    else:
        try:
            raw_alerts = r.lrange(_alerts_key(tenant_id), 0, ALERTS_MAX - 1) or []
            hashes = [r.hgetall(_counts_key(tenant_id, h)) or {} for h in hours]
        except Exception:
            raw_alerts, hashes = [], []
    alerts = []
    for a in raw_alerts:
        try:
            rec = json.loads(a.decode() if isinstance(a, bytes) else a)
        except (ValueError, AttributeError):
            continue
        if rec.get("at", 0) >= since:
            alerts.append(rec)
    totals: dict[tuple, dict] = {}
    for h in hashes:
        for k, n in h.items():
            k = k.decode() if isinstance(k, bytes) else k
            try:
                device, agent, kind = k.rsplit("|", 2)
                n = int(n)
            except (ValueError, TypeError):
                continue
            row = totals.setdefault((device, agent), {"device": device, "agent": agent,
                                                      "process": 0, "file": 0, "network": 0,
                                                      "outside": 0})
            if kind in row:
                row[kind] += n
    laptops = sorted(totals.values(), key=lambda r: (-r["outside"], r["device"], r["agent"]))
    return {"alerts": alerts, "laptops": laptops}


def reset_for_tests() -> None:
    with _mem_lock:
        _mem_lists.clear()
        _mem_hashes.clear()


__all__ = ["KINDS", "OsEventError", "SOURCES", "VERDICTS", "clean_detail", "join", "norm_command",
           "norm_path", "record", "summary", "verdict"]
