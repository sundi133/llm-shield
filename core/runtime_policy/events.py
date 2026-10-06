"""Runtime events: what sandboxes and proxies report back to Shield.

A sandbox that denies `curl evil.io` or loses its kernel filesystem rules
should not be the only one who knows. Events are normalized into one shape
(spec §4.2) and written to the decision audit (guardrail "runtime_boundary"),
telemetry (ASIM NetworkSession / FileEvent / ProcessEvent / AuditEvent), and,
for an allowed read of a classified file, cross-app flow control.

Events are evidence, never commands: they can add session state or raise an
alert; nothing here can lift a block or delete state. The tenant is always the
authenticated caller's, never a field of the event.

OpenShell is supported natively: send its OCSF log lines as
{"source": "openshell", "raw": "<line>"} and they are parsed here, so the
forwarding adapter stays a dumb pipe (examples/runtime/openshell_events.py).
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

SOURCES = ("openshell", "k8s", "cilium", "falco", "squid", "envoy", "claude_code", "osquery",
           "sysmon", "custom")
KINDS = ("network", "file", "process", "resource", "policy", "action", "dlp")
DECISIONS = ("deny", "allow", "audit")
SEVERITIES = ("info", "low", "medium", "high", "critical")
MAX_DETAIL_BYTES = 4096
MAX_ID = 200
#: Sync sidecar report -> minimum severity. A sandbox loosened outside Shield
#: is critical whatever the reporter says.
#: Device DLP agent verdicts (docs/specs/device-dlp-agent.md §3.3).
DLP_VERDICTS = ("allow", "block", "justify", "redact", "uncertain", "monitor")
#: The agent records verdicts, never the prompt: only a rule-redacted excerpt,
#: and only when the tenant turns on privacy.capture_excerpt.
DLP_TEXT_KEYS = ("prompt", "text", "body", "content", "message")
DLP_EXCERPT_MAX = 200
SIDECAR_OPS = {"applied": "info", "reverted": "high", "restart_required": "high",
               "apply_failed": "high", "tampered": "critical"}


class EventError(ValueError):
    pass


def _s(v: Any, n: int = MAX_ID) -> str:
    return str(v)[:n] if v is not None else ""


def _ts(v: Any) -> float:
    if v in (None, ""):
        return time.time()
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise EventError(f"at: not an ISO-8601 time or epoch seconds: {str(v)[:40]!r}")


def normalize(raw: dict) -> dict:
    """One event in the canonical shape. Raises EventError."""
    if not isinstance(raw, dict):
        raise EventError("event must be an object")
    source = raw.get("source", "custom")
    if source not in SOURCES:
        raise EventError(f"source must be one of {', '.join(SOURCES)}")
    if source == "openshell" and raw.get("raw"):
        parsed = parse_openshell_line(str(raw["raw"]))
        if parsed is None:
            raise EventError("raw: not an OpenShell OCSF decision line")
        raw = {**parsed, **{k: v for k, v in raw.items() if k != "raw" and v not in (None, "")}}
    kind, decision = raw.get("kind"), raw.get("decision")
    if kind not in KINDS:
        raise EventError(f"kind must be one of {', '.join(KINDS)}")
    if decision not in DECISIONS:
        raise EventError(f"decision must be one of {', '.join(DECISIONS)}")
    severity = raw.get("severity") or ("medium" if decision == "deny" else "info")
    if severity not in SEVERITIES:
        raise EventError(f"severity must be one of {', '.join(SEVERITIES)}")
    detail = raw.get("detail") or {}
    if not isinstance(detail, dict):
        raise EventError("detail must be an object")
    if len(json.dumps(detail, default=str)) > MAX_DETAIL_BYTES:
        raise EventError(f"detail larger than {MAX_DETAIL_BYTES} bytes")
    op = detail.get("op")
    if kind == "policy" and op is not None:
        # Sync sidecar reports (docs/specs/runtime-live-policy.md §5.1). On
        # file events detail.op is the access mode (read/write) instead.
        if op not in SIDECAR_OPS:
            raise EventError(f"detail.op on a policy event must be one of "
                             f"{', '.join(SIDECAR_OPS)}")
        floor = SIDECAR_OPS[op]
        if SEVERITIES.index(severity) < SEVERITIES.index(floor):
            severity = floor
    if kind == "dlp":
        if detail.get("verdict") not in DLP_VERDICTS:
            raise EventError(f"detail.verdict on a dlp event must be one of "
                             f"{', '.join(DLP_VERDICTS)}")
        present = [k for k in DLP_TEXT_KEYS if k in detail]
        if present:
            raise EventError(f"detail.{present[0]}: dlp events carry no prompt text (send "
                             f"prompt_sha256 and prompt_len; excerpt only with capture_excerpt)")
        excerpt = detail.get("excerpt")
        if excerpt is not None and (not isinstance(excerpt, str)
                                    or len(excerpt) > DLP_EXCERPT_MAX):
            raise EventError(f"detail.excerpt: text of at most {DLP_EXCERPT_MAX} characters")
    if source in ("osquery", "sysmon"):
        # Agent OS events (docs/specs/agent-os-events.md): attributed on the
        # laptop; the verdict and the decision are set at ingest (os_events.join).
        from core.runtime_policy import os_events
        try:
            detail = os_events.clean_detail(kind, detail)
        except os_events.OsEventError as e:
            raise EventError(str(e))
    return {
        "source": source,
        "kind": kind,
        "decision": decision,
        "severity": severity,
        "agent_id": _s(raw.get("agent_id")),
        "agent_instance_id": _s(raw.get("agent_instance_id")),
        "session_id": _s(raw.get("session_id"), 512),
        "profile": _s(raw.get("profile"), 64),
        "profile_hash": _s(raw.get("profile_hash"), 80),
        "detail": detail,
        "at": _ts(raw.get("at")),
    }


# ── OpenShell OCSF lines ─────────────────────────────────────────────

_OCSF = re.compile(r"^\[(?P<ts>\d+(?:\.\d+)?)\]\s+\[[^\]]*\]\s+\[OCSF\s*\]\s+\[ocsf\]\s+"
                   r"(?P<cat>[A-Z]+):(?P<act>[A-Z_]+)\s+\[(?P<sev>[A-Z]+)\]\s?(?P<rest>.*)$")
_NET = re.compile(r"^(?P<dec>ALLOWED|DENIED)\s+(?P<bin>\S+?)\((?P<pid>\d+)\)\s+->\s+"
                  r"(?P<host>[^\s:]+):(?P<port>\d+)")
_HTTP = re.compile(r"^(?P<dec>ALLOWED|DENIED)\s+(?P<method>[A-Z]+)\s+\S+?://(?P<host>[^/\s:]+)"
                   r"(?::(?P<port>\d+))?(?P<path>/\S*)?")
_BRACKET = re.compile(r"\[([a-z_]+:[^\]]*)\]")
_SEV = {"INFO": "info", "LOW": "low", "MED": "medium", "HIGH": "high", "CRIT": "critical",
        "CRITICAL": "critical"}


def parse_openshell_line(line: str) -> Optional[dict]:
    """Canonical-event fields for an OpenShell OCSF log line that carries a
    decision, or None for lines that do not (lifecycle chatter).

    Handles, as emitted by OpenShell 0.0.80:
      NET:OPEN  ... DENIED /usr/bin/curl(38) -> example.com:443 [policy:- engine:opa] [reason:...]
      HTTP:POST ... DENIED POST http://api.github.com:443/zen [policy:... engine:l7] [reason:...]
      FINDING:* ... "Landlock Filesystem Sandbox Unavailable"
      CONFIG:LOADED ... Acknowledged initial policy revision as loaded [version:2] [hash:...]
    """
    m = _OCSF.match(line.strip())
    if not m:
        return None
    cat, act, rest = m["cat"], m["act"], m["rest"]
    sev = _SEV.get(m["sev"], "info")
    tags = _tags(rest)
    base = {"source": "openshell", "at": float(m["ts"])}
    if cat == "NET" and act == "OPEN":
        n = _NET.match(rest)
        if not n:
            return None
        return {**base, "kind": "network",
                "decision": "deny" if n["dec"] == "DENIED" else "allow", "severity": sev,
                "detail": {"host": n["host"], "port": int(n["port"]), "binary": n["bin"],
                           "pid": int(n["pid"]), "policy": tags.get("policy", ""),
                           "engine": _engine(rest), "reason": tags.get("reason", "")[:500]}}
    if cat == "HTTP":
        h = _HTTP.match(rest)
        if not h:
            return None
        return {**base, "kind": "network",
                "decision": "deny" if h["dec"] == "DENIED" else "allow", "severity": sev,
                "detail": {"method": h["method"], "host": h["host"],
                           "port": int(h["port"] or 443), "path": h["path"] or "/",
                           "policy": tags.get("policy", ""), "engine": _engine(rest),
                           "reason": tags.get("reason", "")[:500]}}
    if cat == "FINDING":
        title = rest.split('"')[1] if rest.count('"') >= 2 else rest[:200]
        detail = {"finding": title}
        if "landlock" in title.lower():
            detail["degraded"] = "filesystem"
        return {**base, "kind": "policy", "decision": "audit", "severity": sev, "detail": detail}
    if cat == "CONFIG" and act == "LOADED" and "hash" in tags:
        return {**base, "kind": "policy", "decision": "audit", "severity": "info",
                "detail": {"runtime_policy_hash": tags["hash"],
                           "runtime_policy_version": tags.get("version", "")}}
    return None


def _tags(rest: str) -> dict:
    """[k:v] brackets. One bracket may hold several space-separated pairs
    ("[policy:x engine:opa]"); a reason is free text and keeps its spaces."""
    tags: dict = {}
    for body in _BRACKET.findall(rest):
        if body.startswith("reason:"):
            tags["reason"] = body[len("reason:"):]
            continue
        for tok in body.split():
            if ":" in tok:
                k, v = tok.split(":", 1)
                tags.setdefault(k, v)
    return tags


def _engine(rest: str) -> str:
    m = re.search(r"engine:([a-z0-9_]+)", rest)
    return m.group(1) if m else ""


# ── sinks ────────────────────────────────────────────────────────────


def summary(ev: dict) -> str:
    d = ev["detail"]
    if ev["kind"] == "network":
        host = d.get("host") or d.get("dest_host") or d.get("dest_ip") or "?"
        port = d.get("port") or d.get("dest_port") or ""
        what = f"{d.get('method', '')} {host}:{port}{d.get('path', '')}".strip()
        who = f" by {d['binary']}" if d.get("binary") else ""
        return f"{ev['decision']} network {what}{who}"
    if ev["kind"] == "file":
        return f"{ev['decision']} file {d.get('op', 'access')} {d.get('path', '?')}"
    if ev["kind"] == "process":
        by = f" by {d['AgentId']}" if d.get("AgentId") else ""
        return (f"{ev['decision']} process "
                f"{d.get('command') or d.get('command_line') or d.get('binary') or d.get('image') or '?'}"
                f"{by}")
    if ev["kind"] == "action":
        # Embodied action guard decisions uploaded from robots
        # (docs/specs/embodied-action-guard.md §5.3).
        return (f"{ev['decision']} action {d.get('tool', '?')} by {d.get('rail', '?')}"
                + (f": {', '.join(d['reasons'])}" if isinstance(d.get("reasons"), list) else ""))
    if ev["kind"] == "dlp" and d.get("event") == "enrollment_refused" \
            and d.get("why") == "not_in_inventory":
        return (f"device enrollment refused: {d.get('hostname_claimed', '?')} is not in the "
                f"company inventory (fleet {d.get('fleet', '?')})")
    if ev["kind"] == "dlp" and d.get("event") == "enrollment_refused":
        return (f"device enrollment refused: a device in fleet {d.get('fleet', '?')} with "
                f"this serial ({d.get('device_id', '?')}) is still reporting")
    if ev["kind"] == "dlp" and d.get("hook") == "UserPromptSubmit":
        # Coding-agent prompt check (docs/specs/agent-hooks-prompt-check.md):
        # name the policy, not "? to ?".
        pols = d.get("prompt_check_policies") or []
        what = ", ".join(p for p in pols if p) or d.get("prompt_check_reason") or "a policy"
        return f"coding-agent prompt {d.get('verdict') or ev['decision']}: {what}"
    if ev["kind"] == "dlp" and d.get("hook") == "PostToolUse":
        # Coding-agent tool-result check (docs/specs/agent-hooks-tool-policies.md).
        tool = d.get("tool") or "?"
        why = d.get("tool_policy_reason") or ""
        return (f"coding-agent tool result {d.get('verdict') or ev['decision']} on {tool}"
                + (f": {why}" if why else ""))
    if ev["kind"] == "dlp":
        what = d.get("category") or d.get("rule_id") or "?"
        where = d.get("destination") or "?"
        return (f"dlp {d['verdict']} {what} to {where}"
                + (f" from {d['device_id']}" if d.get("device_id") else ""))
    if ev["kind"] == "policy" and d.get("op"):
        where = d.get("instance") or ev["agent_instance_id"] or "?"
        text = {"applied": "runtime policy applied live", "reverted":
                "runtime policy changed outside Shield was reverted", "restart_required":
                "runtime policy change needs a sandbox restart", "apply_failed":
                "runtime policy could not be applied", "tampered":
                "runtime policy changed outside Shield"}[d["op"]]
        return f"{text} on {where}" + (f": {d['message']}" if d.get("message") else "")
    if ev["kind"] == "policy" and d.get("degraded"):
        return f"runtime boundary degraded: {d.get('finding', d['degraded'])}"
    if ev["kind"] == "policy" and d.get("runtime_policy_hash"):
        return f"runtime policy loaded {d['runtime_policy_hash'][:16]}"
    return f"{ev['decision']} {ev['kind']}"


def telemetry_fields(ev: dict) -> dict:
    """Flat telemetry keys core/asim.py maps onto the ASIM schema for the kind."""
    d = ev["detail"]
    out = {
        "votal.runtime.kind": ev["kind"],
        "votal.runtime.source": ev["source"],
        "votal.runtime.decision": ev["decision"],
        "votal.runtime.severity": ev["severity"],
        "votal.runtime.profile": ev["profile"],
        "votal.runtime.profile_hash": ev["profile_hash"],
        "votal.runtime.instance": ev["agent_instance_id"],
        "votal.session_id": ev["session_id"],
    }
    for src, dst in (("host", "destination.domain"), ("destination", "destination.domain"),
                     ("port", "destination.port"), ("method", "http.request.method"), ("path", "votal.runtime.path"),
                     ("binary", "process.executable"), ("command", "process.command_line"),
                     ("image", "process.executable"), ("command_line", "process.command_line"),
                     ("dest_host", "destination.domain"), ("dest_ip", "destination.ip"),
                     ("dest_port", "destination.port"), ("AgentId", "votal.agent.id"),
                     ("agent_label", "votal.agent.label"),
                     ("ShieldProfileVerdict", "votal.runtime.verdict"),
                     ("finding", "votal.runtime.finding"), ("reason", "votal.runtime.reason")):
        if d.get(src) not in (None, ""):
            out[dst] = d[src]
    if ev["kind"] == "file" and d.get("path"):
        out["file.path"] = d["path"]
    if ev["kind"] == "dlp":
        for key in ("verdict", "category", "rule_id", "device_id", "app"):
            if d.get(key) not in (None, ""):
                out[f"votal.dlp.{key}"] = d[key]
    return out


def _audit_action(ev: dict) -> str:
    if ev["decision"] == "deny":
        return "block"
    if ev["kind"] == "policy" and ev["severity"] in ("high", "critical"):
        return "warn"
    return "log"


def _record_sidecar_report(tenant_id: str, ev: dict, trusted: bool) -> bool:
    d = ev["detail"]
    instance = _s(d.get("instance") or ev["agent_instance_id"])
    if ev["kind"] != "policy" or not d.get("op") or not ev["profile"] or not instance:
        return False
    from core.runtime_policy.attest import record_applied
    record_applied(tenant_id, ev["profile"], instance, op=d["op"],
                   profile_hash=ev["profile_hash"], runtime_hash=_s(d.get("runtime_hash"), 80),
                   runtime_version=d.get("runtime_version"),
                   target_hash=_s(d.get("target_hash"), 80), lock=_s(d.get("lock"), 20),
                   reconcile=_s(d.get("reconcile"), 20), detail=_s(d.get("message"), 500),
                   trusted=trusted, at=ev["at"])
    return True


async def ingest(tenant_id: str, events: list[dict], *, source_ip: str = "",
                 trusted: bool = False) -> dict:
    """Write normalized events to the sinks. Never raises; returns counts.

    deny and audit events go to the decision audit; every event goes to
    telemetry; an allowed read of a file the agent's runtime profile marks
    classified is recorded in cross-app flow control. Sync sidecar reports
    (policy events with detail.op) update the instance's applied state;
    ``trusted`` says the caller used an admin-scoped key, and only then can a
    report satisfy attestation.
    """
    from core.runtime_policy import check as runtime_check
    from core.telemetry import build_guardrail_event, record_event
    from core.xflow import runtime as xflow
    from storage.decision_audit import log_decision

    # Agent OS events (osquery, sysmon): AgentId and the profile verdict first,
    # so the audit row and telemetry below carry them. Dropped entirely when
    # SHIELD_DEVICE_AGENT_OS_EVENTS=off.
    os_evs = [ev for ev in events if ev["source"] in ("osquery", "sysmon")]
    if os_evs:
        from core.dlp import agent_os_events
        from core.runtime_policy import os_events
        from core.runtime_policy.advisor import _shield_hosts
        if agent_os_events.disabled():
            events = [ev for ev in events if ev["source"] not in ("osquery", "sysmon")]
            os_evs = []
        hosts = _shield_hosts()
        for ev in os_evs:
            try:
                os_events.join(tenant_id, ev, hosts)
            except Exception:
                ev["detail"]["ShieldProfileVerdict"] = "no_profile"
                ev["decision"], ev["severity"] = "allow", "info"

    audited = flowed = applied = 0
    for ev in events:
        try:
            applied += _record_sidecar_report(tenant_id, ev, trusted)
        except Exception:
            pass
        text = summary(ev)
        action = _audit_action(ev)
        meta = {"path": "runtime_event", "source": ev["source"], "kind": ev["kind"],
                "decision": ev["decision"], "severity": ev["severity"],
                "agent_instance_id": ev["agent_instance_id"], "profile": ev["profile"],
                "profile_hash": ev["profile_hash"], "detail": ev["detail"], "at": ev["at"]}
        if ev["decision"] != "allow":
            try:
                log_decision(tenant_id=tenant_id, action=action, guardrail=runtime_check.GUARDRAIL,
                             agent_key=ev["agent_id"], tool_name=f"runtime:{ev['kind']}",
                             user_role="", session_id=ev["session_id"], reason=text,
                             source_ip=source_ip, metadata=meta)
                audited += 1
            except Exception:
                pass
        try:
            tel = build_guardrail_event(
                trace_id=f"rt-{int(ev['at'] * 1000)}", guardrail_name=runtime_check.GUARDRAIL,
                passed=ev["decision"] != "deny", action=action, message=text,
                details=meta, agent_key=ev["agent_id"], tenant_id=tenant_id,
                source_ip=source_ip, input_text=f"runtime:{ev['kind']}")
            tel.update(telemetry_fields(ev))
            record_event(tel)
        except Exception:
            pass
        if ev["kind"] == "file" and ev["decision"] != "deny" and ev["detail"].get("path"):
            cp = runtime_check.profile_for(tenant_id, ev["agent_id"])
            cls = runtime_check.classify_path(cp, str(ev["detail"]["path"])) if cp else None
            if cls:
                rec = await xflow.record_call(
                    tenant_id, tool_name=f"runtime:file_{ev['detail'].get('op', 'read')}",
                    evidence="observed", path="runtime_event", session_id=ev["session_id"],
                    agent=ev["agent_id"], classification=cls)
                flowed += bool(rec)
    if os_evs:
        try:
            os_events.record(tenant_id, os_evs)
        except Exception:
            pass
    advised = 0
    try:
        from core.runtime_policy import advisor
        advised = advisor.observe(tenant_id, events)
    except Exception:
        pass
    return {"audited": audited, "flow_records": flowed, "applied_reports": applied,
            "advised": advised}
