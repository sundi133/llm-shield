"""Profiles, statistics, budgets and the report for the device agent load test.

Spec: docs/specs/device-agent-load-test.md (R6). Pure: standard library only.
It must not import psutil, websockets or mitmproxy, so the main CI job can test
it without the harness's own requirements (a test pins this).
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable, Optional

CLASSES = ("prompt_s", "prompt_l", "sse", "ws", "tunnel", "upload", "upload_over")
PROFILE_KEYS = {"name", "duration_s", "warmup_s", "idle_after_s", "tabs", "ramp_s", "think_ms",
                "mix", "model", "model_latency_ms", "budgets"}
REQUIRED_PROFILE_KEYS = {"name", "duration_s", "tabs", "mix", "budgets"}
BUDGET_KEYS = {"name", "max", "equals", "enforce"}

# What each budget measures, as a path into the report.
METRICS = {
    "short_prompt_added_p95_ms": ("classes", "prompt_s", "added_p95_ms"),
    "short_prompt_added_p99_ms": ("classes", "prompt_s", "added_p99_ms"),
    "long_prompt_added_p95_ms": ("classes", "prompt_l", "added_p95_ms"),
    "large_body_added_p95_ms": ("classes", "upload", "added_p95_ms"),
    "stream_ttfb_delta_p95_ms": ("classes", "sse", "ttfb_delta_p95_ms"),
    "ws_frame_added_p95_ms": ("classes", "ws", "added_p95_ms"),
    "tunnel_added_p95_ms": ("classes", "tunnel", "added_p95_ms"),
    "tunnel_bytes_identical": ("classes", "tunnel", "bytes_identical"),
    "proxy_failures": ("failures", "proxy"),
    "agent_cpu_mean_pct": ("resources", "agent_cpu_mean_pct"),
    "agent_cpu_p95_pct": ("resources", "agent_cpu_p95_pct"),
    "agent_rss_peak_mb": ("resources", "agent_rss_peak_mb"),
    "agent_rss_growth_mb": ("resources", "agent_rss_growth_mb"),
    "ollama_rss_peak_mb": ("resources", "ollama_rss_peak_mb"),
    "backlog_drained_s": ("queues", "backlog_drained_s"),
    "audit_headroom_pct": ("queues", "audit_headroom_pct"),
}

AUDIT_CEILING_PER_HOUR = 2400        # sync.push_audit: 200 records per 300 s sync


class ProfileError(ValueError):
    pass


# ── profiles ──────────────────────────────────────────────────────────

def load_profile(src: "str | Path | dict") -> dict:
    """A validated profile (raises ProfileError naming every problem)."""
    p = dict(src) if isinstance(src, dict) else json.loads(Path(src).read_text())
    errors = []
    unknown = set(p) - PROFILE_KEYS
    if unknown:
        errors.append(f"unknown keys: {', '.join(sorted(unknown))}")
    missing = REQUIRED_PROFILE_KEYS - set(p)
    if missing:
        errors.append(f"missing keys: {', '.join(sorted(missing))}")
    mix = p.get("mix") or {}
    if not isinstance(mix, dict) or not mix:
        errors.append("mix: a non-empty object of class -> weight")
    else:
        bad = set(mix) - set(CLASSES)
        if bad:
            errors.append(f"mix: unknown classes {', '.join(sorted(bad))}")
        if any(not isinstance(w, (int, float)) or w <= 0 for w in mix.values()):
            errors.append("mix: weights must be positive numbers")
        elif abs(sum(mix.values()) - 100) > 1e-6:
            errors.append(f"mix: weights sum to {sum(mix.values())}, not 100")
    for k in ("duration_s", "tabs"):
        if k in p and (not isinstance(p[k], int) or p[k] <= 0):
            errors.append(f"{k}: a positive integer")
    if p.get("model", "fake") not in ("fake", "real"):
        errors.append("model: fake or real")
    for i, b in enumerate(p.get("budgets") or []):
        if not isinstance(b, dict) or set(b) - BUDGET_KEYS or b.get("name") not in METRICS:
            errors.append(f"budgets[{i}]: an object with a known name and max or equals")
        elif ("max" in b) == ("equals" in b):
            errors.append(f"budgets[{i}] {b['name']}: exactly one of max or equals")
    if errors:
        raise ProfileError("; ".join(errors))
    return {"warmup_s": 0, "idle_after_s": 0, "ramp_s": 0, "think_ms": 200, "model": "fake",
            "model_latency_ms": 50, **p}


# ── statistics ────────────────────────────────────────────────────────

def percentile(values: Iterable[float], pct: float) -> Optional[float]:
    """Linear interpolation between closest ranks (numpy's default)."""
    xs = sorted(v for v in values if v is not None)
    if not xs:
        return None
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * pct / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return float(xs[lo] + (xs[hi] - xs[lo]) * (k - lo))


def added(pairs: Iterable[tuple]) -> list[float]:
    """Added latency per paired request: proxied minus direct, in ms."""
    return [px - dr for px, dr in pairs if px is not None and dr is not None]


def summarize(samples: list[dict]) -> dict:
    """One request class. A sample: {proxied_ms, direct_ms, error, outcome,
    and for streams ttfb_proxied_ms / ttfb_direct_ms, for the tunnel identical}."""
    ok = [s for s in samples if not s.get("error")]
    a = added((s.get("proxied_ms"), s.get("direct_ms")) for s in ok)
    out = {"count": len(samples), "errors": sum(1 for s in samples if s.get("error")),
           "added_p50_ms": _r(percentile(a, 50)), "added_p95_ms": _r(percentile(a, 95)),
           "added_p99_ms": _r(percentile(a, 99)), "outcomes": {}}
    for s in samples:
        o = s.get("outcome") or ("error" if s.get("error") else "ok")
        out["outcomes"][o] = out["outcomes"].get(o, 0) + 1
    examples = list(dict.fromkeys(s["error"] for s in samples if s.get("error")))[:3]
    if examples:
        out["error_examples"] = examples
    ttfb = added((s.get("ttfb_proxied_ms"), s.get("ttfb_direct_ms")) for s in ok)
    if ttfb:
        out["ttfb_delta_p95_ms"] = _r(percentile(ttfb, 95))
    if any("identical" in s for s in samples):
        out["bytes_identical"] = all(s.get("identical", False) for s in ok) and bool(ok)
    return out


def _r(v: Optional[float]) -> Optional[float]:
    return None if v is None else round(v, 2)


def resources(samples: list[dict], *, last_window_s: float = 480.0) -> dict:
    """Agent and Ollama CPU and RSS from 1 s samples {t, cpu, rss_mb, threads, ollama_rss_mb}."""
    if not samples:
        return {}
    cpu = [s["cpu"] for s in samples if s.get("cpu") is not None]
    rss = [s["rss_mb"] for s in samples if s.get("rss_mb") is not None]
    out = {"agent_cpu_mean_pct": _r(sum(cpu) / len(cpu)) if cpu else None,
           "agent_cpu_p95_pct": _r(percentile(cpu, 95)),
           "agent_rss_start_mb": _r(rss[0]) if rss else None,
           "agent_rss_peak_mb": _r(max(rss)) if rss else None,
           "agent_rss_end_mb": _r(rss[-1]) if rss else None,
           "agent_threads_peak": max((s.get("threads") or 0) for s in samples)}
    t_end = samples[-1]["t"]
    tail = [s["rss_mb"] for s in samples if s.get("rss_mb") is not None and s["t"] >= t_end - last_window_s]
    out["agent_rss_growth_mb"] = _r(tail[-1] - tail[0]) if len(tail) > 1 else 0.0
    oll = [s["ollama_rss_mb"] for s in samples if s.get("ollama_rss_mb")]
    if oll:
        out["ollama_rss_peak_mb"] = _r(max(oll))
    return out


def audit_headroom_pct(records: int, seconds: float) -> Optional[float]:
    if seconds <= 0:
        return None
    return _r(100.0 * (records * 3600.0 / seconds) / AUDIT_CEILING_PER_HOUR)


# ── budgets ───────────────────────────────────────────────────────────

def measured(report: dict, name: str) -> Any:
    node: Any = report
    for k in METRICS[name]:
        if not isinstance(node, dict) or k not in node:
            return None
        node = node[k]
    return node


def grade(report: dict, budgets: list[dict]) -> list[dict]:
    """One row per budget. An invalid run, or a budget with nothing measured,
    grades as pass None (not graded), never as a pass."""
    rows = []
    for b in budgets:
        m = measured(report, b["name"])
        limit = b.get("max", b.get("equals"))
        if not report.get("valid", True) or m is None:
            ok = None
        elif "max" in b:
            ok = m <= b["max"]
        else:
            ok = m == b["equals"]
        rows.append({"name": b["name"], "limit": limit, "kind": "max" if "max" in b else "equals",
                     "measured": m, "pass": ok, "enforce": bool(b.get("enforce", True))})
    return rows


def enforced_failures(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["enforce"] and r["pass"] is False]


# ── schema and rendering ──────────────────────────────────────────────

def validate_report(r: dict) -> list[str]:
    errors = []
    for k, t in (("meta", dict), ("classes", dict), ("resources", dict), ("queues", dict),
                 ("failures", dict), ("budgets", list), ("valid", bool)):
        if not isinstance(r.get(k), t):
            errors.append(f"{k}: {t.__name__}")
    for name, c in (r.get("classes") or {}).items():
        if name not in CLASSES:
            errors.append(f"classes.{name}: unknown class")
        elif not isinstance(c, dict) or not isinstance(c.get("count"), int):
            errors.append(f"classes.{name}.count: int")
    for i, b in enumerate(r.get("budgets") or []):
        if not isinstance(b, dict) or not {"name", "limit", "measured", "pass"} <= set(b):
            errors.append(f"budgets[{i}]: name, limit, measured, pass")
    for k in ("profile", "model", "hardware"):
        if k not in (r.get("meta") or {}):
            errors.append(f"meta.{k}: required")
    return errors


def render_markdown(r: dict) -> str:
    m = r.get("meta", {})
    lines = [f"# Device agent load test: {m.get('profile')} ({m.get('model')} model)", "",
             f"- Hardware: {m.get('hardware')} ({m.get('cpu', '?')}, {m.get('ram_gb', '?')} GB, {m.get('os', '?')})",
             f"- Agent {m.get('agent_version', '?')}, git {m.get('git', '?')}, {m.get('date', '?')}",
             f"- Model gate at the end: {m.get('gate', '?')} (p95 {m.get('gate_p95_ms')} ms)",
             f"- Valid run: {'yes' if r.get('valid') else 'NO: ' + str(r.get('invalid_reason', ''))}", "",
             "## Budgets", "", "| Budget | Limit | Measured | Result |", "|---|---|---|---|"]
    for b in r.get("budgets", []):
        res = {True: "pass", False: "FAIL", None: "not graded"}[b["pass"]]
        if not b.get("enforce", True) and b["pass"] is False:
            res = "FAIL (reported only)"
        op = "<=" if b.get("kind") == "max" else "="
        lines.append(f"| {b['name']} | {op} {b['limit']} | {b['measured']} | {res} |")
    lines += ["", "## Request classes", "",
              "| Class | Count | Errors | Added p50 ms | p95 | p99 | Outcomes |", "|---|---|---|---|---|---|---|"]
    for name, c in r.get("classes", {}).items():
        lines.append(f"| {name} | {c['count']} | {c['errors']} | {c.get('added_p50_ms')} | "
                     f"{c.get('added_p95_ms')} | {c.get('added_p99_ms')} | "
                     f"{', '.join(f'{k} {v}' for k, v in sorted(c.get('outcomes', {}).items()))} |")
    lines += ["", "## Resources and queues", ""]
    for k, v in {**r.get("resources", {}), **r.get("queues", {})}.items():
        lines.append(f"- {k}: {v}")
    return "\n".join(lines) + "\n"
