"""Behavioral risk: per-agent baseline + deviation scoring.

Spec: docs/specs/behavioral-risk-blocking.md

Pure functions over the auth-event buffer — nothing here touches Redis or
the network. The governance plane builds baselines and scores activity;
the resulting flag is persisted onto the agent's registry entry, which the
cap-mint path ALREADY loads, so enforcement costs the hot path zero
additional I/O (a dict .get() behind SHIELD_BEHAVIORAL_RISK=enforce).

v1 scoring is deliberately statistical and explainable — every point of a
score maps to a named signal an auditor can read. No ML.

HONESTY: baselines derive from the bounded recent-event buffer
(storage.agent_auth_stats.RECENT_BUFFER_MAX), i.e. "recent behavior", not
full history. SHIELD_RISK_MIN_BASELINE_EVENTS refuses to score thin
baselines so a barely-observed agent is never cold-start flagged.
"""

from __future__ import annotations

import os
from typing import List, Optional

# Signal weights (sum caps at 100). Explainable constants, not knobs.
WEIGHT_NEW_TOOL = 40
WEIGHT_RATE_SPIKE = 30
WEIGHT_NEW_RESOURCE = 15
WEIGHT_ODD_HOURS = 15

LEVEL_MEDIUM_AT = 40   # step-up approval required
LEVEL_HIGH_AT = 70     # block


def behavioral_risk_mode() -> str:
    """SHIELD_BEHAVIORAL_RISK = off | monitor (default) | enforce.

    monitor: evaluation endpoints work, flags are visible, hot path NEVER
    consults them — zero behavior change. enforce is the explicit opt-in;
    off disables even evaluation writes (escape hatch).
    """
    raw = os.environ.get("SHIELD_BEHAVIORAL_RISK", "monitor").strip().lower()
    return raw if raw in ("off", "monitor", "enforce") else "monitor"


def rate_multiplier() -> float:
    try:
        return max(1.0, float(os.environ.get("SHIELD_RISK_RATE_MULTIPLIER", "5")))
    except ValueError:
        return 5.0


def min_baseline_events() -> int:
    try:
        return max(1, int(os.environ.get("SHIELD_RISK_MIN_BASELINE_EVENTS", "20")))
    except ValueError:
        return 20


def flag_ttl_seconds() -> int:
    try:
        return max(60, int(os.environ.get("SHIELD_RISK_FLAG_TTL_SECONDS", "3600")))
    except ValueError:
        return 3600


def window_seconds() -> int:
    try:
        return max(60, int(os.environ.get("SHIELD_RISK_WINDOW_SECONDS", "900")))
    except ValueError:
        return 900


def build_baseline(events: List[dict], now: int) -> dict:
    """Aggregate an agent's events into a compact behavioral profile."""
    tools: dict = {}
    resources: dict = {}
    hours: dict = {}
    oldest = now
    for e in events:
        ts = int(e.get("ts") or 0)
        if 0 < ts < oldest:
            oldest = ts
        t = e.get("tool")
        if t:
            tools[t] = tools.get(t, 0) + 1
        r = e.get("resource")
        if r:
            resources[r] = resources.get(r, 0) + 1
        if ts:
            import time as _time
            hour = str(_time.gmtime(ts).tm_hour)
            hours[hour] = hours.get(hour, 0) + 1
    span_hours = max(1.0, (now - oldest) / 3600.0)
    return {
        "tools": tools,
        "resources": resources,
        "hours": hours,
        "rate_per_hour": round(len(events) / span_hours, 3),
        "events_analyzed": len(events),
        "computed_at": now,
    }


def score_activity(current: List[dict], baseline: Optional[dict], now: int) -> dict:
    """Score a window of activity against a persisted baseline.

    Returns {score, level, signals, evaluated_at, window_seconds}. Level
    `insufficient_baseline` (score 0, never flagged) when the baseline is
    missing or thinner than SHIELD_RISK_MIN_BASELINE_EVENTS.
    """
    win = window_seconds()
    result = {
        "score": 0, "level": "low", "signals": [],
        "evaluated_at": now, "window_seconds": win,
    }
    if not baseline or baseline.get("events_analyzed", 0) < min_baseline_events():
        result["level"] = "insufficient_baseline"
        return result
    if not current:
        return result

    signals: List[str] = []
    score = 0

    known_tools = set(baseline.get("tools") or {})
    new_tools = sorted({e.get("tool") for e in current if e.get("tool")} - known_tools)
    if new_tools:
        score += WEIGHT_NEW_TOOL
        signals.append("new_tool:" + ",".join(new_tools[:5]))

    base_rate = max(0.5, float(baseline.get("rate_per_hour") or 0.0))
    cur_rate = len(current) / (win / 3600.0)
    if cur_rate > rate_multiplier() * base_rate:
        score += WEIGHT_RATE_SPIKE
        signals.append(f"rate_spike:{cur_rate:.1f}/h>{rate_multiplier():g}x{base_rate:.1f}/h")

    known_res = set(baseline.get("resources") or {})
    new_res = sorted({e.get("resource") for e in current if e.get("resource")} - known_res)
    if new_res:
        score += WEIGHT_NEW_RESOURCE
        signals.append("new_resource:" + ",".join(new_res[:5]))

    import time as _time
    base_hours = {h for h, n in (baseline.get("hours") or {}).items() if n}
    cur_hours = {str(_time.gmtime(int(e.get("ts") or now)).tm_hour) for e in current}
    odd = sorted(cur_hours - base_hours)
    if base_hours and odd:
        score += WEIGHT_ODD_HOURS
        signals.append("odd_hours:" + ",".join(odd))

    score = min(100, score)
    result["score"] = score
    result["signals"] = signals
    if score >= LEVEL_HIGH_AT:
        result["level"] = "high"
    elif score >= LEVEL_MEDIUM_AT:
        result["level"] = "medium"
    return result
