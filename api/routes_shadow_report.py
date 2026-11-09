"""Shadow report: what Shield would have stopped while a tenant ran in monitor.

    GET /v1/tenant/me/shadow-report?days=30&team=<rule id>

Spec: docs/specs/shadow-mode-report.md, task 2. Admin plane only (mounted by
admin_app.py next to the Board Report). A read endpoint: nothing on the guard
path changes.

Where each number comes from:

- ``would_block_total``, ``blocked_total``, ``by_guardrail`` and the daily
  ``would_blocked`` / ``blocked``: the guardrail metrics hashes (exact, one
  read per guardrail per day). They count guardrail CHECKS, so a request that
  tripped two guardrails counts twice.
- ``checked_total``, ``would_block_requests``, the daily ``checked``,
  ``would_block_rate_pct``,
  ``by_team`` and ``examples``: the tenant's audit rows in the range. These
  count REQUESTS, so the rate is would-blocked requests over checked requests
  (one unit, never above 100%).
- With ``team`` set, every count comes from audit rows, because the metrics
  hashes have no team (``counts_from: "audit"``).

No prompt text is ever returned: an example carries the guardrail's own
message, cut to 200 characters, never ``input_text``. A printed report must not
leak what tripped the guardrail.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

logger = logging.getLogger("votal.shadow_report")

router = APIRouter(prefix="/v1/tenant/me", tags=["shadow-report"])

# Newest audit rows read per report. The audit ZSET can hold a million rows;
# past this the report says "sampled" instead of stalling the admin plane.
MAX_SCAN = 50_000
MAX_EXAMPLES = 20
REASON_CHARS = 200
_BLOCKING = ("block", "pending_confirmation")

NOT_COVERED = [
    "Output checks (/guardrails/output) still block in monitor mode.",
    "Kill-switch and disabled-agent blocks always enforce; they are not would-blocks.",
    "Chat proxy and coding-agent decisions appear in examples and by team, "
    "not in the per-guardrail totals.",
]


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


def _blocking_guardrails(metadata: dict) -> list[str]:
    """Guardrails on a row that failed with an action that stops a request."""
    names = []
    for key in ("input_guardrails", "output_guardrails"):
        for g in metadata.get(key) or []:
            if isinstance(g, dict) and not g.get("passed", True) and g.get("action") in _BLOCKING:
                names.append(str(g.get("guardrail") or ""))
    return [n for n in names if n]


def _reason(metadata: dict) -> str:
    msgs = []
    for key in ("input_guardrails", "output_guardrails"):
        for g in metadata.get(key) or []:
            if isinstance(g, dict) and not g.get("passed", True) and g.get("action") in _BLOCKING:
                if g.get("message"):
                    msgs.append(str(g["message"]))
    return "; ".join(msgs)[:REASON_CHARS]


def _team_label(scope: Optional[dict]) -> Optional[str]:
    return scope["rule"] if scope else None


def _date(ts) -> str:
    return str(ts or "")[:10]


def _read_audit(r, tenant_id: str, days: int) -> tuple[list[dict], bool]:
    """This tenant's chat telemetry rows in the range, newest first, bounded."""
    from storage.guardrail_metrics import _fetch_audit_window
    raw = _fetch_audit_window(r, tenant_id, days, MAX_SCAN)
    rows = []
    for item in raw:
        try:
            entry = json.loads(item)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(entry, dict):
            continue
        meta = entry.get("metadata")
        if not isinstance(meta, dict) or meta.get("kind") != "agent_chat_telemetry":
            continue
        if meta.get("tenant_id") != tenant_id:       # defence in depth, as /me/telemetry
            continue
        rows.append(entry)
    return rows, len(raw) >= MAX_SCAN


def _coding_agent_monitor_rows(tenant_id: str, since: str) -> list[dict]:
    from api.routes_tenant_self import _coding_agent_rows, _coding_agent_telemetry_enabled
    if not _coding_agent_telemetry_enabled():
        return []
    try:
        return _coding_agent_rows(tenant_id, agent_key=None, status="monitor",
                                  tool_name=None, q=None, since=since, until=None)
    except Exception as e:      # noqa: BLE001 - never fail the report
        logger.warning("coding-agent rows unavailable: %s", e)
        return []


@router.get("/shadow-report")
async def shadow_report(
    request: Request,
    days: int = Query(30, ge=1, le=30, description="1 to 30 (audit retention)"),
    team: Optional[str] = Query(None, description="A team rule id, 'global', 'unmatched', "
                                                  "or '(none)' for rows with no team recorded"),
):
    """What Shield would have stopped in monitor mode, for the caller's tenant."""
    from api.routes_tenant_self import TEAM_NONE, _TEAM_RULE_RE, _row_scope, _team_matches
    from core.policy_mode import resolve_mode
    from storage import guardrail_metrics as gm
    from storage.tenant_store import get_tenant

    tenant_id = _require_tenant(request)
    team = (team or "").strip() or None
    if team is not None and team != TEAM_NONE and not _TEAM_RULE_RE.match(team):
        raise HTTPException(status_code=422, detail=(
            "team must be a team rule id (lowercase letters, digits, '-' or '_', "
            "at most 64 characters), 'global', 'unmatched', or '(none)'"))

    now = datetime.now(timezone.utc)
    since_dt = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    dates = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)][::-1]

    out = {
        "tenant_id": tenant_id,
        "policy_mode": resolve_mode(get_tenant(tenant_id) or {}),
        "days": days,
        "since": since,
        "team": team,
        "exact_since": None,
        "counts_from": "audit" if team else "metrics",
        "checked_total": None,
        "would_block_requests": None,
        "would_block_total": 0,
        "would_block_rate_pct": None,
        "blocked_total": 0,
        "by_guardrail": [],
        "daily": [{"date": d, "checked": 0, "would_blocked": 0, "blocked": 0} for d in dates],
        "by_team": [],
        "examples": [],
        "sampled": False,
        "degraded": False,
        "not_covered": list(NOT_COVERED),
    }

    r = gm._get_redis()
    if not r:
        out["degraded"] = True
        return out

    out["exact_since"] = gm.get_split_since()
    rows, out["sampled"] = _read_audit(r, tenant_id, days)
    rows = [e for e in rows if _date(e.get("timestamp")) >= dates[0]]
    if team is not None:
        rows = [e for e in rows if _team_matches(_row_scope(e["metadata"]), team)]
    daily = {d["date"]: d for d in out["daily"]}

    # ── requests: always from audit ────────────────────────────────────────
    monitor_rows = []
    for e in rows:
        day = daily.get(_date(e.get("timestamp")))
        if day is not None:
            day["checked"] += 1
        if e.get("action_taken") == "monitor":
            monitor_rows.append(e)
    out["checked_total"] = len(rows)
    out["would_block_requests"] = len(monitor_rows)
    if rows:
        out["would_block_rate_pct"] = round(len(monitor_rows) / len(rows) * 100, 1)

    # ── checks: metrics, or audit when a team is asked for ────────────────
    if team is None:
        by_name = {}
        for g in gm.get_all_guardrails_summary(tenant_id, days=days):
            out["would_block_total"] += g.get("would_blocked", 0)
            out["blocked_total"] += g.get("blocked", 0)
            if g.get("would_blocked"):
                by_name[g["guardrail"]] = g["would_blocked"]
        for d in gm._daily_totals(tenant_id, days):
            if d["date"] in daily:
                daily[d["date"]]["would_blocked"] = d.get("would_blocked", 0)
                daily[d["date"]]["blocked"] = d.get("blocked", 0)
    else:
        by_name = {}
        for e in rows:
            names = _blocking_guardrails(e["metadata"])
            day = daily.get(_date(e.get("timestamp")))
            if e.get("action_taken") == "monitor":
                out["would_block_total"] += len(names)
                for n in names:
                    by_name[n] = by_name.get(n, 0) + 1
                if day is not None:
                    day["would_blocked"] += len(names)
            elif e.get("action_taken") == "block":
                out["blocked_total"] += len(names)
                if day is not None:
                    day["blocked"] += len(names)
    out["by_guardrail"] = [{"guardrail": n, "would_blocked": c}
                           for n, c in sorted(by_name.items(), key=lambda x: (-x[1], x[0]))]

    # ── by team and examples: monitor rows ────────────────────────────────
    teams = {}
    examples = []
    for e in monitor_rows:
        meta = e["metadata"]
        label = _team_label(_row_scope(meta))
        teams[label] = teams.get(label, 0) + 1
        if len(examples) < MAX_EXAMPLES:
            examples.append({
                "timestamp": e.get("timestamp"),
                "guardrails": _blocking_guardrails(meta),
                "reason": _reason(meta),
                "team": label,
                "agent_key": e.get("agent_key") or "",
                "stage": meta.get("stage"),
                "source": "chat",
            })
    # Coding agents never carry a team, so they belong only to "all" and "(none)".
    if team in (None, TEAM_NONE):
        for row in _coding_agent_monitor_rows(tenant_id, since):
            teams[None] = teams.get(None, 0) + 1
            examples.append({
                "timestamp": row.get("timestamp"),
                "guardrails": [],
                "reason": str(row.get("message") or "")[:REASON_CHARS],
                "team": None,
                "agent_key": row.get("agent_key") or "",
                "stage": row.get("stage"),
                "source": "coding-agent",
            })
    examples.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    out["examples"] = examples[:MAX_EXAMPLES]
    out["by_team"] = [{"team": t, "would_blocked": c}
                      for t, c in sorted(teams.items(), key=lambda x: (-x[1], str(x[0])))]
    return out
