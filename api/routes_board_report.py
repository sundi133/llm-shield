"""Board-level compliance report API.

Provides aggregated metrics for executive dashboards:
    GET /v1/tenant/me/board-report?days=30

Returns:
    - total_requests, blocked_count, block_rate_pct
    - top_threats (by guardrail, ranked)
    - guardrail_coverage (enabled vs available)
    - agent_count, shadow_agent_count
    - daily_trend (last N days: date, requests, blocks)
    - compliance_score (% of recommended guardrails enabled)
    - incidents (blocked actions with details)
"""

import json
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger("votal.board_report")

router = APIRouter(prefix="/v1/tenant/me", tags=["board-report"])

# Recommended guardrails for compliance scoring
_RECOMMENDED_GUARDRAILS = {
    "adversarial-prompt-detection",
    "pii-detection",
    "toxicity-detection",
    "keyword-blocklist",
    "sentiment-analysis",
    "bias-detection",
    "topic-restriction",
}


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


@router.get("/board-report")
async def board_report(request: Request, days: int = 30):
    """Executive-level metrics for board and compliance reporting."""
    tenant_id = _require_tenant(request)

    from storage.tenant_store import get_tenant, _get_redis

    tenant_config = get_tenant(tenant_id) or {}
    r = _get_redis()

    # ── Guardrail effectiveness ───────────────────────────────────────
    guardrail_summary = []
    try:
        from storage.guardrail_metrics import get_all_guardrails_summary
        guardrail_summary = get_all_guardrails_summary(tenant_id, days=days)
    except Exception:
        pass

    total_requests = sum(g.get("total", 0) for g in guardrail_summary)
    total_blocked = sum(g.get("blocked", 0) for g in guardrail_summary)

    # ── Top threats ───────────────────────────────────────────────────
    top_threats = [
        {
            "guardrail": g["guardrail"],
            "blocked": g["blocked"],
            "block_rate": g["block_rate"],
            "trend": g["trend"],
        }
        for g in guardrail_summary[:10]
        if g["blocked"] > 0
    ]

    # ── Agent counts ──────────────────────────────────────────────────
    agent_count = 0
    shadow_count = 0
    if r:
        try:
            agents_raw = r.get(f"agents:{tenant_id}")
            if agents_raw:
                agents = json.loads(agents_raw) if isinstance(agents_raw, (str, bytes)) else agents_raw
                agent_count = len(agents) if isinstance(agents, dict) else 0

            unreg_raw = r.get(f"unregistered:{tenant_id}")
            if unreg_raw:
                unreg = json.loads(unreg_raw) if isinstance(unreg_raw, (str, bytes)) else unreg_raw
                shadow_count = len(unreg.get("agents", {})) if isinstance(unreg, dict) else 0
        except Exception:
            pass

    # ── Guardrail coverage ────────────────────────────────────────────
    enabled_input = set(tenant_config.get("input_guardrails", {}).keys())
    enabled_output = set(tenant_config.get("output_guardrails", {}).keys())
    enabled_all = enabled_input | enabled_output
    coverage = len(enabled_all & _RECOMMENDED_GUARDRAILS)
    compliance_score = round(coverage / len(_RECOMMENDED_GUARDRAILS) * 100) if _RECOMMENDED_GUARDRAILS else 0

    # ── Daily trend ───────────────────────────────────────────────────
    daily_trend = []
    # Aggregate from guardrail metrics daily data
    day_totals = {}
    for g in guardrail_summary:
        try:
            from storage.guardrail_metrics import get_effectiveness
            eff = get_effectiveness(tenant_id, g["guardrail"], days=days)
            for d in eff.get("daily", []):
                date = d["date"]
                if date not in day_totals:
                    day_totals[date] = {"date": date, "requests": 0, "blocked": 0}
                day_totals[date]["requests"] += d.get("total", 0)
                day_totals[date]["blocked"] += d.get("blocked", 0)
        except Exception:
            pass

    daily_trend = sorted(day_totals.values(), key=lambda x: x["date"])[-days:]

    # ── Recent incidents ──────────────────────────────────────────────
    incidents = []
    try:
        from storage.decision_audit import query_decisions
        raw_incidents = query_decisions(tenant_id=tenant_id, action="block", limit=20)
        incidents = [
            {
                "timestamp": inc.get("timestamp", ""),
                "guardrail": inc.get("guardrail", ""),
                "tool_name": inc.get("tool_name", ""),
                "agent_key": inc.get("agent_key", ""),
                "user_role": inc.get("user_role", ""),
                "reason": inc.get("reason", "")[:120],
            }
            for inc in raw_incidents
        ]
    except Exception:
        pass

    return {
        "tenant_id": tenant_id,
        "period_days": days,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_requests": total_requests,
            "blocked_count": total_blocked,
            "block_rate_pct": round(total_blocked / max(total_requests, 1) * 100, 1),
            "agent_count": agent_count,
            "shadow_agent_count": shadow_count,
            "guardrails_enabled": len(enabled_all),
            "compliance_score": compliance_score,
        },
        "top_threats": top_threats,
        "guardrail_coverage": {
            "enabled": sorted(enabled_all),
            "recommended": sorted(_RECOMMENDED_GUARDRAILS),
            "missing": sorted(_RECOMMENDED_GUARDRAILS - enabled_all),
        },
        "daily_trend": daily_trend,
        "incidents": incidents,
    }
