"""Compliance evidence pack generator.

Generates a self-contained HTML or JSON report from existing audit data.
No external dependencies — HTML uses inline CSS, printable to PDF.

Sections:
  1. Executive summary (total requests, block rate, coverage)
  2. Policy configuration snapshot
  3. Guardrail effectiveness metrics
  4. Decision audit (blocked actions)
  5. Admin actions timeline
  6. Agent registry snapshot
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("votal.evidence_pack")


def generate_evidence_pack(
    tenant_id: str,
    start_date: str,
    end_date: str,
    framework: str = "generic",
    fmt: str = "json",
) -> dict | str:
    """Generate a compliance evidence pack.

    Args:
        tenant_id: Tenant ID
        start_date: ISO date string (YYYY-MM-DD)
        end_date: ISO date string (YYYY-MM-DD)
        framework: "generic", "hipaa", "pci_dss", "gdpr"
        fmt: "json" or "html"

    Returns:
        dict (JSON format) or str (HTML format)
    """
    data = _collect_data(tenant_id, start_date, end_date)
    data["framework"] = framework
    data["generated_at"] = datetime.utcnow().isoformat() + "Z"

    if fmt == "html":
        return _render_html(data, framework)
    return data


def _collect_data(tenant_id: str, start_date: str, end_date: str) -> dict:
    """Collect all evidence data from existing storage."""
    from storage.tenant_store import get_tenant, _get_redis

    # Tenant config
    tenant_config = get_tenant(tenant_id) or {}

    # Agent registry
    agents = {}
    r = _get_redis()
    if r:
        try:
            raw = r.get(f"agents:{tenant_id}")
            if raw:
                agents = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        except Exception:
            pass

    # Guardrail effectiveness
    guardrail_summary = []
    try:
        from storage.guardrail_metrics import get_all_guardrails_summary
        days = max(1, (datetime.fromisoformat(end_date) - datetime.fromisoformat(start_date)).days)
        guardrail_summary = get_all_guardrails_summary(tenant_id, days=days)
    except Exception as e:
        logger.debug(f"Evidence pack: metrics failed: {e}")

    # Decision audit (blocked actions)
    blocked_decisions = []
    try:
        from storage.decision_audit import query_decisions
        blocked_decisions = query_decisions(
            tenant_id=tenant_id,
            action="block",
            limit=100,
        )
    except Exception as e:
        logger.debug(f"Evidence pack: decisions failed: {e}")

    # Admin audit
    admin_actions = []
    try:
        from storage.admin_audit import query_admin_audit
        admin_actions = query_admin_audit(tenant_id=tenant_id, limit=50)
    except Exception as e:
        logger.debug(f"Evidence pack: admin audit failed: {e}")

    # Audit log stats
    audit_stats = {}
    try:
        from storage.audit_log import audit_logger
        since = datetime.fromisoformat(start_date)
        audit_stats = audit_logger.get_stats(since=since, tenant_id=tenant_id)
    except Exception as e:
        logger.debug(f"Evidence pack: audit stats failed: {e}")

    # Compute summary
    total_requests = audit_stats.get("total_requests", 0)
    blocked_count = audit_stats.get("blocked_count", 0)
    block_rate = audit_stats.get("block_rate", 0.0)
    enabled_guardrails = list(tenant_config.get("input_guardrails", {}).keys()) + \
                         list(tenant_config.get("output_guardrails", {}).keys())

    return {
        "tenant_id": tenant_id,
        "period": {"start": start_date, "end": end_date},
        "summary": {
            "total_requests": total_requests,
            "blocked_count": blocked_count,
            "block_rate_pct": round(block_rate * 100, 1) if isinstance(block_rate, float) else block_rate,
            "agents_registered": len(agents),
            "guardrails_enabled": len(enabled_guardrails),
            "enabled_guardrail_names": enabled_guardrails,
        },
        "guardrail_effectiveness": guardrail_summary,
        "blocked_decisions": blocked_decisions[:50],
        "admin_actions": admin_actions[:30],
        "agent_registry": {
            aid: {
                "name": a.get("name", ""),
                "tools": a.get("tools", []),
                "roles": list(a.get("role_permissions", {}).keys()),
                "status": a.get("status", "active"),
            }
            for aid, a in agents.items()
        } if isinstance(agents, dict) else {},
        "policy_config": {
            "input_guardrails": list(tenant_config.get("input_guardrails", {}).keys()),
            "output_guardrails": list(tenant_config.get("output_guardrails", {}).keys()),
            "rbac_roles": list(tenant_config.get("rbac", {}).get("roles", {}).keys()),
            "plan": tenant_config.get("plan", "basic"),
        },
    }


def _render_html(data: dict, framework: str) -> str:
    """Render evidence pack as self-contained HTML (printable to PDF)."""
    summary = data.get("summary", {})
    period = data.get("period", {})
    guardrails = data.get("guardrail_effectiveness", [])
    decisions = data.get("blocked_decisions", [])
    admin_actions = data.get("admin_actions", [])
    agents = data.get("agent_registry", {})
    policy = data.get("policy_config", {})

    framework_label = {
        "generic": "General Compliance",
        "hipaa": "HIPAA Compliance",
        "pci_dss": "PCI DSS Compliance",
        "gdpr": "GDPR Compliance",
    }.get(framework, framework.upper())

    def _esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    guardrail_rows = ""
    for g in guardrails:
        guardrail_rows += f"""<tr>
            <td>{_esc(g.get('guardrail',''))}</td>
            <td>{g.get('total',0)}</td>
            <td>{g.get('blocked',0)}</td>
            <td>{g.get('block_rate',0):.1%}</td>
            <td>{g.get('avg_latency_ms',0):.0f}ms</td>
            <td>{g.get('trend','stable')}</td>
        </tr>"""

    decision_rows = ""
    for d in decisions[:30]:
        decision_rows += f"""<tr>
            <td>{_esc(d.get('timestamp','')[:19])}</td>
            <td>{_esc(d.get('guardrail',''))}</td>
            <td>{_esc(d.get('tool_name',''))}</td>
            <td>{_esc(d.get('user_role',''))}</td>
            <td>{_esc(d.get('reason','')[:80])}</td>
        </tr>"""

    admin_rows = ""
    for a in admin_actions[:20]:
        admin_rows += f"""<tr>
            <td>{_esc(a.get('timestamp','')[:19])}</td>
            <td>{_esc(a.get('action',''))}</td>
            <td>{_esc(a.get('actor',''))}</td>
            <td>{_esc(str(a.get('metadata','')))[:80]}</td>
        </tr>"""

    agent_rows = ""
    for aid, a in agents.items():
        agent_rows += f"""<tr>
            <td>{_esc(aid)}</td>
            <td>{_esc(a.get('name',''))}</td>
            <td>{len(a.get('tools',[]))}</td>
            <td>{', '.join(a.get('roles',[]))}</td>
            <td>{_esc(a.get('status',''))}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>LLM Shield — {framework_label} Evidence Pack</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; color: #1a1a2e; font-size: 13px; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #6366f1; padding-bottom: 0.5rem; }}
h2 {{ color: #374151; margin-top: 2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.3rem; }}
.meta {{ color: #6b7280; font-size: 12px; margin-bottom: 2rem; }}
.cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1rem 0; }}
.card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; text-align: center; }}
.card .value {{ font-size: 24px; font-weight: 700; color: #1a1a2e; }}
.card .label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 12px; }}
th {{ background: #f3f4f6; text-align: left; padding: 8px 10px; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
td {{ padding: 6px 10px; border-bottom: 1px solid #f3f4f6; }}
tr:hover {{ background: #f9fafb; }}
.footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 11px; text-align: center; }}
@media print {{ body {{ max-width: none; }} .no-print {{ display: none; }} }}
</style></head><body>

<h1>LLM Shield — {framework_label} Evidence Pack</h1>
<div class="meta">
    Tenant: {_esc(data.get('tenant_id',''))} |
    Period: {_esc(period.get('start',''))} to {_esc(period.get('end',''))} |
    Generated: {_esc(data.get('generated_at',''))}
</div>

<h2>Executive Summary</h2>
<div class="cards">
    <div class="card"><div class="value">{summary.get('total_requests',0):,}</div><div class="label">Total Requests</div></div>
    <div class="card"><div class="value">{summary.get('blocked_count',0):,}</div><div class="label">Blocked</div></div>
    <div class="card"><div class="value">{summary.get('block_rate_pct',0)}%</div><div class="label">Block Rate</div></div>
    <div class="card"><div class="value">{summary.get('guardrails_enabled',0)}</div><div class="label">Guardrails Active</div></div>
</div>

<h2>Policy Configuration</h2>
<p><strong>Plan:</strong> {_esc(policy.get('plan',''))}</p>
<p><strong>Input guardrails:</strong> {', '.join(policy.get('input_guardrails',[])) or 'None configured'}</p>
<p><strong>Output guardrails:</strong> {', '.join(policy.get('output_guardrails',[])) or 'None configured'}</p>
<p><strong>RBAC roles:</strong> {', '.join(policy.get('rbac_roles',[])) or 'None configured'}</p>

<h2>Guardrail Effectiveness</h2>
<table>
<tr><th>Guardrail</th><th>Total</th><th>Blocked</th><th>Block Rate</th><th>Avg Latency</th><th>Trend</th></tr>
{guardrail_rows or '<tr><td colspan="6" style="text-align:center;color:#9ca3af;">No metrics recorded yet</td></tr>'}
</table>

<h2>Blocked Actions (Top {len(decisions)})</h2>
<table>
<tr><th>Timestamp</th><th>Guardrail</th><th>Tool</th><th>Role</th><th>Reason</th></tr>
{decision_rows or '<tr><td colspan="5" style="text-align:center;color:#9ca3af;">No blocked actions in this period</td></tr>'}
</table>

<h2>Admin Actions</h2>
<table>
<tr><th>Timestamp</th><th>Action</th><th>Actor</th><th>Details</th></tr>
{admin_rows or '<tr><td colspan="4" style="text-align:center;color:#9ca3af;">No admin actions in this period</td></tr>'}
</table>

<h2>Agent Registry</h2>
<table>
<tr><th>Agent ID</th><th>Name</th><th>Tools</th><th>Roles</th><th>Status</th></tr>
{agent_rows or '<tr><td colspan="5" style="text-align:center;color:#9ca3af;">No agents registered</td></tr>'}
</table>

<div class="footer">
    LLM Shield Compliance Evidence Pack — Generated automatically by Votal AI<br>
    This document is a point-in-time snapshot. Print to PDF for audit records.
</div>
</body></html>"""


# ── Available compliance frameworks ───────────────────────────────────────

FRAMEWORKS = [
    {"id": "generic", "name": "General Compliance", "description": "Standard evidence pack with all sections"},
    {"id": "hipaa", "name": "HIPAA", "description": "PHI protection, access controls, audit trail"},
    {"id": "pci_dss", "name": "PCI DSS", "description": "Cardholder data protection, access controls"},
    {"id": "gdpr", "name": "GDPR", "description": "Personal data protection, right to erasure, consent"},
]
