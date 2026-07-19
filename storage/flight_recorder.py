"""Flight recorder — forensic incident snapshots on containment events.

When Shield contains an agent — a guardrail block, an auto-revoke, an operator
kill switch, or a circuit-breaker trip — this module assembles a single,
self-contained forensic snapshot from data Shield already holds: the triggering
decision, the recent decision history for that session/agent, the session's
data-taint labels and flow graph (captured before their ~1h TTL discards them),
the agent identity, and any revocation status. The snapshot answers the
incident-response question "what was the agent doing when you killed it?" and
feeds the compliance evidence pack.

Design constraints (see docs/spec-flight-recorder.md):
  * OFF the guard path. ``capture_incident`` is invoked fire-and-forget from the
    block/revoke sites AFTER the enforcement decision is final; it never runs
    inline on ``/guardrails/*``, ``tools/call``, or ``cap/mint``, and it never
    raises (best-effort forensics must not degrade enforcement).
  * Opt-in and non-breaking. No-op unless SHIELD_ENABLE_FLIGHT_RECORDER (or
    SHIELD_ENABLE_ENTERPRISE) is set.
  * Reuses existing stores; adds no new dependency.

Redis keys (tenant-scoped):
    flightrec:{tenant_id}                 -> LIST of incident summaries (cap 5000)
    flightrec:{tenant_id}:{incident_id}   -> JSON full snapshot (TTL, default 30d)
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.flight_recorder")

SCHEMA_VERSION = 1

_MAX_SUMMARIES_PER_TENANT = 5000
_MAX_DECISIONS = 50
_MAX_TAINT_LABELS = 200
_REASON_MAXLEN = 500
_METADATA_MAXLEN = 8000
_DECISION_SCAN_WINDOW = 200  # recent decisions to scan before session/agent filter
_DEFAULT_TTL_SECONDS = 2592000  # 30 days


# ── config ────────────────────────────────────────────────────────────────

def _ttl_seconds() -> int:
    """Snapshot retention, read live from env (tunable without restart)."""
    try:
        return int(os.environ.get("SHIELD_FLIGHT_RECORDER_TTL_SECONDS", str(_DEFAULT_TTL_SECONDS)))
    except (ValueError, TypeError):
        return _DEFAULT_TTL_SECONDS


def _enabled() -> bool:
    """Gate capture on the feature flag; fail safe (treat unknown as off)."""
    try:
        from core.feature_flags import flight_recorder_enabled
        return flight_recorder_enabled()
    except Exception:
        return False


def _redis_safe():
    """Return the Redis handle, or None if it is unavailable or errors.

    Real Redis-down already returns None from ``_get_redis``; this also guards
    the case where acquiring the handle raises, so read/write paths degrade to
    the in-memory fallback instead of propagating.
    """
    try:
        return _get_redis()
    except Exception as e:
        logger.debug("flight_recorder: redis unavailable: %s", e)
        return None


# ── helpers ───────────────────────────────────────────────────────────────

def _truncate(s, n: int) -> str:
    if not s:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."


def _bound_metadata(md) -> dict:
    """Keep decision metadata (may carry tool args) from ballooning a snapshot."""
    if not isinstance(md, dict):
        return {}
    try:
        blob = json.dumps(md)
    except Exception:
        return {"_unserializable": True}
    if len(blob) <= _METADATA_MAXLEN:
        return md
    return {"_truncated": True, "_preview": blob[:2000]}


def _collect_recent_decisions(tenant_id: str, session_id=None, agent_key=None) -> list[dict]:
    """Recent decision history for this session (preferred) or agent, capped.

    Filters strictly: with a session_id we return only that session's decisions
    (empty is honest — the triggering decision is captured separately). Never
    mixes unrelated sessions into a forensic record.
    """
    try:
        from storage.decision_audit import query_decisions
        rows = query_decisions(tenant_id=tenant_id, limit=_DECISION_SCAN_WINDOW)
    except Exception as e:
        logger.debug("flight_recorder: decisions unavailable: %s", e)
        return []
    if session_id:
        rows = [d for d in rows if d.get("session_id") == session_id]
    elif agent_key:
        rows = [d for d in rows if d.get("agent_key") == agent_key]
    return rows[:_MAX_DECISIONS]


def _collect_taint(session_id, tenant_id: str) -> dict:
    """Session taint labels + flow graph, captured before the ~1h taint TTL."""
    if not session_id:
        return {}
    try:
        from guardrails.agentic.taint.taint_store import get_session_taints, get_taint_graph
        labels = get_session_taints(session_id, tenant_id) or {}
        if len(labels) > _MAX_TAINT_LABELS:
            labels = dict(list(labels.items())[:_MAX_TAINT_LABELS])
        graph = get_taint_graph(session_id) or {}
        return {"labels": labels, "graph": graph}
    except Exception as e:
        logger.debug("flight_recorder: taint unavailable: %s", e)
        return {}


def _persist(tenant_id: str, incident_id: str, summary: dict, snapshot: dict) -> None:
    """Write summary (list) + full snapshot (keyed, TTL). Redis or fallback."""
    summary_json = json.dumps(summary)
    snapshot_json = json.dumps(snapshot)
    list_key = f"flightrec:{tenant_id}"
    detail_key = f"flightrec:{tenant_id}:{incident_id}"
    ttl = _ttl_seconds()

    r = _redis_safe()
    if r:
        try:
            r.lpush(list_key, summary_json)
            r.ltrim(list_key, 0, _MAX_SUMMARIES_PER_TENANT - 1)
            r.set(detail_key, snapshot_json)
            try:
                r.expire(detail_key, ttl)
            except Exception as e:  # expiry is best-effort; the snapshot is written
                logger.debug("flight_recorder: expire failed: %s", e)
            return
        except Exception as e:
            logger.warning("flight_recorder: redis persist failed, using fallback: %s", e)

    # In-memory fallback (dev/testing only)
    existing = json.loads(_fallback_store.get(list_key, "[]"))
    existing.insert(0, summary)
    _fallback_store[list_key] = json.dumps(existing[:_MAX_SUMMARIES_PER_TENANT])
    _fallback_store[detail_key] = snapshot_json


# ── public API ──────────────────────────────────────────────────────────────

def capture_incident(
    *,
    tenant_id: str,
    trigger: str,
    decision: Optional[dict] = None,
    identity: Optional[dict] = None,
    revocation: Optional[dict] = None,
    budget: Optional[dict] = None,
) -> dict:
    """Assemble and persist a forensic incident snapshot. Never raises.

    Args:
        tenant_id: Tenant the incident belongs to.
        trigger: What contained the agent, e.g. "guardrail_block",
            "auto_revoke", "tool_disabled", "circuit_breaker".
        decision: The triggering decision. Recognised keys: guardrail, action,
            tool_name, user_role, reason, session_id, agent_key, metadata.
        identity: Agent identity as a plain dict (from request.state.identity).
            Recognised keys: agent_instance_id, agent_id, user_sub, build_hash,
            model_version, session_id, identity_method, trust_level.
        revocation: Optional revocation result (e.g. from auto_revoke).
        budget: Optional budget/cost state at the time of the incident.

    Returns:
        {"captured": bool, "trigger": str, ...} — includes "incident_id" on
        success, or "skipped"/"error" describing why nothing was written.
    """
    out = {"captured": False, "trigger": trigger}
    try:
        if not _enabled():
            out["skipped"] = "disabled"
            return out
        if not tenant_id:
            out["skipped"] = "no_tenant"
            return out

        decision = decision or {}
        identity = identity or {}

        session_id = identity.get("session_id") or decision.get("session_id") or None
        agent_instance_id = identity.get("agent_instance_id")
        agent_id = identity.get("agent_id") or decision.get("agent_key")
        agent_key = decision.get("agent_key") or agent_id

        incident_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()

        triggering_decision = {
            "guardrail": decision.get("guardrail", ""),
            "action": decision.get("action", ""),
            "tool_name": decision.get("tool_name"),
            "user_role": decision.get("user_role"),
            "reason": _truncate(decision.get("reason", ""), _REASON_MAXLEN),
            "metadata": _bound_metadata(decision.get("metadata")),
        }

        summary = {
            "incident_id": incident_id,
            "timestamp": now,
            "trigger": trigger,
            "guardrail": triggering_decision["guardrail"],
            "action": triggering_decision["action"],
            "tool_name": triggering_decision["tool_name"],
            "agent_instance_id": agent_instance_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "reason": triggering_decision["reason"],
        }

        snapshot = dict(summary)
        snapshot.update({
            "schema_version": SCHEMA_VERSION,
            "tenant_id": tenant_id,
            "triggering_decision": triggering_decision,
            "recent_decisions": _collect_recent_decisions(tenant_id, session_id, agent_key),
            "taint": _collect_taint(session_id, tenant_id),
            "identity": {
                "agent_instance_id": agent_instance_id,
                "agent_id": agent_id,
                "user_sub": identity.get("user_sub"),
                "build_hash": identity.get("build_hash"),
                "model_version": identity.get("model_version"),
                "session_id": session_id,
                "identity_method": identity.get("identity_method"),
                "trust_level": identity.get("trust_level"),
            } if identity else {},
            "revocation": revocation,
            "budget": budget,
            "sandbox_state": None,  # enriched later via the ingest endpoint (PR 3)
        })

        _persist(tenant_id, incident_id, summary, snapshot)
        out["captured"] = True
        out["incident_id"] = incident_id
    except Exception as e:  # never break the caller's containment path
        logger.warning("flight_recorder: capture failed: %s: %s", type(e).__name__, e)
        out["error"] = str(e)
    return out


def list_incidents(
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
    trigger: Optional[str] = None,
    agent_instance_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> list[dict]:
    """List incident summaries for a tenant, newest first, with optional filters."""
    if not tenant_id:
        return []
    list_key = f"flightrec:{tenant_id}"
    filtered = bool(trigger or agent_instance_id or session_id)

    r = _redis_safe()
    if r:
        try:
            fetch = (offset + limit) * 4 if filtered else (offset + limit)
            raw = r.lrange(list_key, 0, max(fetch, limit) - 1)
        except Exception as e:
            logger.warning("flight_recorder: list failed: %s", e)
            raw = []
    else:
        entries = json.loads(_fallback_store.get(list_key, "[]"))
        raw = [json.dumps(e) for e in entries]

    results: list[dict] = []
    skipped = 0
    for item in raw:
        if isinstance(item, bytes):
            item = item.decode()
        entry = json.loads(item) if isinstance(item, str) else item

        if trigger and entry.get("trigger") != trigger:
            continue
        if agent_instance_id and entry.get("agent_instance_id") != agent_instance_id:
            continue
        if session_id and entry.get("session_id") != session_id:
            continue

        if skipped < offset:
            skipped += 1
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def get_incident(tenant_id: str, incident_id: str) -> Optional[dict]:
    """Fetch a full incident snapshot, or None if not found for this tenant."""
    if not tenant_id or not incident_id:
        return None
    detail_key = f"flightrec:{tenant_id}:{incident_id}"

    r = _redis_safe()
    if r:
        try:
            raw = r.get(detail_key)
        except Exception as e:
            logger.warning("flight_recorder: get failed: %s", e)
            raw = None
    else:
        raw = _fallback_store.get(detail_key)

    if not raw:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode()
    try:
        snapshot = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return None

    # Defense in depth: the key is already tenant-scoped, but never return a
    # snapshot whose stored tenant does not match the caller's tenant.
    if snapshot.get("tenant_id") and snapshot.get("tenant_id") != tenant_id:
        return None
    return snapshot


# ── HTML rendering (printable IR report) ──────────────────────────────────

def _esc(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_incident_html(snapshot: dict) -> str:
    """Render a snapshot as self-contained, printable HTML (Arial, inline CSS).

    All values are HTML-escaped; sandbox-supplied fields are untrusted and are
    never emitted unescaped.
    """
    td = snapshot.get("triggering_decision", {}) or {}
    identity = snapshot.get("identity", {}) or {}
    taint = snapshot.get("taint", {}) or {}
    labels = taint.get("labels", {}) or {}
    revocation = snapshot.get("revocation") or {}
    decisions = snapshot.get("recent_decisions", []) or []

    decision_rows = ""
    for d in decisions:
        decision_rows += (
            "<tr>"
            f"<td>{_esc(str(d.get('timestamp',''))[:19])}</td>"
            f"<td>{_esc(d.get('action',''))}</td>"
            f"<td>{_esc(d.get('guardrail',''))}</td>"
            f"<td>{_esc(d.get('tool_name',''))}</td>"
            f"<td>{_esc(str(d.get('reason',''))[:80])}</td>"
            "</tr>"
        )

    taint_rows = ""
    for tcid, rec in labels.items():
        tags = ", ".join(rec.get("sensitivity_tags", [])) if isinstance(rec, dict) else ""
        tool = rec.get("tool_name", "") if isinstance(rec, dict) else ""
        taint_rows += (
            "<tr>"
            f"<td>{_esc(tcid)}</td>"
            f"<td>{_esc(tool)}</td>"
            f"<td>{_esc(tags)}</td>"
            "</tr>"
        )

    def _kv(label, value):
        return f"<p><strong>{_esc(label)}:</strong> {_esc(value) if value not in (None, '') else 'n/a'}</p>"

    revocation_html = (
        f"<p><strong>Revoked:</strong> {_esc(revocation.get('revoked'))} "
        f"({_esc(revocation.get('trigger',''))})</p>"
        if revocation else "<p>No revocation recorded.</p>"
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>LLM Shield - Flight Recorder Incident {_esc(snapshot.get('incident_id',''))}</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 2rem; color: #1a1a2e; font-size: 13px; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #ef4444; padding-bottom: 0.5rem; }}
h2 {{ color: #374151; margin-top: 2rem; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.3rem; }}
.meta {{ color: #6b7280; font-size: 12px; margin-bottom: 1.5rem; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 12px; }}
th {{ background: #f3f4f6; text-align: left; padding: 8px 10px; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
td {{ padding: 6px 10px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
.footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 11px; text-align: center; }}
@media print {{ body {{ max-width: none; }} }}
</style></head><body>

<h1>Flight Recorder Incident</h1>
<div class="meta">
    Incident: {_esc(snapshot.get('incident_id',''))} |
    Tenant: {_esc(snapshot.get('tenant_id',''))} |
    Trigger: {_esc(snapshot.get('trigger',''))} |
    Time: {_esc(snapshot.get('timestamp',''))}
</div>

<h2>Triggering Decision</h2>
{_kv('Action', td.get('action'))}
{_kv('Guardrail', td.get('guardrail'))}
{_kv('Tool', td.get('tool_name'))}
{_kv('User role', td.get('user_role'))}
{_kv('Reason', td.get('reason'))}

<h2>Agent Identity</h2>
{_kv('Instance', identity.get('agent_instance_id'))}
{_kv('Agent', identity.get('agent_id'))}
{_kv('User', identity.get('user_sub'))}
{_kv('Build hash', identity.get('build_hash'))}
{_kv('Model', identity.get('model_version'))}
{_kv('Session', identity.get('session_id'))}

<h2>Revocation</h2>
{revocation_html}

<h2>Data Taint (session)</h2>
<table>
<tr><th>Tool call</th><th>Tool</th><th>Sensitivity tags</th></tr>
{taint_rows or '<tr><td colspan="3" style="text-align:center;color:#9ca3af;">No taint recorded for this session</td></tr>'}
</table>

<h2>Recent Decisions ({len(decisions)})</h2>
<table>
<tr><th>Timestamp</th><th>Action</th><th>Guardrail</th><th>Tool</th><th>Reason</th></tr>
{decision_rows or '<tr><td colspan="5" style="text-align:center;color:#9ca3af;">No recent decisions for this session</td></tr>'}
</table>

<div class="footer">
    LLM Shield Flight Recorder - forensic snapshot captured at containment time.<br>
    Point-in-time record. Print to PDF for incident-response records.
</div>
</body></html>"""
