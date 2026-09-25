"""Map Shield telemetry events to Microsoft ASIM-normalized field names.

ASIM (Advanced Security Information Model) is the schema Microsoft Sentinel's
built-in analytics, hunting queries and workbooks expect. Emitting telemetry
already in ASIM field names (`ActorUsername`, `SrcIpAddr`, `EventResult`,
`DvcAction`, ...) means those detections work against Shield events without a
per-source parser, and it is the shape portable Sigma rules match on.

This module is a **pure transform**: `to_asim(event)` takes one internal
telemetry event (the dicts built by `core.telemetry.build_*_event`) and returns
a new ASIM-shaped dict. No I/O, no imports of guard-path code, and it never
mutates its input. It runs only in the off-thread telemetry export path
(`core.telemetry`), so it adds nothing to the guard path.

Design rules:
  * Fields Shield cannot populate honestly are **omitted**, never zero-filled,
    so an ASIM query does not read a fabricated value.
  * AI-native attributes that have no ASIM home (agent id, tool, data
    classification, risk score, guardrail results) live under `AdditionalFields`,
    ASIM's sanctioned extension point, so the record stays ASIM-valid while
    carrying agent context.
  * Raw prompt/response/tool bodies are never copied here (only ids, names,
    classifications, verdicts), matching the "never log bodies" rule the rest of
    Shield follows.
"""
from __future__ import annotations

from typing import Any

#: Bump when the field mapping changes in a way consumers must notice.
ASIM_SCHEMA_VERSION = "0.1.0"

#: The output formats the telemetry pipeline understands (see core/telemetry.py).
TELEMETRY_FORMATS = ("both", "asim", "native")

# --- value maps -------------------------------------------------------------

#: Shield internal severity -> ASIM EventSeverity (ASIM allows only these four).
_SEVERITY = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
}

#: Shield enforcement action -> ASIM DvcAction.
_DVC_ACTION = {
    "block": "Deny",
    "pass": "Allow",
    "allow": "Allow",
    "warn": "Allow",
    "redact": "Modify",
    "pending_confirmation": "Reset",
    "monitor": "Allow",
    "log": "Allow",
}

#: Shield event.action prefix -> ASIM-ish EventType (descriptive; the untouched
#: original is preserved in EventOriginalType).
def _event_type(event: dict) -> str:
    action = str(event.get("event.action") or "")
    if action == "request":
        return "HTTPRequest"
    if action == "response":
        return "GuardrailDecision"
    if action.startswith("guardrail."):
        return "GuardrailDecision"
    if action.startswith("tool.") and action.endswith(".execution"):
        return "ToolExecution"
    return action or "Event"


def _event_result(event: dict) -> str:
    """ASIM EventResult: Success | Partial | Failure | NA."""
    action = event.get("votal.action")
    if action in ("warn", "pending_confirmation"):
        return "Partial"
    outcome = event.get("event.outcome")
    if outcome == "failure":
        return "Failure"
    if outcome == "success":
        return "Success"
    # A guardrail that did not pass but produced no outcome is a partial result.
    if event.get("votal.guardrail.passed") is False:
        return "Failure"
    if event.get("votal.safe") is False:
        return "Partial"
    return "NA"


def _severity(event: dict) -> str:
    sev = str(event.get("event.severity") or "").lower()
    if sev in _SEVERITY:
        return _SEVERITY[sev]
    # Fall back to the risk score when severity is absent.
    score = event.get("event.risk_score")
    if isinstance(score, (int, float)):
        if score >= 70:
            return "High"
        if score >= 40:
            return "Medium"
        if score >= 10:
            return "Low"
        return "Informational"
    return "Informational"


def _dvc_action(action: Any) -> str | None:
    if not action:
        return None
    return _DVC_ACTION.get(str(action), str(action))


def _clean(d: dict) -> dict:
    """Drop keys whose value is None/""/[]/{} so nothing is fabricated."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def to_asim(event: dict) -> dict:
    """Return a new ASIM-shaped dict for one internal telemetry event.

    Raises TypeError on a non-dict input so the caller can fall back to emitting
    the native event rather than dropping telemetry.
    """
    if not isinstance(event, dict):
        raise TypeError(f"to_asim expects a dict, got {type(event).__name__}")

    ts = event.get("@timestamp")
    action = event.get("votal.action")
    result_details = (
        event.get("votal.guardrail.message")
        or event.get("votal.attack_type")
        or None
    )

    asim: dict[str, Any] = {
        "EventVendor": "Votal",
        "EventProduct": "Shield",
        "EventSchema": "AuditEvent",
        "EventSchemaVersion": ASIM_SCHEMA_VERSION,
        "EventCount": 1,
        "TimeGenerated": ts,
        "EventStartTime": ts,
        "EventEndTime": ts,
        "EventType": _event_type(event),
        "EventOriginalType": event.get("event.type"),
        "EventResult": _event_result(event),
        "EventResultDetails": result_details,
        "EventSeverity": _severity(event),
        "DvcHostname": event.get("host.name"),
        "DvcAction": _dvc_action(action),
        "SrcIpAddr": event.get("source.ip") or None,
        "ActorUsername": event.get("votal.role_name") or event.get("agent.key") or None,
        "TargetAppName": event.get("votal.tool.name") or event.get("url.path") or None,
        "Url": event.get("url.path") or None,
        "HttpRequestMethod": event.get("http.request.method") or None,
        "HttpStatusCode": event.get("http.response.status_code"),
        "RuleName": event.get("votal.guardrail.name") or None,
        "ThreatCategory": event.get("votal.attack_type") or None,
    }

    # AI-native attributes: no ASIM home, so they ride in AdditionalFields.
    additional = _clean({
        "AgentId": event.get("agent.key"),
        "TenantId": event.get("votal.tenant_id"),
        "SessionId": event.get("votal.session_id"),
        "TraceId": event.get("trace.id"),
        "RiskScore": event.get("event.risk_score"),
        "Safe": event.get("votal.safe"),
        "LatencyMs": event.get("votal.latency_ms") or event.get("votal.guardrail.latency_ms"),
        "ToolName": event.get("votal.tool.name"),
        "ToolSuccess": event.get("votal.tool.success"),
        "ToolErrorType": event.get("votal.tool.error_type"),
        "GuardrailName": event.get("votal.guardrail.name"),
        "GuardrailPassed": event.get("votal.guardrail.passed"),
        "GuardrailAction": event.get("votal.guardrail.action"),
        "GuardrailCount": event.get("votal.guardrail_count"),
        "GuardrailResults": event.get("votal.guardrail_results"),
        "BlockedGuardrails": event.get("votal.blocked_guardrails"),
        "AttackType": event.get("votal.attack_type"),
        "ConversationTurnCount": event.get("votal.conversation.turn_count"),
        "ConversationPattern": event.get("votal.conversation.message_pattern"),
        "AgenticDecisions": event.get("votal.agentic_decisions"),
        "EventAction": event.get("event.action"),
        "EventCategory": event.get("event.category"),
    })
    # Booleans are meaningful even when False, so re-admit them explicitly.
    for k, src in (("Safe", "votal.safe"),
                   ("ToolSuccess", "votal.tool.success"),
                   ("GuardrailPassed", "votal.guardrail.passed")):
        v = event.get(src)
        if isinstance(v, bool):
            additional[k] = v

    if additional:
        asim["AdditionalFields"] = additional

    return _clean(asim)
