"""Unit tests for the Shield -> ASIM telemetry mapper (core/asim.py).

The mapper is pure: given one internal telemetry event (as built by
core.telemetry.build_*_event) it returns a new ASIM-shaped dict, never mutating
its input and never doing I/O.
"""
import copy

import pytest

from core import asim
from core.asim import to_asim
from core.telemetry import (
    build_guardrail_event,
    build_request_event,
    build_response_event,
    build_tool_execution_event,
)


def _ts(event: dict) -> dict:
    """Stamp @timestamp the way record_event would, so mapping is realistic."""
    event.setdefault("@timestamp", "2026-09-24T00:00:00+00:00")
    return event


def test_block_response_maps_to_failure_deny_high():
    ev = _ts(build_response_event(
        trace_id="t1", endpoint="/guardrails/input", status_code=403,
        latency_ms=12.5, action="block", safe=False, tenant_id="bank-co",
        role_name="analyst", source_ip="10.0.0.5", attack_type="prompt_injection",
        blocked_guardrails=["adversarial"],
    ))
    out = to_asim(ev)
    assert out["EventVendor"] == "Votal"
    assert out["EventProduct"] == "Shield"
    assert out["EventSchemaVersion"] == asim.ASIM_SCHEMA_VERSION
    assert out["EventResult"] == "Failure"
    assert out["DvcAction"] == "Deny"
    assert out["EventSeverity"] == "High"
    assert out["SrcIpAddr"] == "10.0.0.5"
    assert out["ActorUsername"] == "analyst"
    # AI-native context rides in AdditionalFields.
    af = out["AdditionalFields"]
    assert af["TenantId"] == "bank-co"
    assert af["AttackType"] == "prompt_injection"
    assert af["BlockedGuardrails"] == ["adversarial"]
    assert af["Safe"] is False


def test_pass_response_maps_to_success_allow():
    ev = _ts(build_response_event(
        trace_id="t2", endpoint="/guardrails/input", status_code=200,
        latency_ms=8.0, action="pass", safe=True, tenant_id="bank-co",
    ))
    out = to_asim(ev)
    assert out["EventResult"] == "Success"
    assert out["DvcAction"] == "Allow"
    assert out["AdditionalFields"]["Safe"] is True


def test_warn_response_is_partial():
    ev = _ts(build_response_event(
        trace_id="t3", endpoint="/guardrails/input", status_code=200,
        latency_ms=5.0, action="warn", safe=False, tenant_id="bank-co",
    ))
    out = to_asim(ev)
    assert out["EventResult"] == "Partial"
    # warn is still allowed traffic at the device action level.
    assert out["DvcAction"] == "Allow"


def test_guardrail_event_mapping():
    ev = _ts(build_guardrail_event(
        trace_id="t4", guardrail_name="pii_detection", passed=False,
        action="block", message="SSN detected", latency_ms=3.0,
        tenant_id="bank-co", source_ip="10.0.0.9",
    ))
    out = to_asim(ev)
    assert out["EventType"] == "GuardrailDecision"
    assert out["EventResult"] == "Failure"
    assert out["RuleName"] == "pii_detection"
    assert out["EventResultDetails"] == "SSN detected"
    af = out["AdditionalFields"]
    assert af["GuardrailName"] == "pii_detection"
    assert af["GuardrailPassed"] is False
    assert af["GuardrailAction"] == "block"


def test_tool_execution_mapping():
    ev = _ts(build_tool_execution_event(
        trace_id="t5", tool_name="database.query", success=False,
        latency_ms=40.0, error_type="Timeout", tenant_id="bank-co",
    ))
    out = to_asim(ev)
    assert out["EventType"] == "ToolExecution"
    assert out["EventResult"] == "Failure"
    assert out["TargetAppName"] == "database.query"
    af = out["AdditionalFields"]
    assert af["ToolName"] == "database.query"
    assert af["ToolSuccess"] is False
    assert af["ToolErrorType"] == "Timeout"


def test_unpopulated_fields_are_omitted_not_faked():
    # A minimal request event has no ip, no tool, no http status.
    ev = _ts(build_request_event(
        trace_id="t6", method="POST", endpoint="/guardrails/input",
        tenant_id="bank-co",
    ))
    out = to_asim(ev)
    # Nothing fabricated: keys we cannot fill are simply absent.
    assert "HttpStatusCode" not in out
    assert out.get("SrcIpAddr") in (None, "") or "SrcIpAddr" not in out
    assert out["EventVendor"] == "Votal"


def test_mapper_does_not_mutate_input():
    ev = _ts(build_response_event(
        trace_id="t7", endpoint="/x", status_code=403, latency_ms=1.0,
        action="block", safe=False, tenant_id="bank-co",
    ))
    before = copy.deepcopy(ev)
    to_asim(ev)
    assert ev == before, "to_asim must not mutate its input event"


def test_non_dict_input_raises_typeerror():
    # So the telemetry export path can fall back to the native event.
    for bad in (None, "not a dict", 42, ["list"]):
        with pytest.raises(TypeError):
            to_asim(bad)


def test_false_booleans_are_preserved_in_additional_fields():
    ev = _ts(build_guardrail_event(
        trace_id="t8", guardrail_name="toxicity", passed=False, action="warn",
        tenant_id="bank-co",
    ))
    out = to_asim(ev)
    assert out["AdditionalFields"]["GuardrailPassed"] is False
