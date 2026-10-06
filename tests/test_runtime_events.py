"""Infrastructure guardrails, task 4: runtime events from sandboxes and proxies.

tests/fixtures/openshell_ocsf_log.txt is real `openshell logs` output (OpenShell
0.0.80, 2026-09-28): a sandbox denied example.com, a POST, and a binary not
in the policy, and reported Landlock unavailable on the host.
Spec: docs/specs/infra-guardrails.md §4.2."""

import os
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.asim import to_asim
from core.runtime_policy import check as rc
from core.runtime_policy import events as ev
from core.runtime_policy import store as rt_store
from core.runtime_policy.model import TEMPLATES
from core.xflow import runtime as xflow
from core.xflow import state as xflow_state

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "openshell_ocsf_log.txt")


def _lines():
    return [l.rstrip("\n") for l in open(FIXTURE)]


# ── OpenShell parser ─────────────────────────────────────────────────


def test_parses_every_decision_line_in_real_openshell_output():
    parsed = [p for p in (ev.parse_openshell_line(l) for l in _lines()) if p]
    kinds = [(p["kind"], p["decision"]) for p in parsed]
    assert kinds.count(("network", "deny")) == 3
    assert ("network", "allow") in kinds
    assert sum(1 for p in parsed if p["detail"].get("degraded") == "filesystem") == 3
    loaded = [p for p in parsed if p["detail"].get("runtime_policy_hash")]
    assert loaded[0]["detail"]["runtime_policy_hash"].startswith("be7831c2")


def test_network_deny_fields():
    line = next(l for l in _lines() if "DENIED /usr/bin/curl" in l)
    p = ev.parse_openshell_line(line)
    assert p["detail"]["host"] == "example.com" and p["detail"]["port"] == 443
    assert p["detail"]["binary"] == "/usr/bin/curl" and p["detail"]["engine"] == "opa"
    assert "not allowed by any policy" in p["detail"]["reason"]
    assert p["severity"] == "medium"


def test_l7_method_deny_fields():
    line = next(l for l in _lines() if "HTTP:POST" in l)
    p = ev.parse_openshell_line(line)
    assert p["detail"]["method"] == "POST" and p["detail"]["path"] == "/zen"
    assert p["detail"]["policy"] == "allow_1_api_github_com"


def _dlp(detail):
    return ev.normalize({"source": "claude_code", "kind": "dlp", "decision": "deny",
                         "severity": "medium", "agent_id": "claude-code",
                         "agent_instance_id": "", "session_id": "s", "profile": "p",
                         "profile_hash": "h", "detail": detail})


def test_summary_names_the_policy_for_a_coding_agent_prompt_block():
    # docs/specs/agent-hooks-prompt-check.md: not "dlp block ? to ?".
    e = _dlp({"hook": "UserPromptSubmit", "verdict": "block", "prompt_len": 20,
              "prompt_sha256": "x" * 64, "prompt_check_policies": ["No file encryption"],
              "prompt_check_reason": "No file encryption: asks to lock a file"})
    assert ev.summary(e) == "coding-agent prompt block: No file encryption"


def test_summary_falls_back_to_the_reason_when_no_policy_name():
    e = _dlp({"hook": "UserPromptSubmit", "verdict": "block", "prompt_len": 1,
              "prompt_sha256": "y" * 64, "prompt_check_reason": "the check could not run"})
    assert ev.summary(e) == "coding-agent prompt block: the check could not run"


def test_summary_describes_a_coding_agent_tool_result_redaction():
    e = _dlp({"hook": "PostToolUse", "verdict": "redact", "tool": "Read",
              "tool_policy_reason": "redacted: card number"})
    assert ev.summary(e) == "coding-agent tool result redact on Read: redacted: card number"


def test_summary_still_reads_a_device_dlp_event_the_old_way():
    e = _dlp({"verdict": "block", "category": "pii", "destination": "upload.example",
              "device_id": "dev-1"})
    assert ev.summary(e) == "dlp block pii to upload.example from dev-1"


def test_chatter_is_ignored():
    for l in _lines():
        if "CONFIG:CREATING" in l or "SSH:LISTEN" in l or "PROC:LAUNCH" in l:
            assert ev.parse_openshell_line(l) is None
    assert ev.parse_openshell_line("not a log line") is None


@pytest.mark.parametrize("bad, needle", [
    ({"kind": "disk", "decision": "deny"}, "kind"),
    ({"kind": "network", "decision": "maybe"}, "decision"),
    ({"source": "mystery", "kind": "network", "decision": "deny"}, "source"),
    ({"kind": "network", "decision": "deny", "detail": "x"}, "detail must be an object"),
    ({"kind": "network", "decision": "deny", "detail": {"x": "y" * 5000}}, "larger than"),
    ({"kind": "network", "decision": "deny", "at": "yesterday"}, "ISO-8601"),
    ({"kind": "network", "decision": "deny", "severity": "apocalyptic"}, "severity"),
    ({"source": "openshell", "raw": "garbage"}, "not an OpenShell"),
    ("nope", "must be an object"),
])
def test_normalize_rejects(bad, needle):
    with pytest.raises(ev.EventError) as e:
        ev.normalize(bad)
    assert needle in str(e.value)


# ── ASIM ─────────────────────────────────────────────────────────────


def _asim(event: dict) -> dict:
    n = ev.normalize(event)
    base = {"@timestamp": "2026-09-28T00:00:00Z", "event.type": "denied",
            "votal.guardrail.name": "runtime_boundary", "agent.key": n["agent_id"]}
    return to_asim({**base, **ev.telemetry_fields(n)})


def test_asim_network_session():
    a = _asim({"source": "openshell", "raw": next(l for l in _lines() if "DENIED /usr/bin/curl" in l),
               "agent_id": "bot"})
    assert a["EventSchema"] == "NetworkSession" and a["EventType"] == "EndpointNetworkSession"
    assert a["DstHostname"] == "example.com" and a["DstPortNumber"] == 443
    assert a["DvcAction"] == "Deny" and a["EventResult"] == "Failure"
    assert a["SrcProcessName"] == "/usr/bin/curl" and a["NetworkDirection"] == "Outbound"


def test_asim_file_and_process():
    f = _asim({"kind": "file", "decision": "deny", "detail": {"path": "/root/.ssh/id_rsa"}})
    assert f["EventSchema"] == "FileEvent" and f["TargetFilePath"] == "/root/.ssh/id_rsa"
    p = _asim({"kind": "process", "decision": "deny",
               "detail": {"binary": "/usr/bin/nc", "command": "nc evil 1"}})
    assert p["EventSchema"] == "ProcessEvent" and p["TargetProcessCommandLine"] == "nc evil 1"


def test_asim_unchanged_for_ordinary_events():
    a = to_asim({"@timestamp": "t", "event.type": "denied", "votal.guardrail.name": "pii"})
    assert a["EventSchema"] == "AuditEvent"


# ── API ──────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean():
    from api.routes_runtime import reset_rate_limits_for_tests
    reset_rate_limits_for_tests()
    rt_store.reset_memory()
    rc.invalidate()
    xflow.invalidate()
    xflow_state.reset_memory()
    xflow_state._mem_policies.clear()
    yield
    rc.invalidate()
    xflow.invalidate()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _tenant(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "re" + uuid.uuid4().hex[:10]
    key = "sk-re-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key, "X-User-Role": "dev"})
    return SimpleNamespace(id=tid, c=c)


def test_ingest_openshell_log_into_the_decision_audit(app):
    from storage.decision_audit import query_decisions

    t = _tenant(app)
    events = [{"source": "openshell", "raw": l, "agent_id": "research-bot",
               "session_id": "task-42"} for l in _lines() if "DENIED" in l or "FINDING" in l]
    events.append({"source": "openshell", "raw": "garbage"})
    r = t.c.post("/v1/shield/runtime/events", json={"events": events})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["accepted"] == len(events) - 1
    assert body["rejected"] == [{"index": len(events) - 1,
                                 "error": "raw: not an OpenShell OCSF decision line"}]
    rows = query_decisions(tenant_id=t.id, guardrail="runtime_boundary", limit=50)
    actions = sorted(r["action"] for r in rows)
    assert actions.count("block") == 3 and actions.count("warn") == 3
    reasons = " | ".join(r.get("reason", "") for r in rows)
    assert "deny network example.com:443 by /usr/bin/curl" in reasons
    assert "runtime boundary degraded: Landlock Filesystem Sandbox Unavailable" in reasons


def test_telemetry_carries_runtime_fields(app):
    t = _tenant(app)
    seen = []
    with patch("core.telemetry.record_event", side_effect=seen.append):
        t.c.post("/v1/shield/runtime/events", json={"events": [
            {"kind": "network", "decision": "deny", "agent_id": "b",
             "detail": {"host": "evil.io", "port": 443, "binary": "/usr/bin/curl"}}]})
    assert seen and seen[0]["votal.runtime.kind"] == "network"
    assert seen[0]["destination.domain"] == "evil.io" and seen[0]["votal.tenant_id"] == t.id


def test_batch_limits_and_rate_limit(app, monkeypatch):
    t = _tenant(app)
    one = {"kind": "network", "decision": "deny"}
    assert t.c.post("/v1/shield/runtime/events", json={"events": []}).status_code == 422
    monkeypatch.setenv("SHIELD_RUNTIME_EVENTS_MAX_BATCH", "3")
    assert t.c.post("/v1/shield/runtime/events", json={"events": [one] * 4}).status_code == 413
    monkeypatch.setenv("SHIELD_RUNTIME_EVENTS_PER_MIN", "5")
    assert t.c.post("/v1/shield/runtime/events", json={"events": [one] * 3}).status_code == 202
    r = t.c.post("/v1/shield/runtime/events", json={"events": [one] * 3})
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    # Another tenant has its own budget.
    assert _tenant(app).c.post("/v1/shield/runtime/events",
                               json={"events": [one] * 3}).status_code == 202


def test_requires_a_tenant(app):
    from starlette.testclient import TestClient
    r = TestClient(app).post("/v1/shield/runtime/events", json={"events": [{}]})
    assert r.status_code in (401, 403)


def test_classified_file_read_reported_by_the_sandbox_feeds_cross_app_flow(app):
    t = _tenant(app)
    tools = ["github_create_repo"]
    prof = {**TEMPLATES["research-agent"], "identity": {"require_agent_token": False}}
    t.c.put("/v1/tenant/me/runtime-profiles/research-agent", json=prof)
    t.c.post("/v1/agents/registry", json={"agent_id": "boxed", "tools": tools,
                                          "role_permissions": {"dev": tools},
                                          "runtime_profile": "research-agent"})
    t.c.put("/v1/tenant/me/flow-control/policy", json={
        "enabled": True, "mode": "enforce", "apps": {"github": {"tools": ["github_*"]}},
        "exposure_rules": [{"tools": ["github_create_repo"], "param": "private",
                            "equals": False, "exposure": "public"}],
        "rules": [{"id": "r", "source": {"min_classification": "confidential"},
                   "destination": {"exposure": ["public"]}, "action": "block"}]})
    t.c.post("/v1/shield/runtime/events", json={"events": [
        {"source": "custom", "kind": "file", "decision": "allow", "agent_id": "boxed",
         "session_id": "s9", "detail": {"op": "read", "path": "/sandbox/data/customers/acme.csv"}},
        # A denied read never taints: nothing left the file.
        {"source": "custom", "kind": "file", "decision": "deny", "agent_id": "boxed",
         "session_id": "s10", "detail": {"op": "read", "path": "/sandbox/data/customers/x.csv"}},
    ]})
    body = {"agent_key": "boxed", "tool_name": "github_create_repo", "user_role": "dev",
            "tool_params": {"private": False}}
    assert t.c.post("/v1/shield/tool/check", json={**body, "session_id": "s9"}).json()["allowed"] is False
    assert t.c.post("/v1/shield/tool/check", json={**body, "session_id": "s10"}).json()["allowed"] is True


def test_forwarder_filter():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "openshell_events", os.path.join(os.path.dirname(__file__), "..", "examples", "runtime",
                                         "openshell_events.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    kept = [l for l in _lines() if mod.interesting(l, include_allowed=False)]
    # Every kept line is one the server parses; nothing with a decision is dropped.
    assert all(ev.parse_openshell_line(l) for l in kept)
    decisions = [l for l in _lines() if (p := ev.parse_openshell_line(l)) and p["decision"] != "allow"]
    assert set(decisions) <= set(kept)
