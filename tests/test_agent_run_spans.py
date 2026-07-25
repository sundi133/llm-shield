"""Span model for agent-run tracing (opt-in; no-op unless enabled)."""

from unittest.mock import patch

import core.telemetry as tel


def _clear():
    tel._buffer.clear()


def test_no_span_when_disabled(monkeypatch):
    monkeypatch.delenv("SHIELD_SPAN_TRACING", raising=False)
    monkeypatch.delenv("SHIELD_OTLP_TRACES_ENDPOINT", raising=False)
    _clear()
    tel.emit_span(run_id="run-1", name="/x", start_ns=1, end_ns=2)
    assert len(tel._buffer) == 0          # zero behavior change when off


def test_span_emitted_when_enabled(monkeypatch):
    monkeypatch.setenv("SHIELD_SPAN_TRACING", "1")
    _clear()
    tel.emit_span(run_id="run-1", name="/guardrails/input", start_ns=10, end_ns=20,
                  attributes={"http.status_code": 200})
    assert len(tel._buffer) == 1
    s = tel._buffer[-1]
    assert s["type"] == "span" and s["run.id"] == "run-1"
    assert len(s["trace.id"]) == 32 and len(s["span.id"]) == 16   # OTLP id widths
    assert s["parent.span.id"] == tel._root_span_id("run-1")
    assert s["name"] == "/guardrails/input"
    assert s["attributes"]["http.status_code"] == 200


def test_same_run_groups_into_one_trace(monkeypatch):
    monkeypatch.setenv("SHIELD_SPAN_TRACING", "1")
    _clear()
    tel.emit_span(run_id="run-x", name="/a", start_ns=1, end_ns=2)
    tel.emit_span(run_id="run-x", name="/b", start_ns=3, end_ns=4)
    a, b = tel._buffer[-2], tel._buffer[-1]
    assert a["trace.id"] == b["trace.id"]            # same run -> same trace
    assert a["parent.span.id"] == b["parent.span.id"]  # same synthetic root
    assert a["span.id"] != b["span.id"]              # distinct spans


def test_traceparent_honored(monkeypatch):
    monkeypatch.setenv("SHIELD_SPAN_TRACING", "1")
    _clear()
    tp = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
    tel.emit_span(run_id="run-1", name="/a", start_ns=1, end_ns=2, traceparent=tp)
    s = tel._buffer[-1]
    assert s["trace.id"] == "a" * 32 and s["parent.span.id"] == "b" * 16


def test_bad_traceparent_falls_back(monkeypatch):
    monkeypatch.setenv("SHIELD_SPAN_TRACING", "1")
    _clear()
    tel.emit_span(run_id="run-1", name="/a", start_ns=1, end_ns=2, traceparent="garbage")
    s = tel._buffer[-1]
    assert s["trace.id"] == tel._trace_id_from_run("run-1")   # derived, not garbage


def test_otlp_endpoint_enables(monkeypatch):
    monkeypatch.delenv("SHIELD_SPAN_TRACING", raising=False)
    monkeypatch.setenv("SHIELD_OTLP_TRACES_ENDPOINT", "http://collector:4318")
    _clear()
    tel.emit_span(run_id="r", name="/a", start_ns=1, end_ns=2)
    assert len(tel._buffer) == 1


# ── integration: a guarded request emits one span into the buffer ────────────

def test_request_emits_span(monkeypatch):
    from starlette.testclient import TestClient
    from config.schema import AuthConfig, ShieldConfig
    import config.schema as cs

    async def _fake_classify(message, context, start):
        return {"safe": True, "action": "pass", "guardrail_results": [], "inference_time_ms": 1.0}

    async def _noop(entry):
        return None

    original = cs.config
    cs.config = ShieldConfig(auth=AuthConfig(enabled=False))
    monkeypatch.setenv("SHIELD_SPAN_TRACING", "1")
    with patch("config.schema.load_config", return_value=cs.config):
        from core.app import create_app
        app = create_app()
    try:
        with (
            patch("api.routes_classify._classify_with_defaults", side_effect=_fake_classify),
            patch("api.routes_classify.audit_logger.log", side_effect=_noop),
        ):
            _clear()
            client = TestClient(app)
            r = client.post("/guardrails/input", json={"message": "hi"},
                            headers={"X-Shield-Run-Id": "run-integ"})
        assert r.status_code == 200
        spans = [e for e in tel._buffer if e.get("type") == "span" and e.get("run.id") == "run-integ"]
        assert len(spans) == 1
        assert spans[0]["name"] == "/guardrails/input"
    finally:
        cs.config = original
