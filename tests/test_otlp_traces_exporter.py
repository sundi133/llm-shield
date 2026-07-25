"""OTLP traces exporter — spans rendered as an OTLP /v1/traces payload."""

import asyncio
import json

from core.telemetry import OTLPTracesExporter


def _span(**kw):
    base = {
        "type": "span", "trace.id": "a" * 32, "span.id": "b" * 16,
        "parent.span.id": "c" * 16, "run.id": "run-1", "name": "/guardrails/input",
        "kind": "SERVER", "start_unix_nano": 10, "end_unix_nano": 20, "status": "OK",
        "attributes": {"http.status_code": 200, "streaming": False, "latency_ms": 1.5},
    }
    base.update(kw)
    return base


def test_payload_structure():
    p = OTLPTracesExporter.build_payload([_span()])
    span = p["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert span["traceId"] == "a" * 32 and span["spanId"] == "b" * 16
    assert span["parentSpanId"] == "c" * 16
    assert span["name"] == "/guardrails/input"
    assert span["kind"] == 2                    # SERVER
    assert span["startTimeUnixNano"] == "10" and span["endTimeUnixNano"] == "20"
    assert span["status"]["code"] == 1          # OK
    # service.name on the resource
    assert p["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"] == "votal-shield"


def test_error_status_code():
    p = OTLPTracesExporter.build_payload([_span(status="ERROR")])
    assert p["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"]["code"] == 2


def test_attribute_typing():
    p = OTLPTracesExporter.build_payload([_span()])
    attrs = {a["key"]: a["value"] for a in p["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]}
    assert attrs["http.status_code"] == {"intValue": "200"}
    assert attrs["streaming"] == {"boolValue": False}
    assert attrs["latency_ms"] == {"doubleValue": 1.5}
    assert attrs["run.id"] == {"stringValue": "run-1"}   # run.id folded into attributes


def test_export_filters_non_spans(monkeypatch):
    sent = {}

    class _FakeResp:
        status_code = 200
        text = ""

    class _FakeClient:
        async def post(self, url, content=None):
            sent["url"] = url
            sent["payload"] = json.loads(content)
            return _FakeResp()

    exp = OTLPTracesExporter(endpoint="http://collector:4318")
    monkeypatch.setattr(exp, "_get_client", lambda: _FakeClient())

    asyncio.run(exp.export([
        _span(name="/a"),
        {"type": "response", "trace.id": "x"},   # non-span, must be ignored
        _span(name="/b"),
    ]))
    assert sent["url"] == "http://collector:4318/v1/traces"
    names = [s["name"] for s in sent["payload"]["resourceSpans"][0]["scopeSpans"][0]["spans"]]
    assert names == ["/a", "/b"]                 # only spans, log events dropped


def test_export_noop_without_spans(monkeypatch):
    called = {"n": 0}

    class _FakeClient:
        async def post(self, *a, **k):
            called["n"] += 1

    exp = OTLPTracesExporter(endpoint="http://c:4318")
    monkeypatch.setattr(exp, "_get_client", lambda: _FakeClient())
    asyncio.run(exp.export([{"type": "response"}]))   # no spans
    assert called["n"] == 0
