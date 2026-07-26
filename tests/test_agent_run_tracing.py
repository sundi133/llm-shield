"""run_id correlation across a multi-turn agent run (additive, non-breaking)."""

import types
from unittest.mock import patch

from core.run_context import resolve_run_id


def _req(headers=None, state=None):
    r = types.SimpleNamespace()
    r.headers = headers or {}
    r.state = types.SimpleNamespace(**(state or {}))
    return r


# ── resolution precedence ────────────────────────────────────────────────────

def test_header_wins():
    r = _req({"X-Shield-Run-Id": "run-hdr"})
    assert resolve_run_id(r, {"run_id": "run-body", "session_id": "s"}) == "run-hdr"


def test_body_run_id_over_session():
    r = _req()
    assert resolve_run_id(r, {"run_id": "run-body", "session_id": "s"}) == "run-body"


def test_session_id_reused_when_no_run_id():
    r = _req()
    assert resolve_run_id(r, {"session_id": "sess-42"}) == "sess-42"


def test_generated_when_nothing_supplied():
    r = _req()
    rid = resolve_run_id(r, {})
    assert rid.startswith("run-") and len(rid) > 8


def test_cached_on_request_state():
    r = _req({"X-Shield-Run-Id": "run-1"})
    first = resolve_run_id(r, {})
    # a later call with a different body still returns the cached value
    assert resolve_run_id(r, {"run_id": "other"}) == first
    assert r.state.run_id == first


# ── sanitization (caller-influenced, treated as untrusted display data) ──────

def test_control_chars_stripped():
    r = _req({"X-Shield-Run-Id": "run\n\r\x00-inject"})
    assert resolve_run_id(r, {}) == "run-inject"


def test_length_capped():
    r = _req({"X-Shield-Run-Id": "x" * 500})
    assert len(resolve_run_id(r, {})) == 128


def test_blank_falls_through_to_generated():
    r = _req({"X-Shield-Run-Id": "   "})
    assert resolve_run_id(r, {"session_id": ""}).startswith("run-")


# ── integration: /guardrails/input echoes header + stamps audit run_id ───────

def test_input_endpoint_echoes_and_stamps(monkeypatch):
    from starlette.testclient import TestClient
    from config.schema import AuthConfig, ShieldConfig
    import config.schema as cs

    captured = {}

    async def _fake_classify(message, context, start):
        return {"safe": True, "action": "pass", "guardrail_results": [], "inference_time_ms": 1.0}

    async def _capture(entry):
        captured.update(entry)

    original = cs.config
    cs.config = ShieldConfig(auth=AuthConfig(enabled=False))
    with patch("config.schema.load_config", return_value=cs.config):
        from core.app import create_app
        app = create_app()
    try:
        with (
            patch("api.routes_classify._classify_with_defaults", side_effect=_fake_classify),
            patch("api.routes_classify.audit_logger.log", side_effect=_capture),
        ):
            client = TestClient(app)
            r = client.post("/guardrails/input", json={"message": "hi"},
                            headers={"X-Shield-Run-Id": "run-abc"})
        assert r.status_code == 200
        assert r.headers.get("X-Shield-Run-Id") == "run-abc"          # echoed
        assert captured["metadata"]["run_id"] == "run-abc"            # stamped in audit
    finally:
        cs.config = original
