"""Request and response bodies stay structured in telemetry at any size.

Spec: docs/specs/telemetry-body-structure.md. A body used to become a string
once it passed 2,000 characters, which hid every field inside it (a LiteLLM
call's forwarded headers among them) and gave Elasticsearch an object on one
event and a string on the next.
"""

import asyncio
import json
import random

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import core.telemetry as t
from core.telemetry import _bounded_body, build_request_event, build_response_event

KEY_ID = "XTZSE4KWMU7RCEMNMVRQ"


def litellm_body(text_len: int) -> dict:
    return {
        "input_type": "request",
        "texts": ["x" * text_len],
        "litellm_call_id": "call-1",
        "request_headers": {"x-tf-api-key-id": KEY_ID, "x-tf-organization-id": "7w2lnkp",
                            "x-tf-project-id": "rx28oml", "x-agent-key": "[present]"},
        "request_data": {"user_api_key_hash": KEY_ID, "user_api_key_org_id": "7w2lnkp",
                         "user_api_key_team_id": "rx28oml"},
    }


def encoded(value) -> int:
    return len(json.dumps(value, default=str))


@pytest.fixture(autouse=True)
def _mode(monkeypatch):
    monkeypatch.delenv(t.BODY_MODE_ENV, raising=False)


# ── Size and shape ───────────────────────────────────────────────────────────

def test_small_body_is_unchanged():
    body = {"message": "hello", "context": {"tenant": "a"}, "n": [1, 2, 3]}
    out, cut = _bounded_body(body)
    assert out == body and cut is False


def test_long_litellm_body_keeps_its_headers_and_ids():
    out, cut = _bounded_body(litellm_body(50_000))
    assert cut is True
    assert encoded(out) <= t._BODY_MAX_CHARS
    assert out["request_headers"]["x-tf-api-key-id"] == KEY_ID
    assert out["request_headers"]["x-tf-organization-id"] == "7w2lnkp"
    assert out["request_data"]["user_api_key_org_id"] == "7w2lnkp"
    assert out["litellm_call_id"] == "call-1"
    assert isinstance(out["texts"], list) and isinstance(out["texts"][0], str)
    assert out["texts"][0].endswith("...[truncated]")


def _json_type(v):
    return "object" if isinstance(v, dict) else "list" if isinstance(v, list) else \
        "string" if isinstance(v, str) else "bool" if isinstance(v, bool) else \
        "number" if isinstance(v, (int, float)) else "null"


def _same_shape(before, after, depth=0):
    """Every key kept has the same JSON type; containers may only become null
    past the depth limit."""
    if after is None and isinstance(before, (dict, list)):
        assert depth >= t._BODY_MAX_DEPTH
        return
    assert _json_type(before) == _json_type(after), (before, after)
    if isinstance(before, dict):
        for k, v in after.items():
            assert k in before
            _same_shape(before[k], v, depth + 1)
    elif isinstance(before, list):
        for b, a in zip(before[-len(after):] if after else [], after):
            _same_shape(b, a, depth + 1)


def _random_body(rng, depth=0, budget=None):
    """Nested JSON up to 9 levels and about 400 nodes, with long strings and lists."""
    budget = budget if budget is not None else [400]
    budget[0] -= 1
    roll = rng.random()
    if depth > 8 or budget[0] <= 0 or roll < 0.3:
        return rng.choice(["s" * rng.randint(0, 3000), rng.randint(0, 9), True, None, 1.5])
    if roll < 0.65:
        return {f"k{i}": _random_body(rng, depth + 1, budget) for i in range(rng.randint(0, 6))}
    return [_random_body(rng, depth + 1, budget) for _ in range(rng.randint(0, 25))]


@pytest.mark.parametrize("seed", range(40))
def test_types_never_change(seed):
    rng = random.Random(seed)
    body = {"a": _random_body(rng), "b": _random_body(rng), "request_headers": {"h": "v"}}
    out, _ = _bounded_body(body)
    assert isinstance(out, dict) and encoded(out) <= t._BODY_MAX_CHARS
    _same_shape(body, out)


def test_long_chat_keeps_the_newest_messages_in_order():
    msgs = [{"role": "user", "content": f"message {i} " + "y" * 400} for i in range(300)]
    out, cut = _bounded_body({"model": "m", "messages": msgs})
    assert cut is True and encoded(out) <= t._BODY_MAX_CHARS
    kept = [m["content"].split(" ")[1] for m in out["messages"]]
    assert kept[-1] == "299"
    assert kept == sorted(kept, key=int)


def test_list_and_scalar_bodies_keep_their_type():
    out, cut = _bounded_body([{"id": i, "name": "n" * 600} for i in range(200)])
    assert isinstance(out, list) and cut is True and encoded(out) <= t._BODY_MAX_CHARS
    assert _bounded_body("plain") == ("plain", False)


def test_many_keys_falls_back_to_metadata():
    body = {f"field{i}": {"v": "z" * 100} for i in range(500)}
    body["request_headers"] = {"x-tf-api-key-id": KEY_ID}
    body["input_type"] = "request"
    out, cut = _bounded_body(body)
    assert cut is True and encoded(out) <= t._BODY_MAX_CHARS
    assert out["request_headers"]["x-tf-api-key-id"] == KEY_ID
    assert out["input_type"] == "request"


# ── Redaction ────────────────────────────────────────────────────────────────

def test_credentials_are_redacted_at_any_depth_and_size():
    body = {
        "tenant_id": "acme",
        "api_keys": ["sk-live-1", "sk-live-2"],
        "request_headers": {"Authorization": "Bearer sk-abc", "X-API-Key": "sk-def",
                            "x-tf-api-key-id": KEY_ID, "x-agent-key": "[present]"},
        "nested": [{"deeper": {"Password": "hunter2", "refresh_token": "rt", "ok": "keep"}}],
        "client_secret": {"v": "s"},
    }
    out, cut = _bounded_body(body)
    assert cut is False
    text = json.dumps(out)
    for secret in ("sk-live-1", "sk-abc", "sk-def", "hunter2", '"rt"'):
        assert secret not in text, secret
    assert out["api_keys"] == ["[REDACTED]"]                  # still a list
    assert out["client_secret"] == {}                         # still an object
    assert out["request_headers"]["Authorization"] == "[REDACTED]"
    assert out["request_headers"]["x-tf-api-key-id"] == KEY_ID  # an id, not a credential
    assert out["request_headers"]["x-agent-key"] == "[present]"
    assert out["nested"][0]["deeper"]["ok"] == "keep"
    # The same holds when the body is long enough to be shortened.
    big = {**body, "texts": ["q" * 20_000]}
    out, cut = _bounded_body(big)
    assert cut is True and "sk-abc" not in json.dumps(out)


def test_api_key_response_is_redacted():
    out = build_response_event(trace_id="t", endpoint="/v1/tenant/me/api-keys",
                               status_code=200, latency_ms=1.0,
                               body={"api_key": "sk-new-secret", "prefix": "sk-new-se"})
    assert out["response.body"] == {"api_key": "[REDACTED]", "prefix": "sk-new-se"}


# ── Event builders ───────────────────────────────────────────────────────────

def test_events_flag_shortened_bodies_and_never_carry_a_string_body():
    small = build_request_event(trace_id="t", endpoint="/x", method="POST", body={"a": 1})
    assert small["request.body"] == {"a": 1} and "request.body_truncated" not in small
    big = build_request_event(trace_id="t", endpoint="/x", method="POST", body=litellm_body(10_000))
    assert isinstance(big["request.body"], dict) and big["request.body_truncated"] is True
    resp = build_response_event(trace_id="t", endpoint="/x", status_code=200, latency_ms=1.0,
                                body={"items": ["w" * 5000]})
    assert isinstance(resp["response.body"], dict) and resp["response.body_truncated"] is True
    none = build_request_event(trace_id="t", endpoint="/x", method="POST", body=None)
    assert none["request.body"] is None and "request.body_truncated" not in none


def test_legacy_mode_is_the_old_output(monkeypatch):
    monkeypatch.setenv(t.BODY_MODE_ENV, "legacy")
    body = litellm_body(10_000)
    ev = build_request_event(trace_id="t", endpoint="/x", method="POST", body=body)
    assert ev["request.body"] == t._truncate(body)
    assert isinstance(ev["request.body"], str) and "request.body_truncated" not in ev
    small = {"api_key": "sk-x"}
    assert build_request_event(trace_id="t", endpoint="/x", method="POST",
                               body=small)["request.body"] == small


def test_a_failure_drops_the_body_never_logs_it_raw(monkeypatch):
    def boom(v):
        raise RuntimeError("bug")
    monkeypatch.setattr(t, "_redact_body", boom)
    ev = build_request_event(trace_id="t", endpoint="/x", method="POST",
                             body={"api_key": "sk-x", "m": "hi"})
    assert ev["request.body"] is None and ev["request.body_truncated"] is True


# ── End to end through the middleware ────────────────────────────────────────

def test_long_litellm_call_is_logged_with_its_headers(monkeypatch):
    import core.telemetry_middleware as tm
    events = []
    monkeypatch.setattr(tm, "record_event", events.append)

    app = FastAPI()
    app.add_middleware(tm.TelemetryMiddleware)

    @app.post("/beta/litellm_basic_guardrail_api")
    async def route(request: Request):
        await asyncio.sleep(0)       # let the request event's task run
        return {"action": "NONE"}

    r = TestClient(app).post("/beta/litellm_basic_guardrail_api", json=litellm_body(30_000))
    assert r.status_code == 200
    req = next(e for e in events if e.get("event.action") == "request")
    assert req["request.body"]["request_headers"]["x-tf-api-key-id"] == KEY_ID
    assert req["request.body"]["request_data"]["user_api_key_org_id"] == "7w2lnkp"
    assert req["request.body_truncated"] is True
