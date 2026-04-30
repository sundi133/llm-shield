"""Tests for OpenAI-compatible streaming through the shield gateway."""

from unittest.mock import patch

from config.schema import AuthConfig, ShieldConfig
from core.models import GuardrailResult, PipelineResult


def _make_app(cfg):
    """Create app with a specific config, preventing load_config from overwriting."""
    import config.schema as cs

    original = cs.config
    cs.config = cfg
    with patch("config.schema.load_config", return_value=cfg):
        from core.app import create_app

        app = create_app()
    return app, original


class _FakeStreamResponse:
    status_code = 200
    headers = {"content-type": "text/event-stream"}

    async def aiter_lines(self):
        lines = [
            'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}',
            "",
            'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}],"usage":{"completion_tokens":2}}',
            "",
            "data: [DONE]",
            "",
        ]
        for line in lines:
            yield line

    async def aread(self):
        return b""


class _FakeStreamContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeAsyncClient:
    last_request = None

    def __init__(self, *args, **kwargs):
        pass

    def stream(self, method, url, json):
        self.__class__.last_request = {"method": method, "url": url, "json": json}
        return _FakeStreamContext(_FakeStreamResponse())

    async def aclose(self):
        return None


class _StreamBlockingGuardrail:
    name = "stream_block_guardrail"
    tier = "fast"
    stage = "output"
    enabled = True
    configured_action = "block"

    async def check(self, content: str, context: dict):
        if "world" in content:
            return GuardrailResult(
                passed=False,
                action="block",
                guardrail_name=self.name,
                message="Blocked mid-stream",
            )
        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="ok",
        )


async def _allow_input(*args, **kwargs):
    return PipelineResult(allowed=True, results=[], total_latency_ms=0.0)


async def _allow_output(content: str, context: dict):
    return PipelineResult(
        allowed=True,
        results=[
            GuardrailResult(
                passed=True,
                action="pass",
                guardrail_name="stream_test_guardrail",
            )
        ],
        total_latency_ms=0.0,
    )


async def _noop_audit(*args, **kwargs):
    return None


def test_gateway_streams_openai_sse():
    import config.schema as cs
    from starlette.testclient import TestClient

    cfg = ShieldConfig(auth=AuthConfig(enabled=False))
    app, original = _make_app(cfg)

    try:
        with (
            patch("api.routes_gateway._get_upstream_url", return_value="https://upstream.test"),
            patch("api.routes_gateway.run_input_pipeline", side_effect=_allow_input),
            patch("api.routes_gateway.run_output_pipeline", side_effect=_allow_output),
            patch("api.routes_gateway.audit_logger.log", side_effect=_noop_audit),
            patch("api.routes_gateway.httpx.AsyncClient", _FakeAsyncClient),
        ):
            client = TestClient(app)
            with client.stream(
                "POST",
                "/v1/shield/chat/completions",
                json={
                    "messages": [{"role": "user", "content": "Say hello"}],
                    "stream": True,
                },
            ) as resp:
                body = "".join(resp.iter_text())

            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            assert resp.headers["x-trace-id"]
            assert "data: [DONE]" in body
            assert '"content":"hello"' in body
            assert '"content":" world"' in body

            assert _FakeAsyncClient.last_request is not None
            assert _FakeAsyncClient.last_request["method"] == "POST"
            assert _FakeAsyncClient.last_request["url"] == "https://upstream.test/v1/chat/completions"
            assert _FakeAsyncClient.last_request["json"]["stream"] is True
    finally:
        cs.config = original


def test_gateway_stream_blocks_before_violating_chunk_is_emitted():
    import config.schema as cs
    from starlette.testclient import TestClient

    cfg = ShieldConfig(auth=AuthConfig(enabled=False))
    app, original = _make_app(cfg)

    try:
        with (
            patch("api.routes_gateway._get_upstream_url", return_value="https://upstream.test"),
            patch("api.routes_gateway.run_input_pipeline", side_effect=_allow_input),
            patch("api.routes_gateway.run_output_pipeline", side_effect=_allow_output),
            patch("api.routes_gateway.audit_logger.log", side_effect=_noop_audit),
            patch("api.routes_gateway.httpx.AsyncClient", _FakeAsyncClient),
            patch("api.routes_gateway.get_by_stage", return_value=[_StreamBlockingGuardrail()]),
            patch("api.routes_gateway._STREAM_FAST_CHECK_EVERY_CHARS", 1),
        ):
            client = TestClient(app)
            with client.stream(
                "POST",
                "/v1/shield/chat/completions",
                json={
                    "messages": [{"role": "user", "content": "Say hello"}],
                    "stream": True,
                },
            ) as resp:
                body = "".join(resp.iter_text())

            assert resp.status_code == 200
            assert '"content":"hello"' in body
            assert '"content":" world"' not in body
            assert '"finish_reason": "content_filter"' in body or '"finish_reason":"content_filter"' in body
            assert '"guardrail": "stream_block_guardrail"' in body or '"guardrail":"stream_block_guardrail"' in body
            assert "data: [DONE]" in body
    finally:
        cs.config = original
