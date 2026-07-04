"""Ollama backend mode (LLM_BACKEND_TYPE=ollama) for core/llm_backend.py.

Ollama mode targets the NATIVE /api/chat endpoint (not OpenAI-compat):
`think: false` is honored there, and `format` enforces JSON schemas
server-side. Covers: native payload shape, think gating via OLLAMA_THINK,
Bearer auth on both call paths, response adaptation to the OpenAI shape,
and regression guards that default vLLM / LiteLLM payloads are unchanged.
No network — transports are stubbed.
"""

import pytest

from core import llm_backend


def _messages():
    return [
        {"role": "system", "content": "You are a guardrail."},
        {"role": "user", "content": "hello"},
    ]


def _clear_backend_env(monkeypatch):
    for var in (
        "LLM_BACKEND_TYPE",
        "LLM_BACKEND_URL",
        "LLM_MODEL_NAME",
        "OLLAMA_API_KEY",
        "LLM_BACKEND_API_KEY",
        "OLLAMA_THINK",
        "ENABLE_LITELLM",
    ):
        monkeypatch.delenv(var, raising=False)


def _set_ollama(monkeypatch, model="gemma4:31b"):
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_MODEL_NAME", model)


# ---------------------------------------------------------------------------
# Native payload shape
# ---------------------------------------------------------------------------

def test_ollama_payload_is_native_api_shape(monkeypatch):
    _clear_backend_env(monkeypatch)
    _set_ollama(monkeypatch)

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    assert payload["model"] == "gemma4:31b"
    assert payload["stream"] is False
    assert payload["options"] == {"temperature": 0, "num_predict": 10}
    assert payload["think"] is False  # default: thinking disabled
    assert "max_tokens" not in payload
    assert "chat_template_kwargs" not in payload
    assert "response_format" not in payload


def test_ollama_no_prompt_pollution(monkeypatch):
    """No /no_think prompt hack in ollama mode — the think param handles it."""
    _clear_backend_env(monkeypatch)
    _set_ollama(monkeypatch, model="qwen3.5:4b")

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    system = payload["messages"][0]["content"]
    assert "/no_think" not in system
    assert "/set nothink" not in system


def test_ollama_think_env_overrides(monkeypatch):
    _clear_backend_env(monkeypatch)
    _set_ollama(monkeypatch)

    monkeypatch.setenv("OLLAMA_THINK", "true")
    assert llm_backend._build_payload(_messages(), 10, 0, None)["think"] is True

    monkeypatch.setenv("OLLAMA_THINK", "auto")
    assert "think" not in llm_backend._build_payload(_messages(), 10, 0, None)


def test_ollama_schema_becomes_native_format(monkeypatch):
    """response_format schema maps to the native `format` field, unwrapped."""
    _clear_backend_env(monkeypatch)
    _set_ollama(monkeypatch)

    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    payload = llm_backend._build_payload(_messages(), 10, 0, schema)

    assert payload["format"] == schema
    assert "response_format" not in payload


# ---------------------------------------------------------------------------
# Response adaptation
# ---------------------------------------------------------------------------

def test_adapt_ollama_response_to_openai_shape():
    native = {
        "model": "gemma4:31b",
        "message": {"role": "assistant", "content": '{"ok": true}'},
        "done": True,
        "done_reason": "stop",
    }
    adapted = llm_backend._adapt_ollama_response(native)
    assert adapted["choices"][0]["message"]["content"] == '{"ok": true}'
    assert adapted["choices"][0]["finish_reason"] == "stop"


def test_adapt_ollama_response_passes_errors_through():
    err = {"error": "model not found"}
    assert llm_backend._adapt_ollama_response(err) == err


# ---------------------------------------------------------------------------
# Regression guards: existing modes unchanged
# ---------------------------------------------------------------------------

def test_vllm_default_payload_unchanged(monkeypatch):
    _clear_backend_env(monkeypatch)

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    assert payload["chat_template_kwargs"] == {"enable_thinking": False}
    assert payload["max_tokens"] == 10
    assert "model" not in payload
    assert "/no_think" in payload["messages"][0]["content"]


def test_litellm_payload_unchanged(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("ENABLE_LITELLM", "true")

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    assert payload["model"] == "default"
    assert "chat_template_kwargs" not in payload
    assert "/no_think" in payload["messages"][0]["content"]


def test_litellm_takes_precedence_over_ollama_type(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("ENABLE_LITELLM", "true")
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_MODEL_NAME", "gemma4:31b")

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    # LiteLLM mode wins: OpenAI-shape payload, no native ollama fields.
    assert payload["model"] == "gemma4:31b"
    assert payload["max_tokens"] == 10
    assert "options" not in payload
    assert "think" not in payload


def test_vllm_response_format_wrapper_unchanged(monkeypatch):
    _clear_backend_env(monkeypatch)

    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    payload = llm_backend._build_payload(_messages(), 10, 0, schema)

    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["schema"] == schema


# ---------------------------------------------------------------------------
# Auth headers
# ---------------------------------------------------------------------------

def test_auth_headers_ollama_with_key(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("OLLAMA_API_KEY", "sk-test")

    assert llm_backend._auth_headers() == {"Authorization": "Bearer sk-test"}


def test_auth_headers_generic_alias(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_BACKEND_API_KEY", "sk-alias")

    assert llm_backend._auth_headers() == {"Authorization": "Bearer sk-alias"}


def test_auth_headers_ollama_without_key(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")

    assert llm_backend._auth_headers() == {}


def test_auth_headers_absent_in_vllm_mode_even_with_key(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("OLLAMA_API_KEY", "sk-test")

    assert llm_backend._auth_headers() == {}


# ---------------------------------------------------------------------------
# Call paths: native endpoint, Bearer header, adapted response
# ---------------------------------------------------------------------------

_NATIVE_RESPONSE = {
    "model": "gemma4:31b",
    "message": {"role": "assistant", "content": '{"safe": true}'},
    "done": True,
    "done_reason": "stop",
}


class _Resp:
    status_code = 200
    text = "{}"

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _StubSession:
    def __init__(self, body):
        self.calls = []
        self._body = body

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Resp(self._body)


class _StubAsyncClient:
    def __init__(self, body):
        self.calls = []
        self._body = body

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Resp(self._body)


def test_llm_call_uses_native_endpoint_and_bearer(monkeypatch):
    _clear_backend_env(monkeypatch)
    _set_ollama(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_URL", "https://ollama.com")
    monkeypatch.setenv("OLLAMA_API_KEY", "sk-test")

    session = _StubSession(dict(_NATIVE_RESPONSE))
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    result = llm_backend.llm_call(_messages())

    url, kwargs = session.calls[0]
    assert url == "https://ollama.com/api/chat"
    assert kwargs["headers"] == {"Authorization": "Bearer sk-test"}
    assert kwargs["json"]["model"] == "gemma4:31b"
    # Response adapted so guardrail callers keep working unchanged
    assert result["choices"][0]["message"]["content"] == '{"safe": true}'


def test_llm_call_vllm_mode_unchanged(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_URL", "http://127.0.0.1:8000")

    openai_body = {"choices": [{"message": {"content": "ok"}}]}
    session = _StubSession(openai_body)
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    result = llm_backend.llm_call(_messages())

    url, kwargs = session.calls[0]
    assert url == "http://127.0.0.1:8000/v1/chat/completions"
    assert kwargs["headers"] is None
    assert result == openai_body


@pytest.mark.asyncio
async def test_async_llm_call_native_endpoint_and_adaptation(monkeypatch):
    _clear_backend_env(monkeypatch)
    _set_ollama(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_URL", "https://ollama.com")
    monkeypatch.setenv("OLLAMA_API_KEY", "sk-test")

    client = _StubAsyncClient(dict(_NATIVE_RESPONSE))
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages())

    url, kwargs = client.calls[0]
    assert url == "https://ollama.com/api/chat"
    assert kwargs["headers"] == {"Authorization": "Bearer sk-test"}
    assert kwargs["json"]["think"] is False
    assert result["choices"][0]["message"]["content"] == '{"safe": true}'
    assert result["_timing"]["server_url"] == "https://ollama.com"


# ---------------------------------------------------------------------------
# parse_llm_json: markdown fence stripping (gemma4 on ollama.com fences its
# JSON even when a format schema is requested)
# ---------------------------------------------------------------------------

def test_parse_llm_json_strips_json_fence():
    raw = '```json\n{"violates_policy": true, "confidence": 1.0}\n```'
    assert llm_backend.parse_llm_json(raw) == {
        "violates_policy": True,
        "confidence": 1.0,
    }


def test_parse_llm_json_strips_bare_fence():
    raw = '```\n{"ok": true}\n```'
    assert llm_backend.parse_llm_json(raw) == {"ok": True}


def test_parse_llm_json_plain_json_unchanged():
    assert llm_backend.parse_llm_json('{"ok": true}') == {"ok": True}


def test_parse_llm_json_backticks_inside_strings_untouched():
    raw = '{"reasoning": "use ```code``` blocks"}'
    assert llm_backend.parse_llm_json(raw) == {"reasoning": "use ```code``` blocks"}
