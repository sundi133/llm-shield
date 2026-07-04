"""Ollama backend mode (LLM_BACKEND_TYPE=ollama) for core/llm_backend.py.

Covers: payload shape (model field, no vLLM-only kwargs), Qwen-gated
/no_think suppression, Bearer auth headers on both call paths, and
regression guards that default vLLM / LiteLLM payloads are unchanged.
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
        "ENABLE_LITELLM",
    ):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# Payload shape
# ---------------------------------------------------------------------------

def test_ollama_payload_has_model_and_no_vllm_kwargs(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_MODEL_NAME", "gemma4:31b")

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    assert payload["model"] == "gemma4:31b"
    assert "chat_template_kwargs" not in payload


def test_ollama_non_qwen_model_gets_clean_system_prompt(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_MODEL_NAME", "gemma4:31b")

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    system = payload["messages"][0]["content"]
    assert "/no_think" not in system
    assert "/set nothink" not in system


def test_ollama_qwen_model_gets_no_think(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_MODEL_NAME", "qwen3:8b")

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    system = payload["messages"][0]["content"]
    assert "/no_think" in system


def test_ollama_response_format_passthrough(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_MODEL_NAME", "gemma4:31b")

    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
    payload = llm_backend._build_payload(_messages(), 10, 0, schema)

    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["schema"] == schema


# ---------------------------------------------------------------------------
# Regression guards: existing modes unchanged
# ---------------------------------------------------------------------------

def test_vllm_default_payload_unchanged(monkeypatch):
    _clear_backend_env(monkeypatch)

    payload = llm_backend._build_payload(_messages(), 10, 0, None)

    assert payload["chat_template_kwargs"] == {"enable_thinking": False}
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

    # LiteLLM mode wins: model alias behavior + /no_think, no ollama gating.
    assert payload["model"] == "gemma4:31b"
    assert "/no_think" in payload["messages"][0]["content"]


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
# Call paths send the header (stubbed transports)
# ---------------------------------------------------------------------------

class _Resp:
    status_code = 200
    text = "{}"

    def json(self):
        return {"choices": []}


class _StubSession:
    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Resp()


class _StubAsyncClient:
    def __init__(self):
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Resp()


def test_llm_call_sends_bearer_in_ollama_mode(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_BACKEND_URL", "https://ollama.com")
    monkeypatch.setenv("LLM_MODEL_NAME", "gemma4:31b")
    monkeypatch.setenv("OLLAMA_API_KEY", "sk-test")

    session = _StubSession()
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    llm_backend.llm_call(_messages())

    url, kwargs = session.calls[0]
    assert url == "https://ollama.com/v1/chat/completions"
    assert kwargs["headers"] == {"Authorization": "Bearer sk-test"}
    assert kwargs["json"]["model"] == "gemma4:31b"


def test_llm_call_no_headers_in_vllm_mode(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_URL", "http://127.0.0.1:8000")

    session = _StubSession()
    monkeypatch.setattr(llm_backend, "_get_shared_session", lambda: session)

    llm_backend.llm_call(_messages())

    _, kwargs = session.calls[0]
    assert kwargs["headers"] is None


@pytest.mark.asyncio
async def test_async_llm_call_sends_bearer_in_ollama_mode(monkeypatch):
    _clear_backend_env(monkeypatch)
    monkeypatch.setenv("LLM_BACKEND_TYPE", "ollama")
    monkeypatch.setenv("LLM_BACKEND_URL", "https://ollama.com")
    monkeypatch.setenv("LLM_MODEL_NAME", "gemma4:31b")
    monkeypatch.setenv("OLLAMA_API_KEY", "sk-test")

    client = _StubAsyncClient()
    monkeypatch.setattr(llm_backend, "_get_shared_client", lambda: client)

    result = await llm_backend.async_llm_call(_messages())

    url, kwargs = client.calls[0]
    assert url == "https://ollama.com/v1/chat/completions"
    assert kwargs["headers"] == {"Authorization": "Bearer sk-test"}
    assert kwargs["json"]["model"] == "gemma4:31b"
    assert result["_timing"]["server_url"] == "https://ollama.com"
