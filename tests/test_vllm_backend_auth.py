"""vllm backend mode: optional bearer token and model name
(docs/specs/onprem-release-bundle.md, task 2).

A model served on OpenShift AI with token auth needs `Authorization: Bearer`,
and a gateway in front of vLLM may route on `model`. Both are opt-in: with
LLM_BACKEND_API_KEY and LLM_MODEL_NAME unset, the request is exactly what it
was before, so every existing vLLM deployment (RunPod, in-pod) is unchanged.
"""

import importlib

import httpx
import pytest

SCHEMA = {"type": "object", "properties": {"violates_policy": {"type": "boolean"}}}
MESSAGES = [{"role": "system", "content": "policy"}, {"role": "user", "content": "hi"}]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("LLM_BACKEND_TYPE", "ENABLE_LITELLM", "LLM_BACKEND_URL", "LLM_MODEL_NAME",
              "OPENROUTER_API_KEY", "OLLAMA_API_KEY", "LLM_BACKEND_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def _backend(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import core.llm_backend as m
    importlib.reload(m)
    return m


def _payload(m, response_format=SCHEMA):
    return m._build_payload([dict(x) for x in MESSAGES], 10, 0, response_format)


# The exact request a vLLM deployment sent before this change (default
# LLM_BACKEND_TYPE=vllm, nothing else set). Built by hand, not by the code under
# test, so a change to the default request fails here.
def _legacy_payload(m, response_format=SCHEMA):
    msgs = [dict(x) for x in MESSAGES]
    if m._nothink_suffix_enabled():
        msgs = m._ensure_no_think(msgs)
    p = {"messages": msgs, "max_tokens": 10, "temperature": 0,
         "chat_template_kwargs": {"enable_thinking": False}}
    if response_format:
        p["response_format"] = {"type": "json_schema", "json_schema": {
            "name": "response", "strict": True, "schema": response_format}}
    return p


@pytest.mark.parametrize("env", [{}, {"LLM_BACKEND_TYPE": "vllm"}])
def test_unset_is_byte_identical_to_before(monkeypatch, env):
    m = _backend(monkeypatch, **env)
    assert _payload(m) == _legacy_payload(m)
    assert _payload(m, None) == _legacy_payload(m, None)
    assert "model" not in _payload(m)
    assert m._auth_headers() == {}


def test_bearer_and_model_when_set(monkeypatch):
    m = _backend(monkeypatch, LLM_BACKEND_API_KEY="tok-123",
                 LLM_MODEL_NAME="votal-ai/vai35-4B-v2")
    assert m._auth_headers() == {"Authorization": "Bearer tok-123"}
    p = _payload(m)
    assert p["model"] == "votal-ai/vai35-4B-v2"
    assert {k: v for k, v in p.items() if k != "model"} == _legacy_payload(m)


def test_other_services_keys_are_never_sent_to_vllm(monkeypatch):
    m = _backend(monkeypatch, OPENROUTER_API_KEY="sk-or-xxx", OLLAMA_API_KEY="ol-xxx")
    assert m._auth_headers() == {}


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_values_count_as_unset(monkeypatch, value):
    m = _backend(monkeypatch, LLM_BACKEND_API_KEY=value, LLM_MODEL_NAME=value)
    assert m._auth_headers() == {}
    assert "model" not in _payload(m)


def test_litellm_mode_is_unchanged(monkeypatch):
    m = _backend(monkeypatch, ENABLE_LITELLM="true", LLM_BACKEND_API_KEY="tok-123")
    assert m._auth_headers() == {}
    assert _payload(m)["model"] == "default"
    assert "chat_template_kwargs" not in _payload(m)


def test_unknown_backend_type_gets_no_new_fields(monkeypatch):
    m = _backend(monkeypatch, LLM_BACKEND_TYPE="litellm", LLM_BACKEND_API_KEY="tok-123",
                 LLM_MODEL_NAME="x")
    assert m._auth_headers() == {}
    assert "model" not in _payload(m)


def test_openrouter_and_ollama_unchanged(monkeypatch):
    m = _backend(monkeypatch, LLM_BACKEND_TYPE="openrouter", OPENROUTER_API_KEY="sk-or",
                 LLM_MODEL_NAME="qwen/qwen3.5-27b")
    assert m._auth_headers() == {"Authorization": "Bearer sk-or"}
    monkeypatch.delenv("OPENROUTER_API_KEY")
    m = _backend(monkeypatch, LLM_BACKEND_TYPE="ollama", OLLAMA_API_KEY="ol",
                 LLM_MODEL_NAME="gemma4:31b")
    assert m._auth_headers() == {"Authorization": "Bearer ol"}


@pytest.mark.asyncio
async def test_the_guard_path_call_carries_both(monkeypatch):
    """async_llm_call, the call every model guardrail makes, sends them."""
    m = _backend(monkeypatch, LLM_BACKEND_URL="http://shield-model:8000",
                 LLM_BACKEND_API_KEY="tok-123", LLM_MODEL_NAME="votal-ai/vai35-4B-v2")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    monkeypatch.setattr(m, "_shared_client", httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await m.async_llm_call(MESSAGES, max_tokens=5)
    assert seen["url"] == "http://shield-model:8000/v1/chat/completions"
    assert seen["auth"] == "Bearer tok-123"
    assert seen["body"]["model"] == "votal-ai/vai35-4B-v2"
