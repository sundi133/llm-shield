"""OpenRouter backend mode (OpenAI-compatible, provider-routed)."""
import pytest


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("LLM_BACKEND_TYPE", "ENABLE_LITELLM", "LLM_BACKEND_URL", "LLM_MODEL_NAME",
              "OPENROUTER_API_KEY", "OPENROUTER_PROVIDERS", "OPENROUTER_ALLOW_FALLBACKS",
              "OPENROUTER_REASONING",
              "OLLAMA_API_KEY", "LLM_BACKEND_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def _openrouter(monkeypatch, **env):
    monkeypatch.setenv("LLM_BACKEND_TYPE", "openrouter")
    monkeypatch.setenv("LLM_MODEL_NAME", "qwen/qwen3.5-27b")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-xxx")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import importlib, core.llm_backend as m
    importlib.reload(m)
    return m


SCHEMA = {"type": "object", "properties": {"violates_policy": {"type": "boolean"}}}


def test_mode_detection_and_auth(monkeypatch):
    m = _openrouter(monkeypatch)
    assert m._is_openrouter_mode() is True
    assert m._is_ollama_mode() is False
    assert m._auth_headers() == {"Authorization": "Bearer sk-or-xxx"}


def test_payload_routes_to_deepinfra_with_json_schema(monkeypatch):
    m = _openrouter(monkeypatch)
    p = m._build_payload([{"role": "user", "content": "eval"}], 200, 0, SCHEMA)
    assert p["model"] == "qwen/qwen3.5-27b"
    assert p["provider"] == {"order": ["deepinfra"], "allow_fallbacks": True}
    assert p["response_format"]["type"] == "json_schema"
    assert p["response_format"]["json_schema"]["strict"] is True
    # OpenAI-strict structured output: every property must be in `required` and
    # additionalProperties:false, else the model omits fields (violates_policy went missing).
    sent = p["response_format"]["json_schema"]["schema"]
    assert sent["required"] == ["violates_policy"]
    assert sent["additionalProperties"] is False
    assert "chat_template_kwargs" not in p          # vLLM-only, not sent to OpenRouter
    assert "ONLY the JSON object" not in p["messages"][-1]["content"]  # no ollama hint


def test_reasoning_disabled_by_default(monkeypatch):
    # Reasoning models (qwen3.5-27b) burn max_tokens in the `reasoning` field and
    # return content=null -> guardrail crash. Off by default keeps content populated.
    m = _openrouter(monkeypatch)
    p = m._build_payload([{"role": "user", "content": "x"}], 200, 0, SCHEMA)
    assert p["reasoning"] == {"enabled": False}


def test_reasoning_escape_hatch(monkeypatch):
    m = _openrouter(monkeypatch, OPENROUTER_REASONING="true")
    p = m._build_payload([{"role": "user", "content": "x"}], 200, 0, SCHEMA)
    assert "reasoning" not in p


def test_parse_llm_json_rejects_null_content(monkeypatch):
    m = _openrouter(monkeypatch)
    with pytest.raises(ValueError, match="null content"):
        m.parse_llm_json(None)


def test_provider_override_and_no_fallback(monkeypatch):
    m = _openrouter(monkeypatch, OPENROUTER_PROVIDERS="DeepInfra,Together",
                    OPENROUTER_ALLOW_FALLBACKS="false")
    p = m._build_payload([{"role": "user", "content": "x"}], 10, 0, None)
    assert p["provider"] == {"order": ["DeepInfra", "Together"], "allow_fallbacks": False}
    assert "response_format" not in p  # CSV guardrails send none


def test_endpoint_url_no_double_v1(monkeypatch):
    m = _openrouter(monkeypatch)
    assert m._chat_completions_url("https://openrouter.ai/api/v1") == "https://openrouter.ai/api/v1/chat/completions"
    assert m._chat_completions_url("https://openrouter.ai/api") == "https://openrouter.ai/api/v1/chat/completions"
    assert m._chat_completions_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000/v1/chat/completions"


def test_vllm_and_ollama_unaffected(monkeypatch):
    import importlib, core.llm_backend as m
    # default = vllm
    for k in ("LLM_BACKEND_TYPE", "ENABLE_LITELLM"):
        monkeypatch.delenv(k, raising=False)
    importlib.reload(m)
    p = m._build_payload([{"role": "user", "content": "eval"}], 200, 0, SCHEMA)
    assert p["chat_template_kwargs"] == {"enable_thinking": False}   # vLLM path intact
    assert "provider" not in p
    # vLLM schema is left as-is (lenient guided decoding); strictify only runs on OpenRouter
    assert "required" not in p["response_format"]["json_schema"]["schema"]
    assert m._auth_headers() == {}                                    # no bearer for local vLLM
