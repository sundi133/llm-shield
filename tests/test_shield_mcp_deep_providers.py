"""Deep-scan provider abstraction + backend resolution (deep-scan Task 2)."""

import asyncio
import json

import httpx
import pytest

from shield_mcp.providers import (
    resolve_client,
    OpenAIClient,
    AnthropicClient,
    DeepConfigError,
)

_SCHEMA = {"type": "object", "properties": {"findings": {"type": "array"}},
           "required": ["findings"], "additionalProperties": False}


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ("SHIELD_DEEP_URL", "SHIELD_DEEP_MODEL", "SHIELD_DEEP_API_KEY",
              "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)


# ── resolution: hard error when unconfigured ──
def test_openai_requires_url_and_model():
    with pytest.raises(DeepConfigError, match="deep-url"):
        resolve_client("openai", model="m")          # no url
    with pytest.raises(DeepConfigError, match="deep-model"):
        resolve_client("openai", url="http://h/v1")  # no model
    c = resolve_client("openai", url="http://h/v1", model="m", api_key="k")
    assert isinstance(c, OpenAIClient) and c.model == "m"


def test_anthropic_requires_key_defaults_model():
    with pytest.raises(DeepConfigError, match="ANTHROPIC_API_KEY"):
        resolve_client("anthropic")
    c = resolve_client("anthropic", api_key="sk")
    assert isinstance(c, AnthropicClient)
    assert c.model == "claude-opus-4-8"  # documented default


def test_unknown_provider_errors():
    with pytest.raises(DeepConfigError, match="unknown --deep-provider"):
        resolve_client("gemini", url="x", model="y")


def test_env_resolution(monkeypatch):
    monkeypatch.setenv("SHIELD_DEEP_URL", "http://env/v1")
    monkeypatch.setenv("SHIELD_DEEP_MODEL", "env-model")
    c = resolve_client("openai")
    assert c.base_url == "http://env/v1" and c.model == "env-model"


def test_default_provider_is_openai(monkeypatch):
    monkeypatch.setenv("SHIELD_DEEP_URL", "http://env/v1")
    monkeypatch.setenv("SHIELD_DEEP_MODEL", "m")
    assert isinstance(resolve_client(None), OpenAIClient)


# ── OpenAIClient.complete via a mocked transport (no network) ──
def test_openai_complete_parses_structured_json():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={
            "choices": [{"message": {"content": json.dumps({"findings": [{"x": 1}]})}}]
        })

    c = OpenAIClient(base_url="https://api.example/v1", model="gpt-x", api_key="secret",
                     transport=httpx.MockTransport(handler))
    out = asyncio.run(c.complete("SYS", "USER", _SCHEMA))
    assert out == {"findings": [{"x": 1}]}
    assert captured["url"].endswith("/chat/completions")
    assert captured["auth"] == "Bearer secret"
    assert captured["body"]["model"] == "gpt-x"
    assert captured["body"]["response_format"]["type"] == "json_schema"
    # system + user both sent
    roles = [m["role"] for m in captured["body"]["messages"]]
    assert roles == ["system", "user"]


def test_openai_complete_raises_on_5xx():
    def handler(request):
        return httpx.Response(500, json={"error": "down"})
    c = OpenAIClient(base_url="https://h/v1", model="m", transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(c.complete("s", "u", _SCHEMA))
