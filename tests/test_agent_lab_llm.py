"""The lab agents' model adapter sends screenshots correctly (task 0b, screen mode).

No live model and no anthropic package needed: the SDK client and httpx are
replaced by fakes that capture the request.
"""

import asyncio
import base64
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab" / "agent-traffic" / "agents"))

import llm  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\nfake"
SCHEMA = {"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]}


def test_anthropic_request_puts_the_screenshot_before_the_text(monkeypatch):
    captured = {}

    class Messages:
        async def create(self, **kw):
            captured.update(kw)
            usage = types.SimpleNamespace(input_tokens=10, output_tokens=2, cache_read_input_tokens=0,
                                          cache_creation_input_tokens=0)
            return types.SimpleNamespace(stop_reason="end_turn", usage=usage,
                                         content=[types.SimpleNamespace(type="text", text='{"a": 1}')])

    fake = types.ModuleType("anthropic")
    fake.APIStatusError = type("APIStatusError", (Exception,), {})
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setattr(llm, "_anthropic_client", lambda: types.SimpleNamespace(messages=Messages()))
    m = llm.LLM(provider="anthropic", model="claude-opus-5-5")
    out = asyncio.run(m.json_call("sys", "what next?", SCHEMA, images=[PNG]))
    assert out == {"a": 1}
    content = captured["messages"][0]["content"]
    assert content[0]["type"] == "image" and content[0]["source"]["media_type"] == "image/png"
    assert base64.b64decode(content[0]["source"]["data"]) == PNG
    assert content[-1] == {"type": "text", "text": "what next?"}


def test_openai_compatible_request_carries_a_data_url(monkeypatch):
    captured = {}

    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": '{"a": 2}'}}], "usage": {"prompt_tokens": 5}}

    class Client:
        def __init__(self, **_):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json, headers):
            captured["body"] = json
            return Resp()

    monkeypatch.setenv("AGENT_LLM_BASE_URL", "http://localhost:9/v1")
    monkeypatch.setattr(llm.httpx, "AsyncClient", Client)
    m = llm.LLM(provider="openai", model="any")
    assert asyncio.run(m.json_call("sys", "go", SCHEMA, images=[PNG])) == {"a": 2}
    parts = captured["body"]["messages"][1]["content"]
    assert parts[0] == {"type": "text", "text": "go"}
    assert parts[1]["image_url"]["url"].startswith("data:image/png;base64,")


def test_scripted_screen_plan_clicks_inside_the_element_box():
    user = ("Task: t\n\nPersona: {\"name\": \"A B\", \"email\": \"a@example.com\"}\n\nLast action result: none\n\n"
            "URL: /signup\nTitle: x\n\nPage text:\nhi\n\nElements:\n"
            '[0] input[type=text] label="Full name" box=100,200,300,40\n')
    step = llm._scripted_screen_step(user)
    assert step["action"] == "click_type" and step["text"] == "A B"
    assert 100 <= step["x"] <= 400 and 200 <= step["y"] <= 240
