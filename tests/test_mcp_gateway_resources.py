"""Task 1: MCPProxy resources/prompts methods + MCPUpstream adapter (fake upstream).

resources/read is DLP-sanitized; lists + prompts/get pass through. No live upstream.
"""

import asyncio
import types

import pytest

from core.mcp.proxy_server import MCPProxy
from core.mcp.upstream import MCPUpstream


def run(coro):
    return asyncio.run(coro)


ID = dict(agent_key="bot", user_role="reader", tenant_id="acme")


class FakeUpstream:
    """Upstream exposing resources + prompts (dict-shaped, like a fake)."""
    def __init__(self):
        self.reads = []

    async def list_resources(self):
        return [{"uri": "file://a", "name": "a"}, {"uri": "file://b", "name": "b"}]

    async def read_resource(self, uri):
        self.reads.append(uri)
        return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": "name=Jane ssn=123-45-6789"}]}

    async def list_resource_templates(self):
        return [{"uriTemplate": "file://{id}", "name": "tmpl"}]

    async def list_prompts(self):
        return [{"name": "greet", "description": "greeting"}]

    async def get_prompt(self, name, arguments):
        return {"description": "", "messages": [{"role": "user", "content": f"hi {arguments}"}]}


class _Redact:
    async def enforce_tool_call(self, *a, **k): return {"allowed": True, "action": "pass", "reason": ""}
    async def sanitize_tool_result(self, name, raw, **k):
        return {"blocked": False, "sanitized_output": str(raw).replace("123-45-6789", "[REDACTED]")}
    def filter_tools_for_role(self, tools, **k): return list(tools)


class _Block(_Redact):
    async def sanitize_tool_result(self, name, raw, **k):
        return {"blocked": True, "sanitized_output": None}


# ── resources ────────────────────────────────────────────────────────


def test_list_resources_passthrough():
    p = MCPProxy(FakeUpstream(), enforcer=_Redact())
    out = run(p.list_resources(**ID))
    assert [r["uri"] for r in out] == ["file://a", "file://b"]


def test_read_resource_is_dlp_sanitized():
    up = FakeUpstream()
    p = MCPProxy(up, enforcer=_Redact())
    out = run(p.read_resource("file://a", **ID))
    assert out["blocked"] is False
    assert out["contents"][0]["text"] == "name=Jane ssn=[REDACTED]"   # SSN redacted on the way out
    assert up.reads == ["file://a"]


def test_read_resource_block_withholds_content():
    p = MCPProxy(FakeUpstream(), enforcer=_Block())
    out = run(p.read_resource("file://a", **ID))
    assert out["blocked"] is True and out["contents"] == []
    assert "blocked by shield" in out["reason"].lower()


def test_list_resource_templates_passthrough():
    p = MCPProxy(FakeUpstream(), enforcer=_Redact())
    out = run(p.list_resource_templates(**ID))
    assert out[0]["uriTemplate"] == "file://{id}"


# ── prompts ──────────────────────────────────────────────────────────


def test_list_prompts_passthrough():
    p = MCPProxy(FakeUpstream(), enforcer=_Redact())
    assert [x["name"] for x in run(p.list_prompts(**ID))] == ["greet"]


def test_get_prompt_passthrough():
    p = MCPProxy(FakeUpstream(), enforcer=_Redact())
    out = run(p.get_prompt("greet", {"who": "x"}, **ID))
    assert out["messages"][0]["role"] == "user" and "x" in out["messages"][0]["content"]


# ── MCPUpstream adapter normalizes SDK-shaped objects ────────────────


def test_adapter_normalizes_sdk_objects():
    ns = types.SimpleNamespace

    class FakeSession:
        async def list_resources(self):
            return ns(resources=[ns(uri="file://x", name="x", description="d", mimeType="text/plain")])
        async def read_resource(self, uri):
            return ns(contents=[ns(uri=uri, mimeType="text/plain", text="hello")])
        async def list_prompts(self):
            return ns(prompts=[ns(name="p1", description="dp", arguments=[])])
        async def get_prompt(self, name, arguments):
            return ns(description="", messages=[ns(role="user", content=ns(text="hey"))])

    up = MCPUpstream(FakeSession())
    assert run(up.list_resources())[0] == {"uri": "file://x", "name": "x", "description": "d", "mimeType": "text/plain"}
    assert run(up.read_resource("file://x"))["contents"][0]["text"] == "hello"
    assert run(up.list_prompts())[0]["name"] == "p1"
    assert run(up.get_prompt("p1", {}))["messages"][0]["content"] == "hey"   # nested TextContent flattened
