"""HR QA deep-mcp-005: a JSON-RPC batch (array) body must not crash with HTTP 500.

The /mcp/message handler did body.get(...) directly, so an array body raised
AttributeError -> 500. It now accepts single objects and batches, and turns
malformed/failed requests into JSON-RPC error objects instead of 500.
"""
import asyncio
import json

from api.routes_mcp_server import _dispatch_mcp_message, mcp_message


class _Req:
    """Minimal stand-in for starlette Request for these handlers."""
    def __init__(self, body):
        self._b = body
        self.headers = {}

    async def json(self):
        return self._b


def _run(coro):
    return asyncio.run(coro)


# --- per-message dispatch -------------------------------------------------

def test_dispatch_tools_list():
    r = _run(_dispatch_mcp_message({"method": "tools/list", "id": 1}, _Req({})))
    assert r["id"] == 1 and "tools" in r["result"]


def test_dispatch_unknown_method_is_jsonrpc_error():
    r = _run(_dispatch_mcp_message({"method": "nope", "id": 2}, _Req({})))
    assert r["error"]["code"] == -32601


def test_dispatch_non_dict_is_invalid_request():
    r = _run(_dispatch_mcp_message(["not", "a", "dict"], _Req({})))
    assert r["error"]["code"] == -32600


# --- batch + single via the route ----------------------------------------

def test_batch_returns_array_of_responses():
    body = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    resp = _run(mcp_message(_Req(body)))
    data = json.loads(resp.body)
    assert isinstance(data, list) and len(data) == 2
    assert {d["id"] for d in data} == {1, 2}


def test_empty_batch_is_invalid_not_500():
    resp = _run(mcp_message(_Req([])))
    data = json.loads(resp.body)
    assert data["error"]["code"] == -32600


def test_batch_with_one_unknown_method_does_not_crash():
    body = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "bogus/method"},
    ]
    resp = _run(mcp_message(_Req(body)))
    data = json.loads(resp.body)
    assert len(data) == 2
    errs = [d for d in data if "error" in d]
    assert errs and errs[0]["error"]["code"] == -32601


def test_single_message_unchanged():
    resp = _run(mcp_message(_Req({"jsonrpc": "2.0", "id": 5, "method": "tools/list"})))
    data = json.loads(resp.body)
    assert data["id"] == 5 and "tools" in data["result"]
