"""Regression: hosted MCP shield_check_tool must not crash on a bad import.

Production failed with `No module named 'guardrails.agentic.tools'` because
api/routes_mcp_server.py imported the package as `agentic.tools` (plural) while
the real path is `agentic.tool` (singular). The handler's broad `except`
swallowed the ImportError into an `ERROR — tool check failed: ...` string, so
it passed import-time checks but returned an error for every call.

These tests pin the correct path and assert shield_check_tool returns a real
authorization decision instead of an import error.

    PYTHONPATH=. pytest tests/test_mcp_shield_check_tool_import.py
"""

import asyncio
import importlib
import types

import pytest


def test_canonical_tool_allowlist_path_imports():
    # the path routes_mcp_server.py must use
    mod = importlib.import_module("guardrails.agentic.tool.tool_allowlist")
    assert hasattr(mod, "ToolAllowlistGuardrail")


def test_wrong_plural_path_does_not_exist():
    # guards against re-introducing the `agentic.tools` (plural) typo
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("guardrails.agentic.tools.tool_allowlist")


def _fake_request(tenant_id=""):
    state = types.SimpleNamespace(tenant_id=tenant_id, agent_key="mcp-agent")
    # shield_check_tool now delegates to the full /v1/shield/tool/check handler,
    # which reads request.headers and request.client — provide them.
    return types.SimpleNamespace(state=state, headers={}, client=None)


def test_shield_check_tool_returns_decision_not_import_error():
    from api.routes_mcp_server import _handle_tool_call

    result = asyncio.run(_handle_tool_call(
        "shield_check_tool",
        {"tool_name": "get_demo", "user_role": "developer"},
        _fake_request(),
    ))

    # the original bug surfaced here as the swallowed import error
    assert "No module named" not in result
    assert not result.startswith("ERROR — tool check failed")
    # a normal authorization verdict instead
    assert result.startswith("ALLOWED") or result.startswith("BLOCKED")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
