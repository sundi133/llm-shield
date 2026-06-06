"""SDK wrap_tools tests — sync + async (deep-agents) enforcement.

These don't need a running Shield: we stub the HTTP-backed methods so the
test focuses on the wrapping logic (which path runs, deny short-circuits
execution, sanitization is applied, name/schema preserved).
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from votal import VotalShield  # noqa: E402
from votal.guard import ToolGuard  # noqa: E402

pytest.importorskip("langchain_core")
from langchain_core.tools import StructuredTool, tool  # noqa: E402


def _shield(allow=True, action="pass"):
    s = VotalShield(shield_url="http://x", api_key="k", agent_id="a", user_role="nurse")
    s.check_tool = lambda name, inp=None, **kw: ToolGuard(
        allowed=allow, action=action, reason="" if allow else "role denied")
    s.sanitize_output = lambda name, out, **kw: {
        "sanitized_output": "[REDACTED]" if action == "redact" else out,
        "action": action,
    }
    return s


def test_sync_tool_allowed_executes_and_preserves_schema():
    s = _shield(allow=True)

    @tool
    def lookup(patient_id: str) -> str:
        """Look up a patient."""
        return f"record:{patient_id}"

    wrapped = s.wrap_tools([lookup])[0]
    assert wrapped.name == "lookup"           # name preserved
    assert wrapped.args_schema is not None     # schema preserved
    assert wrapped.invoke({"patient_id": "P1"}) == "record:P1"


def test_sync_tool_denied_short_circuits():
    s = _shield(allow=False)

    @tool
    def prescribe(patient_id: str, drug: str) -> str:
        """Prescribe."""
        raise AssertionError("tool body must NOT run when denied")

    wrapped = s.wrap_tools([prescribe])[0]
    out = wrapped.invoke({"patient_id": "P1", "drug": "amox"})
    assert "DENIED by Shield" in out


def test_async_tool_allowed_executes():
    s = _shield(allow=True)

    async def _impl(patient_id: str) -> str:
        return f"async:{patient_id}"

    t = StructuredTool.from_function(coroutine=_impl, name="alookup",
                                     description="async lookup")
    wrapped = s.wrap_tools([t])[0]
    assert wrapped.coroutine is not None
    out = asyncio.run(wrapped.ainvoke({"patient_id": "P9"}))
    assert out == "async:P9"


def test_async_tool_denied_short_circuits():
    s = _shield(allow=False)
    ran = {"v": False}

    async def _impl(patient_id: str) -> str:
        ran["v"] = True
        return "should not happen"

    t = StructuredTool.from_function(coroutine=_impl, name="adel",
                                     description="async delete")
    wrapped = s.wrap_tools([t])[0]
    out = asyncio.run(wrapped.ainvoke({"patient_id": "P9"}))
    assert "DENIED by Shield" in out
    assert ran["v"] is False                   # async body never ran


def test_async_output_blocked():
    s = _shield(allow=True, action="block")

    async def _impl(x: str) -> str:
        return "secret"

    t = StructuredTool.from_function(coroutine=_impl, name="a", description="d")
    wrapped = s.wrap_tools([t])[0]
    out = asyncio.run(wrapped.ainvoke({"x": "1"}))
    assert out == "[OUTPUT BLOCKED BY DATA POLICY]"


def test_interrupt_on_maps_only_requested():
    s = _shield()

    @tool
    def a(x: str) -> str:
        """a"""
        return x

    @tool
    def wire_transfer(x: str) -> str:
        """wt"""
        return x

    m = s.interrupt_on([a, wire_transfer], require_approval=["wire_transfer"])
    assert m == {"wire_transfer": True}
    assert s.interrupt_on([a, wire_transfer]) == {}   # none by default
