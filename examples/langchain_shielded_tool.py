"""Wrap any LangChain tool so every call is gated by a Shield capability.

This is the AGENT plane (Plane 2) of the two-plane architecture: it authorizes
tool calls. The LLM and its input/output guardrails belong to Plane 1 — point
your ChatOpenAI base_url at the LiteLLM proxy (whose config.yaml has the
votal.ai guardrails callback) and guardrails run there automatically. This
factory does NOT call /guardrails/*; it only mints + verifies capability tokens
for each tool the agent invokes.

The wrapper does three things on every tool invocation:
  1. Asks Shield to authorize THIS call (tool + resource).
  2. If allowed, gets back a one-shot capability token.
  3. Sends the cap to the tool side (verify_cap) before executing.

If step 1 or 3 fails, the tool raises and LangChain surfaces the reason
to the LLM. Customers do not need the admin key — only their tenant
API key.

Usage:

    from langchain.tools import tool
    from examples.shield_client import ShieldClient
    from examples.langchain_shielded_tool import ShieldedToolFactory

    shield = ShieldClient(base_url="https://shield.acme.com")
    token = shield.mint_agent_token(
        user_sub="alice@acme.com",
        agent_id="billing-bot",
        agent_instance_id=f"pod-{os.environ['HOSTNAME']}",
        build_hash="sha256:abc",
        model_version="claude-opus-4.7",
        session_id=conversation_id,
    )
    factory = ShieldedToolFactory(shield, token)

    @tool
    def send_email_raw(to: str, body: str) -> str:
        '''send an email'''
        ...

    # Wrap once; LangChain treats it as a normal Tool:
    send_email = factory.wrap(send_email_raw, resource_fn=lambda kwargs: f"user/{kwargs['to']}/inbox")

    agent = create_react_agent(llm, [send_email])

Requires:
    pip install langchain  (or langchain-core)
"""

from __future__ import annotations

import os
import sys
from typing import Any, Callable, Optional

# Same dual-import bootstrap as openai_shielded_tool.py
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    from langchain.tools.base import BaseTool
except Exception:  # langchain not installed in the smoke-test sandbox
    BaseTool = object  # type: ignore[assignment,misc]

from shield_client import AgentToken, ShieldClient, ShieldError  # noqa: E402


class ShieldedToolFactory:
    """Wraps LangChain tools with cap mint+verify.

    Pass the same `token` to wrap() for every tool used in one agent
    session — caps inherit the user/agent identity from it.
    """

    def __init__(
        self,
        client: ShieldClient,
        token: AgentToken,
        *,
        verify_on_tool_side: bool = True,
        clearance_max: str = "public",
        cap_ttl_seconds: int = 30,
    ):
        self.client = client
        self.token = token
        self.verify_on_tool_side = verify_on_tool_side
        self.clearance_max = clearance_max
        self.cap_ttl_seconds = cap_ttl_seconds

    def wrap(
        self,
        tool: "BaseTool",
        *,
        resource_fn: Optional[Callable[[dict], str]] = None,
        scope_fn: Optional[Callable[[dict], list[str]]] = None,
    ) -> "BaseTool":
        """Return a new tool that mint+verifies a cap on every call.

        Args:
            tool:         the original LangChain tool to protect.
            resource_fn:  builds the per-call resource string from kwargs.
                          E.g. for an email tool: lambda k: f"user/{k['to']}/inbox".
                          Defaults to tool.name (coarse but safe).
            scope_fn:     optional extra constraints baked into the cap.
                          E.g. lambda k: [f"to:{k['to']}", f"max_body_chars:{len(k['body'])}"].
        """
        client = self.client
        token = self.token
        verify = self.verify_on_tool_side
        clearance = self.clearance_max
        ttl = self.cap_ttl_seconds
        tool_name = getattr(tool, "name", tool.__class__.__name__)

        # Preserve the original run methods
        original_run = getattr(tool, "_run", None) or tool.run
        original_arun = getattr(tool, "_arun", None)

        def _resource(kwargs: dict) -> str:
            if resource_fn:
                return resource_fn(kwargs)
            return tool_name

        def _scope(kwargs: dict) -> list[str]:
            return scope_fn(kwargs) if scope_fn else []

        def _guarded_call(args: tuple, kwargs: dict, exec_fn: Callable):
            resource = _resource(kwargs)
            # 1. Ask Shield to authorize this call.
            try:
                cap = client.mint_cap(
                    token, tool=tool_name, resource=resource,
                    scope_constraints=_scope(kwargs),
                    clearance_max=clearance, ttl_seconds=ttl,
                )
            except ShieldError as e:
                # Surface the denial to the LLM as a tool result.
                return f"DENIED by Shield: {e}"

            # 2. Tool side verifies the cap (with the same Shield instance,
            #    or its own pubkey + nonce store). Burns the nonce so a
            #    later replay would fail.
            if verify:
                ok, claims_or_err = client.verify_cap(cap, expected_tool=tool_name,
                                                     expected_resource=resource)
                if not ok:
                    return f"DENIED by Shield (verify): {claims_or_err.get('error')}"

            # 3. Now run the real tool.
            return exec_fn(*args, **kwargs)

        def shielded_run(*args, **kwargs):
            return _guarded_call(args, kwargs, original_run)

        async def shielded_arun(*args, **kwargs):
            if original_arun is None:
                # Fall back to sync if the tool has no async impl
                return shielded_run(*args, **kwargs)
            return await _guarded_call(args, kwargs, original_arun)

        # Mutate the tool's run methods in place. Keeps name/description
        # so LangChain agents see the same surface.
        tool._run = shielded_run  # type: ignore[attr-defined]
        if original_arun is not None:
            tool._arun = shielded_arun  # type: ignore[attr-defined]
        return tool
