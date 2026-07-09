"""Gate every OpenAI/Anthropic tool call with a Shield capability.

This is the AGENT plane (Plane 2) of the two-plane architecture: it authorizes
tool calls. The LLM itself — and its input/output guardrails — belong to Plane 1
(the LiteLLM proxy): point your OpenAI/Anthropic client's base_url at the proxy
and guardrails run there automatically. This module does NOT call /guardrails/*;
it only mints + verifies capability tokens for the tools the model wants to run.

This is the no-framework path: you read the model's tool_calls and you
dispatch them yourself. To gate one with Shield, ask Shield to authorize
the call (mint cap) and have the tool side verify before executing.

Customers only need their tenant API key — no admin key.

Pattern (OpenAI-style, but identical for Anthropic):

    from examples.shield_client import ShieldClient, ShieldError

    shield = ShieldClient(base_url=os.environ["SHIELD_URL"])
    token = shield.mint_agent_token(
        user_sub="alice@acme.com",
        agent_id="billing-bot",
        agent_instance_id=f"pod-{os.getpid()}",
        build_hash="sha256:abc",
        model_version="claude-opus-4.7",
        session_id=conversation_id,
    )

    TOOL_REGISTRY = {
        "send_email": (real_send_email,  lambda args: f"user/{args['to']}/inbox"),
        "lookup_invoice": (real_lookup,  lambda args: f"invoice/{args['id']}"),
    }

    def run_tool(name: str, args: dict) -> str:
        fn, resource_fn = TOOL_REGISTRY[name]
        resource = resource_fn(args)
        try:
            cap = shield.mint_cap(token, tool=name, resource=resource)
        except ShieldError as e:
            return f"DENIED by policy: {e}"
        ok, claims_or_err = shield.verify_cap(cap, expected_tool=name,
                                              expected_resource=resource)
        if not ok:
            return f"DENIED at verify: {claims_or_err['error']}"
        return fn(**args)

    # Then in your model loop:
    for tc in completion.choices[0].message.tool_calls:
        result = run_tool(tc.function.name, json.loads(tc.function.arguments))
        # send `result` back to the model as the next message

Notes
-----

* `mint_cap` returns the authorization decision (allowed/denied + reasons).
  If denied, surface the reasons to the model in the tool result so it
  can apologize / ask for permission instead of looping.

* `verify_cap` burns the cap's nonce. If a buggy code path runs the same
  tool call twice, the second one fails fast with "cap replay detected" —
  which is exactly what you want for non-idempotent tools like payments
  or emails.

* Caps default to 30s TTL. That's deliberately short: if your tool takes
  longer than 30s, mint with `ttl_seconds=60` and treat that as the
  upper bound. Anything longer means you should be doing it async with
  a separate scheduling primitive, not a single cap.

* The `decision` field on the returned cap is interesting for audit:
  it contains the agent role Shield used, what tool/resource it locked
  the cap to, and the reasons (empty list on allow).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable

# Make the SDK importable whether you run this as a script
# (`python3 examples/openai_shielded_tool.py`) or as a module
# (`python3 -m examples.openai_shielded_tool`).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from shield_client import AgentToken, ShieldClient, ShieldError  # noqa: E402


def shielded_dispatch(
    shield: ShieldClient,
    token: AgentToken,
    *,
    tool_name: str,
    tool_args: dict[str, Any],
    impl: Callable[..., str],
    resource_fn: Callable[[dict], str],
    scope_fn: Callable[[dict], list[str]] | None = None,
    clearance_max: str = "public",
) -> str:
    """Run one tool call gated by Shield. Returns a string the LLM will see."""
    resource = resource_fn(tool_args)
    try:
        cap = shield.mint_cap(
            token,
            tool=tool_name,
            resource=resource,
            scope_constraints=(scope_fn(tool_args) if scope_fn else []),
            clearance_max=clearance_max,
        )
    except ShieldError as e:
        # Send the denial back to the model. The "reasons" are inside
        # the message — the LLM can choose to apologize, ask the user,
        # or stop.
        return f"DENIED by Shield (mint): {e}"

    ok, claims_or_err = shield.verify_cap(cap, expected_tool=tool_name,
                                           expected_resource=resource)
    if not ok:
        return f"DENIED by Shield (verify): {claims_or_err['error']}"

    try:
        return impl(**tool_args)
    except Exception as e:
        return f"tool error: {e}"


# Minimal example you can run end-to-end against a Shield instance.
# Replace impl_send_email with whatever your tool actually does.
if __name__ == "__main__":
    import os

    def impl_send_email(to: str, body: str) -> str:
        # Pretend to send. In production, your SMTP/SES call goes here.
        return f"sent to {to}: {body[:40]}..."

    shield = ShieldClient(base_url=os.environ.get("SHIELD_URL", "http://localhost:8080"))
    token = shield.mint_agent_token(
        user_sub="alice@acme.com",
        agent_id="billing-bot",
        agent_instance_id=f"demo-{os.getpid()}",
        build_hash="sha256:demo",
        model_version="claude-opus-4.7",
        session_id="demo-session",
    )

    # Simulate the model deciding to call send_email
    fake_tool_call = {
        "name": "send_email",
        "arguments": json.dumps({"to": "user@acme.com", "body": "your invoice is ready"}),
    }
    args = json.loads(fake_tool_call["arguments"])

    result = shielded_dispatch(
        shield, token,
        tool_name=fake_tool_call["name"],
        tool_args=args,
        impl=impl_send_email,
        resource_fn=lambda a: f"user/{a['to']}/inbox",
        scope_fn=lambda a: [f"to:{a['to']}"],
    )
    print(result)
