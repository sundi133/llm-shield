#!/usr/bin/env python3
"""Agent run tracing demo — one run_id across a multi-turn agent's guard calls.

Simulates an agent doing two turns (each: screen the user message, check a tool,
screen the reply). Every call carries the SAME X-Shield-Run-Id, so all the guard
records — and, if spans are enabled, all the spans — correlate into one run.

    export SHIELD_URL=http://localhost:8000
    python examples/tracing/agent_run_demo.py

To also see the run as a trace tree, run Shield with span tracing pointed at a
collector (e.g. Jaeger all-in-one), then filter by the run.id attribute:
    SHIELD_OTLP_TRACES_ENDPOINT=http://localhost:4318  (on the Shield server)
"""
import os
import sys
import uuid

import requests

BASE = os.environ.get("SHIELD_URL", "http://localhost:8000").rstrip("/")
KEY = os.environ.get("TENANT_KEY", "")
# One run id for the whole agent run. Omit to let Shield generate + echo one.
RUN_ID = os.environ.get("RUN_ID", f"run-demo-{uuid.uuid4().hex[:8]}")

H = {"Content-Type": "application/json", "X-Shield-Run-Id": RUN_ID}
if KEY:
    H["X-API-Key"] = KEY
G, R, Z = "\033[32m", "\033[31m", "\033[0m"


def call(step, method, path, payload):
    url = BASE + path
    r = requests.request(method, url, headers=H, json=payload, timeout=30)
    echoed = r.headers.get("X-Shield-Run-Id", "<none>")
    ok = echoed == RUN_ID
    mark = f"{G}✓{Z}" if ok else f"{R}✗{Z}"
    print(f"  {mark} {step:<22} {method} {path:<28} [{r.status_code}]  run_id={echoed}")
    return r


def main():
    print(f"\nAgent run — X-Shield-Run-Id: {G}{RUN_ID}{Z}")
    print(f"Shield: {BASE}\n")

    print("Turn 1 — user asks to refund an order")
    call("screen prompt", "POST", "/guardrails/input",
         {"message": "Please refund order 8821", "session_id": "sess-1"})
    call("check tool", "POST", "/v1/shield/tool/check",
         {"agent_key": "support-bot", "tool_name": "get_order", "user_role": "support_agent",
          "tool_params": {"order": "8821"}, "session_id": "sess-1"})
    call("screen reply", "POST", "/guardrails/output",
         {"output": "Order 8821 is eligible for a refund.",
          "context": {"session_id": "sess-1"}})

    print("\nTurn 2 — user confirms")
    call("screen prompt", "POST", "/guardrails/input",
         {"message": "Yes, go ahead", "session_id": "sess-1"})
    call("screen reply", "POST", "/guardrails/output",
         {"output": "Refund of $50 has been issued.", "context": {"session_id": "sess-1"}})

    print(f"\n{G}Done.{Z} All 5 guard calls share run_id={RUN_ID}.")
    print("  Reconstruct the run from the audit log by filtering metadata.run_id.")
    print("  If span tracing is on, view the trace tree filtered by run.id in your backend.")


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        sys.exit(f"Cannot reach {BASE} — start Shield first (see the module docstring).")
