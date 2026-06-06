#!/usr/bin/env python3
"""Deep Agents + Shield — the SIMPLE way (one-line wrap).

Compare with examples/deep_agent_shield.py, which hand-builds every tool from
Shield schemas. Here the developer writes PLAIN tools and adds ONE line:

    protected = shield.wrap_tools(my_tools)

deep-agents is otherwise untouched — same create_deep_agent call, same native
`interrupt_on` for human approval. Shield RBAC + output sanitization run inside
each tool (sync AND async paths), so the planner and sub-agents never see it.

Run:
    export SHIELD_URL=https://shield.your-company.com
    export SHIELD_API_KEY=sk-tenant-...
    export LITELLM_URL=https://litellm.your-company.com   # guardrails plane
    export USER_ROLE=nurse
    python examples/langchain/deep_agent_simple.py
"""

from __future__ import annotations

import os
import sys

# Make the SDK importable from the repo (or `pip install ./sdk`)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk"))

from votal import VotalShield  # noqa: E402


def main() -> None:
    shield = VotalShield(
        shield_url=os.environ.get("SHIELD_URL", "http://localhost:8080"),
        api_key=os.environ.get("SHIELD_API_KEY", ""),
        agent_id=os.environ.get("AGENT_ID", "clinical-bot"),
        user_role=os.environ.get("USER_ROLE", "nurse"),
    )

    try:
        from langchain_core.tools import tool
        from langchain_openai import ChatOpenAI
        from deepagents import create_deep_agent
    except Exception as e:  # noqa: BLE001
        print(f"deep-agents/LangChain not installed ({e}).")
        print("pip install deepagents langchain-openai")
        return

    # ── 1. Developer writes PLAIN tools — no Shield code inside ──
    @tool
    def patient_lookup(patient_id: str) -> str:
        """Look up a patient's record by ID."""
        return f"{patient_id}: John Smith, A1C 7.2%, on metformin"

    @tool
    def prescribe(patient_id: str, drug: str, dosage: str) -> str:
        """Prescribe a medication for a patient."""
        return f"prescribed {drug} {dosage} to {patient_id}"

    @tool
    def delete_record(patient_id: str, reason: str) -> str:
        """Permanently delete a patient record (admin only)."""
        return f"deleted {patient_id}"

    my_tools = [patient_lookup, prescribe, delete_record]

    # ── 2. ONE line: RBAC + sanitization on every tool (sync + async) ──
    protected = shield.wrap_tools(my_tools)

    # ── 3. deep-agents unchanged. Native HITL for the sensitive tool, ──
    #       driven by Shield policy.
    llm = ChatOpenAI(
        model=os.environ.get("LLM_MODEL", "gpt-4o-mini"),
        base_url=f"{os.environ.get('LITELLM_URL', 'https://api.openai.com')}/v1",
        api_key=os.environ.get("LITELLM_API_KEY", os.environ.get("OPENAI_API_KEY", "sk-noop")),
        temperature=0,
    )
    agent = create_deep_agent(
        model=llm,
        tools=protected,
        interrupt_on=shield.interrupt_on(my_tools, require_approval=["delete_record"]),
    )

    # nurse role: patient_lookup allowed; prescribe/delete blocked by Shield
    result = agent.invoke({"messages": [
        {"role": "user", "content": "Look up patient P-1234, then prescribe amoxicillin 500mg."}
    ]})
    for m in result["messages"]:
        print(getattr(m, "content", m))


if __name__ == "__main__":
    main()
