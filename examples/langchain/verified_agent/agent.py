#!/usr/bin/env python3
"""LangChain agent with VERIFIED identity (Option C, two-pane).

Flow:
  Phase 0 (startup): exchange tenant key -> signed agent_token  (prove WHO)
  Phase 1 (per call): agent_token -> mint_cap(tool, resource)   (ask permission)
  Phase 2 (execute):  POST cap to the SEPARATE tool server, which verifies it

The agent does NOT hold the SMTP credential. Its only way to send email is to
obtain a cap from Shield and present it to the tool server. If Shield denies
(role/policy), mint_cap raises 403 and there is no cap to present.

Run (after starting tool_server.py):
    export SHIELD_URL=https://shield.your-company.com
    export SHIELD_TENANT_KEY=sk-tenant-...
    export TOOL_SERVER_URL=http://localhost:9100
    export USER_SUB=alice@acme.com
    export USER_ROLE=invoicing
    python agent.py
"""

from __future__ import annotations

import os
import sys
import uuid

import requests

# Reuse the repo's HTTP client (examples/shield_client.py)
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "..")))
from shield_client import ShieldClient, ShieldError, AgentToken  # noqa: E402

SHIELD_URL = os.environ.get("SHIELD_URL", "http://localhost:8080")
TOOL_SERVER_URL = os.environ.get("TOOL_SERVER_URL", "http://localhost:9100").rstrip("/")
USER_SUB = os.environ.get("USER_SUB", "alice@acme.com")
AGENT_ID = os.environ.get("AGENT_ID", "billing-bot")
SESSION_ID = f"sess-{uuid.uuid4().hex[:8]}"

shield = ShieldClient(base_url=SHIELD_URL)   # reads SHIELD_TENANT_KEY from env


# ── Phase 0: verify the agent's identity once, at startup ────────────────
class AgentIdentity:
    """Holds the verified agent token, refreshing before expiry."""

    def __init__(self) -> None:
        self._token: AgentToken | None = None

    def token(self) -> AgentToken:
        if self._token is None:
            # Shield checks the tenant key, then signs an Ed25519 JWT that
            # FREEZES this identity. This is what "verified agent" means.
            self._token = shield.mint_agent_token(
                user_sub=USER_SUB,
                agent_id=AGENT_ID,
                agent_instance_id=f"pod-{uuid.uuid4().hex[:6]}",
                build_hash="sha256:demo-build",
                model_version="langchain-demo",
                session_id=SESSION_ID,
            )
            print(f"[agent] identity verified -> agent_token "
                  f"(expires in {self._token.expires_in}s)")
        return self._token


identity = AgentIdentity()


# ── The tool the LLM may call ────────────────────────────────────────────
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email. Wrapped with Shield mint -> remote verify."""
    # Phase 1: ask Shield to authorize THIS exact action.
    try:
        cap = shield.mint_cap(
            identity.token(),
            tool="send_email",
            resource=to,                 # cap is bound to this recipient only
            scope_constraints=[f"to:{to}"],
            clearance_max="internal",
            ttl_seconds=30,
        )
    except ShieldError as e:
        # 403 = role/policy denied. No cap minted -> cannot proceed.
        return f"DENIED by Shield (no capability granted): {e}"

    # Phase 2: present the cap to the SEPARATE tool server. We do NOT verify
    # it ourselves and we do NOT hold the SMTP credential — the tool server
    # verifies the cap and executes.
    resp = requests.post(
        f"{TOOL_SERVER_URL}/tools/send_email",
        json={"to": to, "subject": subject, "body": body,
              "cap_token": cap.cap_token},
        timeout=10,
    )
    if resp.status_code == 403:
        return f"Tool server rejected the capability: {resp.json().get('detail')}"
    resp.raise_for_status()
    return f"Email sent (verified by tool server): {resp.json()}"


# ── LangChain wiring ─────────────────────────────────────────────────────
def main() -> None:
    try:
        from langchain.tools import tool
        from langchain.agents import AgentExecutor, create_tool_calling_agent
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_openai import ChatOpenAI
    except Exception as e:  # noqa: BLE001
        print(f"LangChain not installed ({e}). Running the tool directly instead:\n")
        print(send_email("bob@acme.com", "Q4 invoice", "Please find attached."))
        return

    send_email_tool = tool(send_email)   # turn the function into a LangChain tool

    llm = ChatOpenAI(
        model=os.environ.get("LLM_MODEL", "gpt-4o-mini"),
        base_url=os.environ.get("LITELLM_URL", "https://api.openai.com/v1"),
        api_key=os.environ.get("OPENAI_API_KEY", "sk-noop"),
        temperature=0,
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a billing assistant. Use tools when needed."),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])
    agent = create_tool_calling_agent(llm, [send_email_tool], prompt)
    executor = AgentExecutor(agent=agent, tools=[send_email_tool], verbose=True)

    executor.invoke({
        "input": "Email bob@acme.com the Q4 invoice with subject 'Q4 Invoice'."
    })


if __name__ == "__main__":
    main()
