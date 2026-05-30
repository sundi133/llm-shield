#!/usr/bin/env python3
"""CrewAI + LLM Shield Integration (production deployment architecture).

Two planes, matching the deployment architecture:

  PLANE 1 — LLM + GUARDRAILS  →  LiteLLM proxy
      Every crew agent's LLM points at the LiteLLM proxy whose config.yaml has
      the votal.ai guardrails callback configured. Input (PreCall) and output
      (PostCall) guardrails run *inside* the proxy — the app never calls
      /guardrails/input or /guardrails/output directly. (CrewAI already uses
      LiteLLM under the hood, so this is just a base_url.)

  PLANE 2 — AGENTS + RBAC  →  LLM Shield
      Each crew member registers as its own Shield agent. Tool calls are gated
      by the Shield endpoints (NOT LiteLLM):
        /v1/agents/registry     register each agent + role_permissions
        /v1/shield/tool/check    pre-exec: RBAC + input data policy
        /v1/shield/tool/output   post-exec: output sanitization/redaction
        /v1/agents/unregistered  shadow discovery

Flow:

    Crew kicks off ─▶ agents reason via LiteLLM proxy (─▶ guardrails)
                       └─ tool call ─▶ Shield /v1/shield/tool/check (RBAC + policy)
                                        ├─ allowed ▶ run ▶ /tool/output (sanitize)
                                        └─ blocked ▶ deny, reason returned to agent

Usage:
    # Plane 1 — LiteLLM proxy (guardrails configured in its config.yaml)
    export LITELLM_URL="https://litellm.your-company.com"
    export LITELLM_API_KEY="sk-litellm-..."     # LiteLLM virtual key
    export LLM_MODEL="gpt-4o-mini"             # model alias in litellm config

    # Plane 2 — LLM Shield (agents + RBAC)
    export LLM_SHIELD_URL="https://shield.votal.ai"
    export API_KEY="tenant-...-key-..."
    export USER_ROLE="analyst"                 # analyst / viewer

    pip install -r requirements.txt
    python shield_crewai_agent.py
"""

import json
import os
import time
from typing import Type

import requests
from crewai import Agent, Crew, LLM, Process, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Config — TWO separate planes
# ---------------------------------------------------------------------------

# Plane 1: LiteLLM proxy (guardrails run inside it via the votal.ai callback)
LITELLM_URL = os.getenv("LITELLM_URL", "https://litellm.your-company.com").rstrip("/")
LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", os.getenv("OPENAI_API_KEY", "sk-noop"))
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

# Plane 2: LLM Shield (agents + RBAC + data policy)
SHIELD_URL = os.getenv("LLM_SHIELD_URL", "https://shield.votal.ai").rstrip("/")
API_KEY = os.getenv("API_KEY", "")
USER_ROLE = os.getenv("USER_ROLE", "analyst")
SESSION_ID = f"sess-{int(time.time())}"

# CrewAI LLM → LiteLLM proxy (so guardrails run in the proxy)
crew_llm = LLM(
    model=f"openai/{LLM_MODEL}",
    base_url=f"{LITELLM_URL}/v1",
    api_key=LITELLM_API_KEY,
)

# Shield session — tenant key on every Shield request
shield = requests.Session()
shield.headers.update({
    "X-API-Key": API_KEY,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
})


# ---------------------------------------------------------------------------
# 1. Register crew agents (run once — skip to test shadow discovery)
# ---------------------------------------------------------------------------

def register_crew():
    """Register each crew member as a separate Shield agent."""
    agents = [
        {
            "agent_id": "research-agent",
            "name": "Research Analyst",
            "description": "Searches public data sources for information",
            "tools": ["web_search", "document_search"],
            "role_permissions": {
                "analyst": ["web_search", "document_search"],
                "viewer": ["web_search"],
            },
        },
        {
            "agent_id": "writer-agent",
            "name": "Report Writer",
            "description": "Writes formatted reports from research data",
            "tools": ["generate_report", "send_email"],
            "role_permissions": {
                "analyst": ["generate_report", "send_email"],
                "viewer": ["generate_report"],
            },
        },
    ]
    for agent_cfg in agents:
        resp = shield.post(f"{SHIELD_URL}/v1/agents/registry", json=agent_cfg)
        print(f"[register] {agent_cfg['agent_id']}: {resp.status_code}")


# ---------------------------------------------------------------------------
# 2. Shield tool gate — RBAC + data policy around every tool execution
# ---------------------------------------------------------------------------

class ToolBlocked(Exception):
    """Raised when Shield denies a tool call; message is returned to the agent."""


def _shield_tool_check(agent_key: str, tool_name: str, args: dict) -> None:
    """Pre-execution gate: RBAC + input data-policy via Shield /tool/check."""
    resp = shield.post(
        f"{SHIELD_URL}/v1/shield/tool/check",
        json={
            "agent_key": agent_key,
            "tool_name": tool_name,
            "user_role": USER_ROLE,
            "session_id": SESSION_ID,
            "tool_params": args,
        },
    )
    if resp.status_code != 200:
        raise ToolBlocked(f"tool/check failed ({resp.status_code}): {resp.text}")
    data = resp.json()
    if not (data.get("allowed", True) and data.get("action") != "block"):
        reason = "denied by policy"
        for r in data.get("guardrail_results", []):
            if not r.get("passed", True):
                reason = r.get("message", reason)
                break
        raise ToolBlocked(f"{tool_name} blocked for role '{USER_ROLE}' — {reason}")


def _shield_tool_output(agent_key: str, tool_name: str, raw_output: str) -> str:
    """Post-execution gate: sanitize/redact tool output via Shield /tool/output."""
    resp = shield.post(
        f"{SHIELD_URL}/v1/shield/tool/output",
        json={
            "tool_name": tool_name,
            "tool_output": str(raw_output),
            "agent_key": agent_key,
            "session_id": SESSION_ID,
        },
    )
    if resp.status_code != 200:
        raise ToolBlocked(f"{tool_name} output withheld (sanitizer error)")
    data = resp.json()
    if data.get("action") == "block":
        raise ToolBlocked(f"{tool_name} output blocked by data policy")
    return data.get("sanitized_output", str(raw_output))


# ---------------------------------------------------------------------------
# 3. Shield-aware CrewAI tool base class
# ---------------------------------------------------------------------------

class ShieldTool(BaseTool):
    """CrewAI tool that gates every call through Shield (RBAC + data policy).

    Subclasses set `agent_key` and implement `execute()`.
    """

    agent_key: str = ""

    def execute(self, query: str) -> str:  # override in subclasses
        raise NotImplementedError

    def _run(self, query: str) -> str:
        try:
            _shield_tool_check(self.agent_key, self.name, {"query": query})
            raw = self.execute(query)
            out = _shield_tool_output(self.agent_key, self.name, raw)
            print(f"  [ALLOWED] {self.name}('{query}') -> {out}")
            return out
        except ToolBlocked as e:
            print(f"  [Shield] BLOCKED {self.name}: {e}")
            return f"BLOCKED by LLM Shield: {e}"


# ---------------------------------------------------------------------------
# 4. Concrete tools
# ---------------------------------------------------------------------------

class SearchInput(BaseModel):
    query: str = Field(description="What to search for")


class WebSearchTool(ShieldTool):
    name: str = "web_search"
    description: str = "Search the web for current information"
    args_schema: Type[BaseModel] = SearchInput
    agent_key: str = "research-agent"

    def execute(self, query: str) -> str:
        return f"Web results for '{query}': 3 sources found (example.com, news.org, ...)."


class DocumentSearchTool(ShieldTool):
    name: str = "document_search"
    description: str = "Search internal documents for information"
    args_schema: Type[BaseModel] = SearchInput
    agent_key: str = "research-agent"

    def execute(self, query: str) -> str:
        return f"Internal docs for '{query}': see Q1 strategy memo, section 4."


class ReportInput(BaseModel):
    query: str = Field(description="Report topic and content")


class GenerateReportTool(ShieldTool):
    name: str = "generate_report"
    description: str = "Generate a formatted report from data"
    args_schema: Type[BaseModel] = ReportInput
    agent_key: str = "writer-agent"

    def execute(self, query: str) -> str:
        return f"Report draft generated for '{query}' (1,200 words, 3 sections)."


class EmailInput(BaseModel):
    query: str = Field(description="Email subject and recipients")


class SendEmailTool(ShieldTool):
    name: str = "send_email"
    description: str = "Send an email with the report attached"
    args_schema: Type[BaseModel] = EmailInput
    agent_key: str = "writer-agent"

    def execute(self, query: str) -> str:
        return f"Email sent: '{query}'."


# ---------------------------------------------------------------------------
# 5. Build and run the crew
# ---------------------------------------------------------------------------

def run_crew(topic: str) -> str:
    """Run a two-agent crew. LLM reasoning (with guardrails) goes through the
    LiteLLM proxy; tool calls are gated by Shield per crew member."""
    print(f"\n{'=' * 60}")
    print(f"Crew topic: {topic}")
    print(f"{'=' * 60}")

    researcher = Agent(
        role="Research Analyst",
        goal=f"Research: {topic}",
        backstory="Senior analyst with deep domain expertise",
        tools=[WebSearchTool(), DocumentSearchTool()],
        llm=crew_llm,
        verbose=True,
    )
    writer = Agent(
        role="Report Writer",
        goal="Write a clear, actionable report from the research",
        backstory="Technical writer specializing in data-driven reports",
        tools=[GenerateReportTool(), SendEmailTool()],
        llm=crew_llm,
        verbose=True,
    )

    research_task = Task(
        description=f"Research {topic} thoroughly using available search tools",
        expected_output="Key findings with sources",
        agent=researcher,
    )
    report_task = Task(
        description="Synthesize the research into a professional report",
        expected_output="Formatted report with recommendations",
        agent=writer,
    )

    crew = Crew(
        agents=[researcher, writer],
        tasks=[research_task, report_task],
        process=Process.sequential,
        verbose=True,
    )

    try:
        result = str(crew.kickoff())
    except Exception as e:  # noqa: BLE001 — surface proxy-side guardrail blocks
        msg = str(e)
        if any(k in msg.lower() for k in ("guardrail", "blocked", "403", "policy")):
            print(f"[BLOCKED by LiteLLM proxy guardrails] {msg}")
            return "[Request blocked by guardrails in the LiteLLM proxy]"
        print(f"[Crew error] {msg}")
        return f"Error: {msg}"

    print(f"\nFinal output:\n{result}")
    return result


# ---------------------------------------------------------------------------
# 6. Shadow discovery — Shield endpoint
# ---------------------------------------------------------------------------

def check_shadow_items():
    """Fetch unregistered agents/tools that Shield has detected."""
    resp = shield.get(f"{SHIELD_URL}/v1/agents/unregistered")
    if resp.status_code != 200:
        print(f"Could not fetch shadow items: {resp.status_code}")
        return
    data = resp.json()
    if data.get("agents"):
        print("\nShadow Agents:")
        print(json.dumps(data["agents"], indent=2))
    if data.get("tools"):
        print("\nShadow Tools:")
        print(json.dumps(data["tools"], indent=2))
    if not data.get("agents") and not data.get("tools"):
        print("\nNo shadow agents or tools detected.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not API_KEY:
        print("WARNING: API_KEY not set — Shield requests may be rejected")
    print(f"LLM plane  : LiteLLM proxy at {LITELLM_URL} (model={LLM_MODEL})")
    print(f"Agent plane: LLM Shield at {SHIELD_URL} (role={USER_ROLE})")

    # Uncomment on first run to register the crew (skip to test shadow discovery):
    # register_crew()

    run_crew("Analyze Q1 2026 market trends in AI infrastructure")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
