#!/usr/bin/env python3
"""CrewAI + LLM Shield Integration

Demonstrates a multi-agent CrewAI crew protected by LLM Shield:
  - Each crew member registers as a separate Shield agent with its own RBAC
  - Input guardrails run before the crew starts
  - Each tool call routes through Shield for RBAC enforcement
  - Output guardrails run on the final crew output
  - Shadow discovery detects unregistered agents and tools

Usage:
    export LLM_SHIELD_URL="http://localhost:8080"
    export API_KEY="tenant-...-key-..."
    export OPENAI_API_KEY="sk-..."
    export USER_ROLE="analyst"            # optional

    pip install -r requirements.txt
    python shield_crewai_agent.py
"""

import json
import os
import sys
from typing import Type

import requests
from crewai import Agent, Crew, Process, Task
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SHIELD_URL = os.getenv("LLM_SHIELD_URL", "http://localhost:8080")
API_KEY = os.getenv("API_KEY", "")
USER_ROLE = os.getenv("USER_ROLE", "analyst")

shield = requests.Session()
shield.headers.update({
    "X-API-Key": API_KEY,
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
        resp = shield.post(
            f"{SHIELD_URL}/v1/agents/registry", json=agent_cfg
        )
        print(f"[register] {agent_cfg['agent_id']}: {resp.status_code}")


# ---------------------------------------------------------------------------
# 2. Shield-aware tool base class
# ---------------------------------------------------------------------------

class ShieldTool(BaseTool):
    """CrewAI tool that routes execution through Shield for RBAC."""

    agent_key: str = ""
    user_role: str = ""

    def _run(self, query: str) -> str:
        """Override to call Shield's chat/agent endpoint for RBAC."""
        result = shield.post(
            f"{SHIELD_URL}/v1/shield/chat/agent",
            json={
                "messages": [{"role": "user", "content": query}],
                "agent_key": self.agent_key,
                "user_role": self.user_role,
                "llm_api_key": os.getenv("OPENAI_API_KEY"),
            },
        )
        if result.status_code != 200:
            return f"Shield error: {result.status_code} — {result.text}"

        data = result.json()
        parts = []

        for tc in data.get("tool_calls", []):
            if tc["rbac"]["allowed"]:
                parts.append(f"[{tc['tool_name']}] OK — {tc.get('simulated_output', '')}")
            else:
                parts.append(
                    f"BLOCKED: {tc['tool_name']} — {tc['rbac']['message']}"
                )

        # Surface shadow discovery warnings
        unreg = data.get("unregistered", {})
        if unreg.get("agents"):
            parts.append(f"[Shadow agent(s): {unreg['agents']}]")
        if unreg.get("tools"):
            parts.append(f"[Shadow tool(s): {unreg['tools']}]")

        return data.get("text", "") or "\n".join(parts)


# ---------------------------------------------------------------------------
# 3. Concrete tools
# ---------------------------------------------------------------------------

class SearchInput(BaseModel):
    query: str = Field(description="What to search for")


class WebSearchTool(ShieldTool):
    name: str = "web_search"
    description: str = "Search the web for current information"
    args_schema: Type[BaseModel] = SearchInput
    agent_key: str = "research-agent"


class DocumentSearchTool(ShieldTool):
    name: str = "document_search"
    description: str = "Search internal documents for information"
    args_schema: Type[BaseModel] = SearchInput
    agent_key: str = "research-agent"


class ReportInput(BaseModel):
    query: str = Field(description="Report topic and content")


class GenerateReportTool(ShieldTool):
    name: str = "generate_report"
    description: str = "Generate a formatted report from data"
    args_schema: Type[BaseModel] = ReportInput
    agent_key: str = "writer-agent"


class EmailInput(BaseModel):
    query: str = Field(description="Email subject and recipients")


class SendEmailTool(ShieldTool):
    name: str = "send_email"
    description: str = "Send an email with the report attached"
    args_schema: Type[BaseModel] = EmailInput
    agent_key: str = "writer-agent"


# ---------------------------------------------------------------------------
# 4. Guardrail helpers
# ---------------------------------------------------------------------------

def check_input(text: str) -> str | None:
    """Run input guardrails. Returns error message if blocked, else None."""
    resp = shield.post(
        f"{SHIELD_URL}/guardrails/input", json={"message": text}
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("action") == "block":
        blocked = [
            g["guardrail"]
            for g in data.get("guardrail_results", [])
            if g.get("action") == "block"
        ]
        return f"Input blocked: {', '.join(blocked)}"
    return None


def check_output(text: str) -> str | None:
    """Run output guardrails. Returns error message if blocked, else None."""
    resp = shield.post(
        f"{SHIELD_URL}/guardrails/output", json={"output": text}
    )
    if resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("action") == "block":
        blocked = [
            g["guardrail"]
            for g in data.get("guardrail_results", [])
            if g.get("action") == "block"
        ]
        return f"Output blocked: {', '.join(blocked)}"
    return None


# ---------------------------------------------------------------------------
# 5. Build and run the crew
# ---------------------------------------------------------------------------

def run_crew(topic: str) -> str:
    """Run a two-agent crew with Shield protection.

    Flow:
        1. Input guardrails on the topic
        2. Researcher agent searches (RBAC via Shield)
        3. Writer agent produces report (RBAC via Shield)
        4. Output guardrails on the final result
    """
    print(f"\n{'='*60}")
    print(f"Crew topic: {topic}")
    print(f"{'='*60}")

    # Step 1: input guardrails
    block = check_input(topic)
    if block:
        print(f"[BLOCKED] {block}")
        return block

    # Step 2: build crew
    researcher = Agent(
        role="Research Analyst",
        goal=f"Research: {topic}",
        backstory="Senior analyst with deep domain expertise",
        tools=[
            WebSearchTool(user_role=USER_ROLE),
            DocumentSearchTool(user_role=USER_ROLE),
        ],
        verbose=True,
    )
    writer = Agent(
        role="Report Writer",
        goal="Write a clear, actionable report from the research",
        backstory="Technical writer specializing in data-driven reports",
        tools=[
            GenerateReportTool(user_role=USER_ROLE),
            SendEmailTool(user_role=USER_ROLE),
        ],
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

    # Step 3: execute
    result = str(crew.kickoff())

    # Step 4: output guardrails
    block = check_output(result)
    if block:
        print(f"[BLOCKED] {block}")
        return block

    print(f"\nFinal output:\n{result}")
    return result


# ---------------------------------------------------------------------------
# 6. Shadow discovery check
# ---------------------------------------------------------------------------

def check_shadow_items():
    """Fetch unregistered agents/tools that Shield has detected."""
    resp = shield.get(f"{SHIELD_URL}/v1/agents/unregistered")
    if resp.status_code == 200:
        data = resp.json()
        if data.get("agents"):
            print("\nShadow Agents:")
            print(json.dumps(data["agents"], indent=2))
        if data.get("tools"):
            print("\nShadow Tools:")
            print(json.dumps(data["tools"], indent=2))
        if not data.get("agents") and not data.get("tools"):
            print("\nNo shadow agents or tools detected.")
    else:
        print(f"Could not fetch shadow items: {resp.status_code}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not os.getenv("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set")
        sys.exit(1)
    if not API_KEY:
        print("WARNING: API_KEY not set — requests may be rejected")

    # Uncomment to register the crew (skip to test shadow discovery):
    # register_crew()

    run_crew("Analyze Q1 2026 market trends in AI infrastructure")

    print("\n" + "=" * 60)
    print("Shadow Discovery Report")
    print("=" * 60)
    check_shadow_items()
