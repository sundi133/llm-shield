"""LLM Shield + LangChain Deep Agent Integration (two-plane architecture).

Demonstrates a healthcare AI agent following the two-plane deployment model:

  PLANE 1 — LLM + GUARDRAILS  →  LiteLLM proxy
      The Deep Agent's model points at the LiteLLM proxy whose config.yaml has
      the votal.ai guardrails callback configured. Input (PII, toxicity,
      adversarial) and output guardrails run *inside* the proxy on every turn —
      this app never calls /guardrails/input or /guardrails/output directly.

  PLANE 2 — AGENTS + RBAC  →  LLM Shield
      Tools, roles and agents are loaded dynamically from the tenant's
      Redis-backed Shield config, and every tool call is gated by Shield:
        - /v1/shield/tool/check   RBAC (tool_allowlist intersection)
        - /v1/shield/tool/output  output sanitization / redaction
      Different agent/role combos get different permissions at runtime.

Usage:
    # Plane 1 — LiteLLM proxy (guardrails configured in its config.yaml)
    export LITELLM_URL="http://localhost:4000"
    export LITELLM_API_KEY="sk-litellm-..."
    export LLM_MODEL="gpt-4o-mini"

    # Plane 2 — LLM Shield
    export SHIELD_URL="https://your-shield.up.railway.app"
    export SHIELD_API_KEY="tenant-...-key-..."

    python examples/deep_agent_shield.py
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Optional

import httpx


# Plane 1: LiteLLM proxy (guardrails run inside it via the votal.ai callback)
LITELLM_URL = os.environ.get("LITELLM_URL", "http://localhost:4000").rstrip("/")
LITELLM_API_KEY = os.environ.get("LITELLM_API_KEY", os.environ.get("OPENAI_API_KEY", "sk-noop"))
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")


def _make_llm():
    """Build the LangChain model for the Deep Agent, pointed at the LiteLLM
    proxy (Plane 1) so input/output guardrails run in the proxy."""
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=LLM_MODEL,
        base_url=f"{LITELLM_URL}/v1",   # ← LiteLLM proxy, guardrails live here
        api_key=LITELLM_API_KEY,
        temperature=0.1,
    )


# ============================================================================
# Shield Client — talks to the Shield REST API
# ============================================================================


@dataclass
class ShieldClient:
    """Client for the LLM Shield REST API.

    Loads tools, roles, agents, and policies dynamically from the tenant's
    Redis-backed config via the Shield API.
    """

    base_url: str
    api_key: str
    _tools: list[dict] = field(default_factory=list, repr=False)
    _policy: dict = field(default_factory=dict, repr=False)
    _agents: dict = field(default_factory=dict, repr=False)

    def _headers(self, agent_key: str = "", user_role: str = "") -> dict:
        h = {"Content-Type": "application/json", "X-API-Key": self.api_key}
        if agent_key:
            h["X-Agent-Key"] = agent_key
        if user_role:
            h["X-User-Role"] = user_role
        return h

    # --- Bootstrap: load everything from Shield ---

    async def load(self):
        """Load tools, policies, and agents from the tenant's Shield config."""
        async with httpx.AsyncClient(timeout=30) as c:
            tools_resp, policy_resp, agents_resp = await asyncio.gather(
                c.get(f"{self.base_url}/v1/tenant/me/tools",
                      headers=self._headers()),
                c.get(f"{self.base_url}/v1/tenant/me/policies",
                      headers=self._headers()),
                c.get(f"{self.base_url}/v1/tenant/me/agents",
                      headers=self._headers()),
            )

        if tools_resp.status_code == 200:
            data = tools_resp.json()
            self._tools = data.get("tools", [])

        if policy_resp.status_code == 200:
            self._policy = policy_resp.json()

        if agents_resp.status_code == 200:
            self._agents = agents_resp.json()

        print(f"[shield] Loaded {len(self._tools)} tool definitions")
        print(f"[shield] Roles: {list(self.per_role.keys())}")
        print(f"[shield] Agents: {list(self.per_agent.keys())}")

    # --- Accessors ---

    @property
    def tools(self) -> list[dict]:
        return self._tools

    @property
    def tool_names(self) -> list[str]:
        return [t["function"]["name"] for t in self._tools if "function" in t]

    @property
    def per_role(self) -> dict:
        ta = self._policy.get("input_guardrails", {}).get("tool_allowlist", {})
        return ta.get("settings", {}).get("per_role", {})

    @property
    def per_agent(self) -> dict:
        ta = self._policy.get("input_guardrails", {}).get("tool_allowlist", {})
        return ta.get("settings", {}).get("per_agent", {})

    @property
    def roles(self) -> list[str]:
        return list(self.per_role.keys())

    @property
    def agent_keys(self) -> list[str]:
        return list(self.per_agent.keys())

    def tools_for(self, agent_key: str, user_role: str) -> list[str]:
        """Compute allowed tools using the intersection model."""
        agent_tools = set(self.per_agent.get(agent_key, []))
        role_tools = set(self.per_role.get(user_role, []))

        if "*" in agent_tools:
            agent_tools = set(self.tool_names)
        if "*" in role_tools:
            role_tools = set(self.tool_names)

        return sorted(agent_tools & role_tools)

    def tools_blocked_for(self, agent_key: str, user_role: str) -> list[str]:
        all_tools = set(self.tool_names)
        allowed = set(self.tools_for(agent_key, user_role))
        return sorted(all_tools - allowed)

    # --- Runtime checks ---

    async def check_tool(self, tool_name: str, agent_key: str,
                         user_role: str) -> dict:
        """Call /v1/shield/tool/check — full RBAC + rate limit + validation."""
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(
                f"{self.base_url}/v1/shield/tool/check",
                json={
                    "agent_key": agent_key,
                    "tool_name": tool_name,
                    "user_role": user_role,
                    "session_id": f"deep-agent-{agent_key}",
                },
                headers=self._headers(agent_key, user_role),
            )
            return resp.json()

    async def sanitize_output(self, tool_name: str, output: str,
                              agent_key: str, user_role: str) -> dict:
        """Call /v1/shield/tool/output — sanitize/redact a tool's output against
        the tenant's data policies before the LLM sees it."""
        async with httpx.AsyncClient(timeout=15) as c:
            resp = await c.post(
                f"{self.base_url}/v1/shield/tool/output",
                json={
                    "tool_name": tool_name,
                    "tool_output": str(output),
                    "agent_key": agent_key,
                    "session_id": f"deep-agent-{agent_key}",
                },
                headers=self._headers(agent_key, user_role),
            )
            return resp.json()


# ============================================================================
# Tool Registration — push tool schemas to the tenant's Shield config
# ============================================================================


HEALTHCARE_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "patient_lookup",
            "description": "Look up patient records by ID — demographics, history, allergies, medications",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string", "description": "Patient ID, e.g. P-12345"},
                    "query": {"type": "string", "description": "What to look up: demographics, history, allergies, medications, lab_results"},
                },
                "required": ["patient_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_vitals",
            "description": "Record or update a patient's vital signs",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "blood_pressure": {"type": "string", "description": "e.g. 120/80"},
                    "heart_rate": {"type": "integer"},
                    "temperature": {"type": "number", "description": "°F"},
                },
                "required": ["patient_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "prescribe_medication",
            "description": "Create a new prescription for a patient",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "medication": {"type": "string", "description": "Drug name and strength"},
                    "dosage": {"type": "string", "description": "Dosage instructions"},
                    "duration": {"type": "string"},
                },
                "required": ["patient_id", "medication", "dosage"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "diagnosis_update",
            "description": "Update or add a diagnosis to a patient's medical record",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "diagnosis": {"type": "string", "description": "ICD-10 code or description"},
                    "status": {"type": "string", "enum": ["active", "resolved", "chronic"]},
                },
                "required": ["patient_id", "diagnosis"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "surgery_scheduling",
            "description": "Schedule a surgical procedure for a patient",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "procedure": {"type": "string"},
                    "date": {"type": "string", "description": "YYYY-MM-DD"},
                },
                "required": ["patient_id", "procedure"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_patient_record",
            "description": "Permanently delete a patient record (administrative only)",
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_id": {"type": "string"},
                    "reason": {"type": "string", "description": "Justification for audit trail"},
                    "confirm": {"type": "boolean"},
                },
                "required": ["patient_id", "reason", "confirm"],
            },
        },
    },
]


async def register_tools(shield: ShieldClient):
    """Push tool definitions to the tenant's Redis config via the Shield API."""
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.put(
            f"{shield.base_url}/v1/tenant/me/tools",
            json={"tools": HEALTHCARE_TOOL_DEFINITIONS},
            headers=shield._headers(),
        )
        data = resp.json()
        print(f"[shield] Registered {data.get('tool_count', 0)} tool definitions: {data.get('tool_names', [])}")


# ============================================================================
# Deep Agent Builder — creates a LangChain Deep Agent with Shield enforcement
# ============================================================================


def build_shield_tools(shield: ShieldClient, agent_key: str, user_role: str):
    """Build LangChain-compatible tools that enforce Shield RBAC on every call.

    Each tool wraps a simulated healthcare function with:
      1. Pre-execution RBAC check via Shield /v1/shield/tool/check
      2. The actual tool logic (simulated here)
      3. Post-execution output sanitization via Shield /v1/shield/tool/output
    """
    from langchain_core.tools import StructuredTool
    from pydantic import BaseModel, Field, create_model
    from typing import Any

    built_tools = []

    for tool_def in shield.tools:
        func = tool_def.get("function", {})
        name = func.get("name", "")
        desc = func.get("description", "")
        params = func.get("parameters", {})
        properties = params.get("properties", {})
        required_fields = params.get("required", [])

        field_defs: dict[str, Any] = {}
        for pname, pschema in properties.items():
            ptype = pschema.get("type", "string")
            py_type = {"string": str, "integer": int, "number": float, "boolean": bool}.get(ptype, str)
            pdesc = pschema.get("description", "")

            if pname in required_fields:
                field_defs[pname] = (py_type, Field(description=pdesc))
            else:
                field_defs[pname] = (Optional[py_type], Field(default=None, description=pdesc))

        input_model = create_model(f"{name}_input", **field_defs)

        captured_name = name
        captured_agent = agent_key
        captured_role = user_role

        async def _invoke(_tool_name=captured_name, _agent=captured_agent,
                          _role=captured_role, **kwargs) -> str:
            rbac = await shield.check_tool(_tool_name, _agent, _role)
            allowed = rbac.get("allowed", False)
            results = rbac.get("guardrail_results", [])
            rbac_msg = results[0].get("message", "") if results else ""

            if not allowed:
                return json.dumps({
                    "status": "BLOCKED",
                    "tool": _tool_name,
                    "reason": rbac_msg,
                    "agent": _agent,
                    "role": _role,
                })

            # Execute (simulated), then sanitize output against data policies.
            raw_result = f"[simulated] {_tool_name} executed with {kwargs}"
            san = await shield.sanitize_output(_tool_name, raw_result, _agent, _role)
            if san.get("action") == "block":
                return json.dumps({
                    "status": "OUTPUT_BLOCKED",
                    "tool": _tool_name,
                    "reason": "output blocked by data policy",
                })

            return json.dumps({
                "status": "OK",
                "tool": _tool_name,
                "result": san.get("sanitized_output", raw_result),
                "rbac": rbac_msg,
            })

        tool = StructuredTool.from_function(
            coroutine=_invoke,
            name=name,
            description=desc,
            args_schema=input_model,
        )
        built_tools.append(tool)

    return built_tools


async def create_healthcare_agent(shield: ShieldClient, agent_key: str,
                                  user_role: str):
    """Create a LangChain Deep Agent with Shield-enforced tools.

    Everything is loaded dynamically from the tenant's Redis config:
      - Tool definitions from tool_definitions:{tenant_id}
      - RBAC rules from input_guardrails.tool_allowlist
      - Agent registry from agents:{tenant_id}
    """
    from langchain_deepagents import create_deep_agent

    tools = build_shield_tools(shield, agent_key, user_role)
    allowed = shield.tools_for(agent_key, user_role)
    blocked = shield.tools_blocked_for(agent_key, user_role)

    print(f"\n{'='*60}")
    print(f"Agent: {agent_key}  |  Role: {user_role}")
    print(f"Tools allowed (intersection): {allowed}")
    print(f"Tools blocked: {blocked}")
    print(f"{'='*60}\n")

    # Model points at the LiteLLM proxy (Plane 1) so guardrails run in the proxy.
    agent = create_deep_agent(
        model=_make_llm(),
        tools=tools,
        interrupt_on={"delete_patient_record": True},
        memory=[],
    )
    return agent


# ============================================================================
# Demo: run scenarios showing RBAC enforcement
# ============================================================================


async def demo_check_permissions(shield: ShieldClient):
    """Show the permission matrix for all agent/role combos."""
    print("\n" + "=" * 70)
    print("RBAC PERMISSION MATRIX (loaded from tenant Redis config)")
    print("=" * 70)

    for agent_key in shield.agent_keys:
        for role in shield.roles:
            allowed = shield.tools_for(agent_key, role)
            blocked = shield.tools_blocked_for(agent_key, role)
            print(f"\n  {agent_key} / {role}:")
            print(f"    ✅ {', '.join(allowed) if allowed else '(none)'}")
            if blocked:
                print(f"    🚫 {', '.join(blocked)}")


async def demo_agent_chat(shield: ShieldClient):
    """Drive a Deep Agent (LLM via the LiteLLM proxy) with Shield-gated tools.

    The LLM reasoning + input/output guardrails go through the LiteLLM proxy
    (Plane 1); each tool the agent calls is gated by Shield RBAC + data policy
    (Plane 2). The simulated tools return JSON with status OK / BLOCKED.
    """
    try:
        from langchain_deepagents import create_deep_agent  # noqa: F401
        from langchain_openai import ChatOpenAI  # noqa: F401
    except ImportError:
        print("\n[skip] Install langchain-deepagents + langchain-openai to run "
              "the Deep Agent chat demo\n")
        return

    scenarios = [
        {
            "agent_key": "healthcare-doctor-senior",
            "user_role": "nurse",
            "message": "Update the diagnosis for patient P-12345 to Type 2 Diabetes",
            "expect": "BLOCKED — nurse cannot use diagnosis_update",
        },
        {
            "agent_key": "healthcare-doctor-senior",
            "user_role": "nurse",
            "message": "Look up the medical history for patient P-12345",
            "expect": "ALLOWED — nurse can use patient_lookup",
        },
        {
            "agent_key": "healthcare-doctor-senior",
            "user_role": "doctor",
            "message": "Prescribe Lisinopril 10mg daily for patient P-12345",
            "expect": "ALLOWED — doctor can use prescribe_medication",
        },
    ]

    for i, s in enumerate(scenarios):
        print(f"\n{'─'*60}")
        print(f"Scenario {i+1}: {s['expect']}")
        print(f"  Agent: {s['agent_key']}  Role: {s['user_role']}")
        print(f"  Message: {s['message']}")
        print(f"{'─'*60}")

        try:
            agent = await create_healthcare_agent(
                shield, s["agent_key"], s["user_role"]
            )
            # LLM call routes through the LiteLLM proxy (guardrails apply there).
            state = await agent.ainvoke(
                {"messages": [{"role": "user", "content": s["message"]}]}
            )
        except Exception as e:  # noqa: BLE001 — surface proxy-side guardrail blocks
            msg = str(e)
            if any(k in msg.lower() for k in ("guardrail", "blocked", "403", "policy")):
                print(f"  ❌ Input blocked by LiteLLM proxy guardrails")
            else:
                print(f"  [error] {msg}")
            continue

        # Print the agent's final message + any tool results (OK/BLOCKED JSON).
        for m in state.get("messages", []):
            content = getattr(m, "content", "") if not isinstance(m, dict) else m.get("content", "")
            if not content:
                continue
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict) and "status" in parsed:
                    ok = parsed["status"] == "OK"
                    icon = "✅" if ok else "🚫"
                    print(f"  {icon} {parsed.get('tool')}: {parsed.get('result') or parsed.get('reason')}")
                    continue
            except (ValueError, TypeError):
                pass
        final = state.get("messages", [])
        if final:
            last = final[-1]
            text = getattr(last, "content", "") if not isinstance(last, dict) else last.get("content", "")
            if text:
                print(f"  LLM: {str(text)[:120]}")


async def demo_tool_checks(shield: ShieldClient):
    """Direct tool permission checks — no LLM involved."""
    print("\n" + "=" * 70)
    print("DIRECT TOOL PERMISSION CHECKS")
    print("=" * 70)

    checks = [
        ("healthcare-nurse-head", "nurse", "prescribe_medication"),
        ("healthcare-nurse-head", "nurse", "patient_lookup"),
        ("healthcare-doctor-senior", "nurse", "diagnosis_update"),
        ("healthcare-doctor-senior", "doctor", "diagnosis_update"),
        ("healthcare-ai-assistant", "admin", "delete_patient_record"),
    ]

    for agent_key, role, tool in checks:
        result = await shield.check_tool(tool, agent_key, role)
        ok = result.get("allowed", False)
        icon = "✅" if ok else "🚫"
        msg = ""
        for gr in result.get("guardrail_results", []):
            if gr.get("guardrail") == "tool_allowlist":
                msg = gr.get("message", "")
        print(f"  {icon} {agent_key}/{role} → {tool}")
        print(f"     {msg}")


# ============================================================================
# Main
# ============================================================================


async def main():
    shield_url = os.environ.get("SHIELD_URL", "https://llm-shield-production.up.railway.app")
    shield_api_key = os.environ.get("SHIELD_API_KEY", "")

    if not shield_api_key:
        print("Set SHIELD_API_KEY to your tenant API key")
        return

    shield = ShieldClient(base_url=shield_url, api_key=shield_api_key)
    print(f"[Plane 1] LLM + guardrails via LiteLLM proxy at {LITELLM_URL} (model={LLM_MODEL})")
    print(f"[Plane 2] Agents + RBAC via LLM Shield at {shield_url}")

    # Step 1: Register tool definitions (push schemas to Redis)
    print("\n[1] Registering tool definitions with tenant...")
    await register_tools(shield)

    # Step 2: Load everything from the tenant's Redis config
    print("\n[2] Loading tools, roles, and agents from Shield...")
    await shield.load()

    # Step 3: Show the RBAC permission matrix
    await demo_check_permissions(shield)

    # Step 4: Run direct tool permission checks
    await demo_tool_checks(shield)

    # Step 5: Run Deep Agent scenarios (LLM via LiteLLM proxy, tools via Shield)
    await demo_agent_chat(shield)

    # Step 6: (Optional) Create a Deep Agent
    try:
        from langchain_deepagents import create_deep_agent  # noqa: F401
        print("\n[6] Creating Deep Agent with Shield-enforced tools...")
        agent = await create_healthcare_agent(
            shield, "healthcare-doctor-senior", "nurse"
        )
        print(f"  Agent created with {len(agent.tools)} tools")
        print("  Each tool call will be gated by Shield RBAC at runtime")
    except ImportError:
        print("\n[6] langchain-deepagents not installed — skipping Deep Agent creation")
        print("    pip install langchain-deepagents to enable")
        print("    The ShieldClient + tool checks work independently of LangChain")


if __name__ == "__main__":
    asyncio.run(main())
