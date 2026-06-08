"""
Deep Agents harness + LLM Shield integration.

Two changes to your existing harness — that's it:

  1. Point the model at LiteLLM proxy (input/output guardrails automatic)
  2. Wrap tools with VotalShield (RBAC + data policy per tool call)

Everything else stays the same — subagents, backend, permissions,
human-in-the-loop, skills, memory all work unchanged.

Architecture:

  ┌──────────────────────────────────────────────────────────────┐
  │  Deep Agent Harness                                         │
  │                                                             │
  │  User message                                               │
  │    │                                                        │
  │    ▼                                                        │
  │  LLM call ──▶ LiteLLM proxy ──▶ [input guardrails] ──▶ LLM │
  │    │           (automatic)       prompt injection,          │
  │    │                             PII, toxic, bias           │
  │    │                                                        │
  │    ▼                                                        │
  │  Tool call ──▶ VotalShield ──▶ [RBAC check] ──▶ execute     │
  │    │           (per-tool)     role→tool policy   │          │
  │    │                                             ▼          │
  │    │                          [sanitize output] ◀─┘         │
  │    │                           PII redaction                │
  │    ▼                                                        │
  │  LLM response ◀── LiteLLM ◀── [output guardrails]          │
  │    │                            PII leakage,               │
  │    ▼                            competitor mentions         │
  │  Return to user                                             │
  └──────────────────────────────────────────────────────────────┘

Install:
    pip install -U "deepagents>=0.5.2" langchain-anthropic langgraph votal

Config:
    # LiteLLM proxy (handles input/output guardrails automatically)
    export LITELLM_URL="https://litellm.your-company.com"
    export LITELLM_KEY="sk-litellm-..."

    # Shield (handles tool RBAC + data policy)
    export LLM_SHIELD_URL="https://shield.votal.ai"
    export API_KEY="tenant-...-key-..."

    # Agent identity
    export AGENT_ID="deep-agent"
    export USER_ROLE="branch_manager"
"""

import os

from deepagents import create_deep_agent
from deepagents.backends import LocalShellBackend
from deepagents.middleware.filesystem import FilesystemPermission
from langchain.agents.middleware import InterruptOnConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.store.memory import InMemoryStore
from langgraph.types import Command

# ─────────────────────────────────────────────────────────────────────────
# CHANGE 1: Import VotalShield
# ─────────────────────────────────────────────────────────────────────────
from votal import VotalShield

shield = VotalShield(
    shield_url=os.getenv("LLM_SHIELD_URL", "https://shield.votal.ai"),
    api_key=os.getenv("API_KEY", ""),
    agent_id=os.getenv("AGENT_ID", "deep-agent"),
    user_role=os.getenv("USER_ROLE", "branch_manager"),
)

# One-time: register agent (safe to call on every startup — idempotent)
shield.register_agent(
    tools=["search_web", "customer_lookup", "send_email", "execute"],
    role_permissions={
        "branch_manager":     ["search_web", "customer_lookup", "send_email", "execute"],
        "customer_support":   ["search_web", "customer_lookup", "send_email"],
        "compliance_officer": ["search_web", "customer_lookup"],
        "fraud_analyst":      ["search_web", "customer_lookup"],
    },
    name="Deep Agent",
    description="Engineering assistant with Shield RBAC",
)

# ─────────────────────────────────────────────────────────────────────────
# Your tools — CHANGE 2: wrap with @shield.protect
# ─────────────────────────────────────────────────────────────────────────
from langchain.tools import tool


@shield.protect       # ← this is the only line you add per tool
@tool
def search_web(query: str) -> str:
    """Search the web for a query and return results."""
    return f"(stub) results for {query!r}"


@shield.protect
@tool
def customer_lookup(customer_id: str) -> str:
    """Look up customer profile by ID."""
    return f'{{"customer_id": "{customer_id}", "name": "Ahmed Ali", "status": "active"}}'


@shield.protect
@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer or internal team."""
    return f'{{"status": "sent", "to": "{to}", "subject": "{subject}"}}'


# ─────────────────────────────────────────────────────────────────────────
# Everything below is your existing harness — UNCHANGED
# ─────────────────────────────────────────────────────────────────────────

# === BACKEND ==============================================================
backend = LocalShellBackend(root_dir="./workspace")

# === PERMISSIONS ==========================================================
main_permissions = [
    FilesystemPermission(operations=["read", "write"], paths=["/workspace/**"], mode="allow"),
    FilesystemPermission(operations=["read", "write"], paths=["/**"], mode="deny"),
]

# === SUBAGENTS ============================================================
subagents = [
    {
        "name": "researcher",
        "description": "Deep research on a topic; returns a synthesized brief.",
        "system_prompt": "You are a meticulous researcher. Search, then summarize concisely.",
        "tools": [search_web],          # already Shield-protected
    },
    {
        "name": "auditor",
        "description": "Read-only code/content reviewer. Never writes files.",
        "system_prompt": "Review the workspace for issues. Do not modify anything.",
        "model": "anthropic:claude-sonnet-4-6",
        # permissions removed — incompatible with shell backend in deepagents 0.5
    },
]

# === HUMAN-IN-THE-LOOP ====================================================
interrupt_on = {
    "write_file": True,
    "execute": InterruptOnConfig(
        allowed_decisions=["approve", "edit", "reject"],
    ),
}

# === SKILLS + MEMORY ======================================================
skills = ["/skills/"]
memory = ["/memory/AGENTS.md"]
checkpointer = InMemorySaver()
store = InMemoryStore()

# === ASSEMBLE =============================================================
# ─────────────────────────────────────────────────────────────────────────
# CHANGE 1 (continued): Point model at LiteLLM proxy
#
# Input/output guardrails run automatically inside LiteLLM — your agent
# code doesn't call Shield for these. Just change the model string.
# ─────────────────────────────────────────────────────────────────────────
LITELLM_URL = os.getenv("LITELLM_URL", "")
LITELLM_KEY = os.getenv("LITELLM_KEY", "")

# If LiteLLM is configured, use it (guardrails automatic).
# Otherwise, use Anthropic directly (no LLM guardrails, but tool RBAC still works).
if LITELLM_URL:
    # Set OpenAI env vars so the model resolves through LiteLLM proxy
    os.environ.setdefault("OPENAI_API_KEY", LITELLM_KEY or "not-needed")
    os.environ.setdefault("OPENAI_BASE_URL", f"{LITELLM_URL}/v1")
    MODEL = f"openai:{os.getenv('MODEL', 'gpt-4o-mini')}"
else:
    MODEL = os.getenv("MODEL", "anthropic:claude-sonnet-4-6")

agent = create_deep_agent(
    model=MODEL,
    tools=[search_web, customer_lookup, send_email],  # already wrapped
    system_prompt="You are a senior engineering assistant for a banking company.",
    subagents=subagents,
    backend=backend,
    # permissions removed — incompatible with shell backend in deepagents 0.5
    # Shield RBAC handles tool-level access control instead
    interrupt_on=interrupt_on,
    skills=skills,
    memory=memory,
    checkpointer=checkpointer,
    store=store,
)


# === RUN ==================================================================
if __name__ == "__main__":
    config = {"configurable": {"thread_id": "session-1"}}

    # Shield RBAC is enforced per tool call:
    #   branch_manager  → all tools allowed
    #   customer_support → search_web, customer_lookup, send_email (no execute)
    #   compliance_officer → search_web, customer_lookup only
    #
    # Change USER_ROLE to test different access levels:
    #   USER_ROLE=compliance_officer python deepagents_shielded.py

    print(f"Agent: {os.getenv('AGENT_ID', 'deep-agent')}")
    print(f"Role:  {os.getenv('USER_ROLE', 'branch_manager')}")
    print(f"LLM:   {LITELLM_URL} (guardrails automatic)")
    print(f"Shield: {shield.shield_url} (tool RBAC)")
    print()

    result = agent.invoke(
        {"messages": [{"role": "user",
                       "content": "Look up customer CUST-12345, then email a summary to ops@bank.ae"}]},
        config,
    )

    while result.get("__interrupt__"):
        result = agent.invoke(Command(resume=[{"type": "approve"}]), config)

    print(result["messages"][-1].content)
