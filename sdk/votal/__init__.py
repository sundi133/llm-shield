"""Votal Shield SDK — protect any LLM agent with RBAC + data policies.

Usage:
    from votal import VotalShield

    shield = VotalShield(
        shield_url="https://shield.votal.ai",
        api_key="your-tenant-api-key",
        agent_id="my-agent",
        user_role="branch_manager",
    )

    # Option A: Decorator — wraps a LangChain tool
    @shield.protect
    @tool
    def get_account_balance(customer_id: str) -> str:
        return db.query(customer_id)

    # Option B: Wrap existing tools
    tools = shield.wrap_tools([search_faq, create_ticket])

    # Option C: LangChain callback (wraps ALL tools automatically)
    executor = AgentExecutor(
        agent=agent, tools=tools,
        callbacks=[shield.callback()],
    )

    # Option D: Manual check (for custom flows)
    with shield.tool_guard("get_balance", {"id": "C-123"}) as guard:
        if guard.allowed:
            raw = get_balance("C-123")
            result = guard.sanitize(raw)
"""

from votal.client import VotalShield
from votal.guard import ToolGuard, ToolGuardContext

__all__ = ["VotalShield", "ToolGuard", "ToolGuardContext"]
__version__ = "0.1.0"
