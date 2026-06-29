from typing import Any

from votal_shield_langchain import ShieldClient, ShieldContext, shield_tool
from votal_shield_langchain.errors import ShieldAuthorizationError


class DemoShieldClient(ShieldClient):
    """Fake local Shield client for demo purposes."""

    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed

    def check_tool(
        self,
        *,
        context: ShieldContext,
        tool_name: str,
        tool_params: dict[str, Any],
        input_sources: list[str] | None = None,
    ) -> dict[str, Any]:
        print("\n[Shield] Checking tool permission...")
        print(f"[Shield] Agent: {context.agent_key}")
        print(f"[Shield] Tenant: {context.tenant_id}")
        print(f"[Shield] Role: {context.user_role}")
        print(f"[Shield] Tool: {tool_name}")
        print(f"[Shield] Params: {tool_params}")

        if not self.allowed:
            raise ShieldAuthorizationError("Tool blocked by policy")

        print("[Shield] Decision: ALLOW")
        return {"allowed": True}

    def report_tool_output(
        self,
        *,
        context: ShieldContext,
        tool_name: str,
        tool_output: Any,
        tool_call_id: str,
    ) -> dict[str, Any]:
        print("\n[Shield] Reporting tool output...")
        print(f"[Shield] Tool output: {tool_output}")
        print("[Shield] Output sanitized/audited")
        return {"sanitized_output": f"[SAFE OUTPUT] {tool_output}"}


context = ShieldContext(
    agent_key="customer-service-agent",
    tenant_id="demo-tenant",
    user_role="branch_manager",
)


allowed_client = DemoShieldClient(allowed=True)


@shield_tool(
    client=allowed_client,
    context=context,
    name="email_send",
    description="Send an email after Shield authorizes the call.",
)
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    print("\n[Tool] Original send_email function is running...")
    return f"Email sent to {to} with subject '{subject}'"


print("\n========== DEMO 1: ALLOWED TOOL CALL ==========")

result = send_email.invoke(
    {
        "to": "ops@bank.ae",
        "subject": "Audit Complete",
        "body": "The audit has been completed.",
    }
)

print(f"\nFinal result returned to LangChain: {result}")


blocked_client = DemoShieldClient(allowed=False)


@shield_tool(
    client=blocked_client,
    context=context,
    name="database_delete",
    description="Delete a database record.",
)
def delete_record(record_id: str) -> str:
    """Delete a database record."""
    print("\n[Tool] THIS SHOULD NOT RUN")
    return f"Deleted record {record_id}"


print("\n========== DEMO 2: BLOCKED TOOL CALL ==========")

blocked_result = delete_record.invoke({"record_id": "customer-123"})

print(f"\nFinal result returned to LangChain: {blocked_result}")