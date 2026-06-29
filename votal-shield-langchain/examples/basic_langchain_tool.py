"""Basic example of a Shield-protected LangChain tool."""

from votal_shield_langchain import ShieldClient, ShieldContext, shield_tool

client = ShieldClient(
    base_url="http://localhost:8080",
    api_key="replace-with-your-shield-api-key",
)

context = ShieldContext(
    agent_key="customer-service-agent",
    tenant_id="demo-tenant",
    user_role="branch_manager",
)


@shield_tool(
    client=client,
    context=context,
    name="email_send",
    description="Send an email after Shield authorizes the tool call.",
)
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""

    return f"Email sent to {to} with subject '{subject}'."


if __name__ == "__main__":
    result = send_email.invoke(
        {
            "to": "ops@bank.ae",
            "subject": "Audit Complete",
            "body": "The audit has been completed.",
        }
    )

    print(result)