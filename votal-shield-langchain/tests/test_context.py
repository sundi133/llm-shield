from votal_shield_langchain import ShieldContext


def test_context_builds_headers() -> None:
    context = ShieldContext(
        agent_key="support-bot",
        tenant_id="acme",
        user_role="manager",
    )

    assert context.to_headers() == {
        "X-Agent-Key": "support-bot",
        "X-Tenant-ID": "acme",
        "X-User-Role": "manager",
    }


def test_context_generates_session_id() -> None:
    context = ShieldContext(agent_key="support-bot")

    assert context.session_id