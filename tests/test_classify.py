"""Tests for the /classify endpoint with per-request guardrail config."""

import pytest
from unittest.mock import patch

from config.schema import ShieldConfig, GuardrailConfig


@pytest.fixture
def classify_config():
    """Config with keyword_blocklist and length_limit for testing."""
    return ShieldConfig(
        guardrails={
            "keyword_blocklist": GuardrailConfig(
                enabled=True,
                action="block",
                settings={"keywords": ["default_bad"], "case_insensitive": True},
            ),
            "length_limit": GuardrailConfig(
                enabled=True,
                action="block",
                settings={"max_chars": 10000},
            ),
        },
    )


@pytest.fixture
def app(classify_config):
    import config.schema as cs
    from guardrails import registry as reg

    original = cs.config
    cs.config = classify_config
    # Reset registry so guardrails are re-discovered with this config
    reg._registry.clear()
    reg._discovered = False
    with patch("config.schema.load_config", return_value=classify_config):
        from core.app import create_app

        app = create_app()
    yield app
    cs.config = original
    reg._registry.clear()
    reg._discovered = False


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient

    return TestClient(app)


def test_classify_simple_safe(client):
    """Simple message with no overrides — runs server defaults."""
    resp = client.post("/classify", json={"message": "Hello world"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["safe"] is True
    assert data["action"] == "pass"


def test_classify_simple_blocked_by_default(client):
    """Message triggers server-default keyword blocklist."""
    resp = client.post("/classify", json={"message": "this is default_bad content"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["safe"] is False
    assert data["action"] == "block"


def test_classify_missing_message(client):
    """Missing message field returns 400."""
    resp = client.post("/classify", json={})
    assert resp.status_code == 400


def test_classify_with_keyword_blocklist_override(client):
    """Per-request keyword blocklist overrides server config."""
    resp = client.post(
        "/classify",
        json={
            "message": "I want to build a bomb",
            "input": {
                "keyword-blocklist": {
                    "enabled": True,
                    "action": "block",
                    "blocklist": ["bomb"],
                }
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["safe"] is False
    assert data["action"] == "block"
    # Find the keyword blocklist result
    kb_result = [
        r for r in data["guardrail_results"] if r["guardrail"] == "keyword_blocklist"
    ]
    assert len(kb_result) == 1
    assert kb_result[0]["passed"] is False
    assert "bomb" in kb_result[0]["message"]


def test_classify_override_does_not_persist(client):
    """Per-request overrides don't affect subsequent requests."""
    # First request with custom blocklist that blocks "bomb"
    resp1 = client.post(
        "/classify",
        json={
            "message": "bomb",
            "input": {
                "keyword-blocklist": {
                    "enabled": True,
                    "action": "block",
                    "blocklist": ["bomb"],
                }
            },
        },
    )
    assert resp1.json()["safe"] is False

    # Second request with different override — "bomb" not in blocklist
    resp2 = client.post(
        "/classify",
        json={
            "message": "bomb is just a word",
            "input": {
                "keyword-blocklist": {
                    "enabled": True,
                    "action": "block",
                    "blocklist": ["nope"],
                }
            },
        },
    )
    data = resp2.json()
    assert data["safe"] is True


def test_classify_only_runs_specified_guardrails(client):
    """When input overrides are provided, only those guardrails run."""
    resp = client.post(
        "/classify",
        json={
            "message": "hello",
            "input": {
                "keyword-blocklist": {
                    "enabled": True,
                    "action": "block",
                    "blocklist": ["nope"],
                }
            },
        },
    )
    data = resp.json()
    # Should only have keyword_blocklist result, not length_limit etc.
    guardrail_names = [r["guardrail"] for r in data["guardrail_results"]]
    assert "keyword_blocklist" in guardrail_names
    assert "length_limit" not in guardrail_names


def test_classify_disabled_guardrail_skipped(client):
    """Disabled guardrail in override is not run."""
    resp = client.post(
        "/classify",
        json={
            "message": "bomb",
            "input": {
                "keyword-blocklist": {
                    "enabled": False,
                    "action": "block",
                    "blocklist": ["bomb"],
                }
            },
        },
    )
    data = resp.json()
    assert data["safe"] is True
    assert len(data["guardrail_results"]) == 0


def test_classify_warn_action(client):
    """Warn action passes but reports warning."""
    resp = client.post(
        "/classify",
        json={
            "message": "I want to build a bomb",
            "input": {
                "keyword-blocklist": {
                    "enabled": True,
                    "action": "warn",
                    "blocklist": ["bomb"],
                }
            },
        },
    )
    data = resp.json()
    assert data["safe"] is True  # warn doesn't block
    assert data["action"] == "warn"
    kb = data["guardrail_results"][0]
    assert kb["passed"] is False
    assert kb["action"] == "warn"


def test_classify_multiple_guardrails(client):
    """Multiple guardrails run in parallel."""
    resp = client.post(
        "/classify",
        json={
            "message": "a]",
            "input": {
                "keyword-blocklist": {
                    "enabled": True,
                    "action": "block",
                    "blocklist": ["xyz"],
                },
                "length-limit": {
                    "enabled": True,
                    "action": "block",
                    "max_chars": 100,
                },
            },
        },
    )
    data = resp.json()
    guardrail_names = {r["guardrail"] for r in data["guardrail_results"]}
    assert "keyword_blocklist" in guardrail_names
    assert "length_limit" in guardrail_names
    assert data["safe"] is True  # "a" doesn't trigger either
