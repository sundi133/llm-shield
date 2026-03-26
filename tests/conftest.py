"""Shared test fixtures for LLM Shield tests."""

import pytest
from unittest.mock import patch

from config.schema import (
    ShieldConfig,
    GuardrailConfig,
    RBACConfig,
    RBACRole,
    PipelineConfig,
)


@pytest.fixture
def mock_config():
    """Provide a mock ShieldConfig with test values and patch it into config.schema.config."""
    test_config = ShieldConfig(
        guardrails={
            "keyword_blocklist": GuardrailConfig(
                enabled=True,
                action="block",
                settings={
                    "keywords": ["hack", "exploit", "malware"],
                    "case_insensitive": True,
                },
            ),
            "length_limit": GuardrailConfig(
                enabled=True,
                action="block",
                settings={
                    "max_chars": 100,
                    "max_tokens": 50,
                    "encoding": "cl100k_base",
                },
            ),
            "regex_pattern": GuardrailConfig(
                enabled=True,
                action="block",
                settings={
                    "patterns": [
                        {
                            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                            "description": "SSN pattern",
                            "action": "block",
                        },
                        {
                            "pattern": r"password\s*=\s*\S+",
                            "description": "Password in text",
                            "action": "warn",
                        },
                    ],
                },
            ),
            "rate_limiter": GuardrailConfig(
                enabled=True,
                action="block",
                settings={
                    "max_requests": 3,
                    "window_seconds": 60,
                },
            ),
            "action_guard": GuardrailConfig(
                enabled=True,
                action="block",
                settings={
                    "max_actions_per_type": {
                        "delete": 2,
                        "modify": 5,
                    },
                    "sensitive_actions": ["delete", "modify_permissions"],
                    "require_approval_for": ["delete_account", "bulk_export"],
                },
            ),
            "rbac_guard": GuardrailConfig(
                enabled=True,
                action="block",
                settings={},
            ),
        },
        rbac=RBACConfig(
            roles={
                "viewer": RBACRole(
                    name="viewer",
                    allowed_tools=["search", "read"],
                    denied_tools=["execute_sql"],
                    max_tokens_per_request=1024,
                    rate_limit="10/min",
                    data_clearance="public",
                    allowed_data_scopes=["public_docs"],
                    denied_data_scopes=["financials"],
                ),
                "admin": RBACRole(
                    name="admin",
                    allowed_tools=[],
                    denied_tools=[],
                    max_tokens_per_request=8192,
                    rate_limit="300/min",
                    data_clearance="restricted",
                    allowed_data_scopes=[],
                    denied_data_scopes=[],
                ),
            },
            agents={
                "agent-viewer": "viewer",
                "agent-admin": "admin",
            },
        ),
        pipeline=PipelineConfig(fast_timeout_ms=500, slow_timeout_ms=5000),
    )

    with patch("config.schema.config", test_config):
        yield test_config
