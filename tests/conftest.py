"""Shared test fixtures for LLM Shield tests."""

import sys
from pathlib import Path

import pytest
from unittest.mock import patch

# Standalone pip packages under packages/ use a src layout. Put their src dirs on
# sys.path so their tests (tests/test_shield_mcp_*.py, tests/test_mcp_registry_*.py)
# run under the repo's `pytest tests` gate without a separate install step.
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "packages"
for _pkg in ("shield-mcp", "mcp-registry"):
    _src = _PACKAGE_ROOT / _pkg / "src"
    if _src.is_dir() and str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

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
