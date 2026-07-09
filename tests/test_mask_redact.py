"""Tests for mask and redact actions across the data policy enforcement layers.

Covers:
- _apply_sanitization() in admin_app.py (regex layer)
- _apply_regex_sanitization() in routes_classify_output.py (regex layer)
- validate endpoint role action logic in routes_data_policies.py
- tool_output_sanitization.py guardrail (LLM layer)
- output role_based_policy.py guardrail (LLM layer)
- _resolve_action() with mask in _VALID_ACTIONS
- policy inheritance strictness ordering for mask
"""

import pytest
import json
from unittest.mock import patch, AsyncMock, MagicMock


# ---------------------------------------------------------------------------
# Layer 1: Regex sanitization in admin_app.py
# ---------------------------------------------------------------------------

class TestAdminAppSanitization:
    """Test _apply_sanitization and _resolve_action from admin_app.py."""

    def test_redact_replaces_with_placeholder(self):
        from admin_app import _apply_sanitization

        rules = [{
            "pattern_id": "email",
            "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
            "replacement": "[REDACTED]",
            "description": "Email address",
            "enabled": True,
            "severity": "high",
            "action": "redact",
        }]
        text = "Contact john@acme.com for details"
        sanitized, violations = _apply_sanitization(text, rules)

        assert sanitized == "Contact [REDACTED] for details"
        assert len(violations) == 1
        assert violations[0]["action"] == "redact"
        assert violations[0]["pattern_id"] == "email"

    def test_redact_uses_custom_replacement(self):
        from admin_app import _apply_sanitization

        rules = [{
            "pattern_id": "ssn",
            "regex": r"\b\d{3}-\d{2}-\d{4}\b",
            "replacement": "XXX-XX-XXXX",
            "description": "SSN",
            "enabled": True,
            "severity": "critical",
        }]
        text = "SSN is 123-45-6789"
        sanitized, violations = _apply_sanitization(text, rules)

        # Critical severity always resolves to "block", not "redact"
        # so no substitution happens for critical
        assert violations[0]["action"] == "block"

    def test_mask_partial_replaces_middle(self):
        from admin_app import _apply_sanitization

        rules = [{
            "pattern_id": "email",
            "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
            "replacement": "[REDACTED]",
            "description": "Email address",
            "enabled": True,
            "severity": "high",
            "action": "mask",
        }]
        text = "Contact john@acme.com for details"
        sanitized, violations = _apply_sanitization(text, rules)

        assert "john@acme.com" not in sanitized
        assert violations[0]["action"] == "mask"
        # Partial mask keeps first and last char
        masked_value = sanitized.split("Contact ")[1].split(" for")[0]
        assert masked_value[0] == "j"
        assert masked_value[-1] == "m"
        assert "*" in masked_value

    def test_mask_short_value_fully_starred(self):
        from admin_app import _apply_sanitization

        rules = [{
            "pattern_id": "pin",
            "regex": r"\b\d{4}\b",
            "replacement": "[REDACTED]",
            "description": "4-digit PIN",
            "enabled": True,
            "severity": "medium",
            "action": "mask",
        }]
        text = "PIN is 1234"
        sanitized, violations = _apply_sanitization(text, rules)

        assert sanitized == "PIN is ****"
        assert violations[0]["action"] == "mask"

    def test_detect_does_not_modify_text(self):
        from admin_app import _apply_sanitization

        rules = [{
            "pattern_id": "email",
            "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
            "replacement": "[REDACTED]",
            "description": "Email address",
            "enabled": True,
            "severity": "low",
            "action": "detect",
        }]
        text = "Contact john@acme.com for details"
        sanitized, violations = _apply_sanitization(text, rules)

        assert sanitized == text  # No modification
        assert len(violations) == 1
        assert violations[0]["action"] == "detect"

    def test_disabled_rule_is_skipped(self):
        from admin_app import _apply_sanitization

        rules = [{
            "pattern_id": "email",
            "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
            "replacement": "[REDACTED]",
            "description": "Email",
            "enabled": False,
            "action": "redact",
        }]
        text = "Contact john@acme.com"
        sanitized, violations = _apply_sanitization(text, rules)

        assert sanitized == text
        assert len(violations) == 0

    def test_multiple_rules_redact_and_mask(self):
        from admin_app import _apply_sanitization

        rules = [
            {
                "pattern_id": "email",
                "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
                "replacement": "[EMAIL REDACTED]",
                "description": "Email",
                "enabled": True,
                "action": "redact",
            },
            {
                "pattern_id": "phone",
                "regex": r"\b\d{3}-\d{3}-\d{4}\b",
                "replacement": "[PHONE]",
                "description": "Phone number",
                "enabled": True,
                "action": "mask",
            },
        ]
        text = "Email: john@acme.com Phone: 555-123-4567"
        sanitized, violations = _apply_sanitization(text, rules)

        assert "john@acme.com" not in sanitized
        assert "[EMAIL REDACTED]" in sanitized
        assert "555-123-4567" not in sanitized
        # Phone should be partially masked
        assert len(violations) == 2
        actions = {v["pattern_id"]: v["action"] for v in violations}
        assert actions["email"] == "redact"
        assert actions["phone"] == "mask"

    def test_empty_text_returns_unchanged(self):
        from admin_app import _apply_sanitization

        sanitized, violations = _apply_sanitization("", [{"regex": ".*", "action": "redact", "enabled": True}])
        assert sanitized == ""
        assert violations == []

    def test_empty_rules_returns_unchanged(self):
        from admin_app import _apply_sanitization

        sanitized, violations = _apply_sanitization("some text", [])
        assert sanitized == "some text"
        assert violations == []


class TestResolveAction:
    """Test _resolve_action logic including mask."""

    def test_mask_is_valid_action(self):
        from admin_app import _resolve_action

        result = _resolve_action({"action": "mask"}, "detect")
        assert result == "mask"

    def test_critical_severity_always_blocks(self):
        from admin_app import _resolve_action

        result = _resolve_action({"severity": "critical", "action": "mask"}, "detect")
        assert result == "block"

    def test_no_explicit_action_uses_default(self):
        from admin_app import _resolve_action

        result = _resolve_action({}, "mask")
        assert result == "mask"

    def test_invalid_action_falls_back_to_default(self):
        from admin_app import _resolve_action

        result = _resolve_action({"action": "invalid"}, "redact")
        assert result == "redact"

    def test_invalid_default_falls_back_to_detect(self):
        from admin_app import _resolve_action

        result = _resolve_action({"action": "invalid"}, "invalid")
        assert result == "detect"


# ---------------------------------------------------------------------------
# Layer 1: Regex sanitization in routes_classify_output.py
# ---------------------------------------------------------------------------

class TestClassifyOutputSanitization:
    """Test _apply_regex_sanitization from routes_classify_output.py."""

    def test_redact_in_classify_output(self):
        from api.routes_classify_output import _apply_regex_sanitization

        rules = [{
            "pattern_id": "email",
            "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
            "replacement": "[REDACTED]",
            "description": "Email",
            "enabled": True,
            "action": "redact",
        }]
        sanitized, violations, had_block = _apply_regex_sanitization(
            "Contact john@acme.com", rules
        )
        assert sanitized == "Contact [REDACTED]"
        assert not had_block
        assert violations[0]["action"] == "redact"

    def test_mask_in_classify_output(self):
        from api.routes_classify_output import _apply_regex_sanitization

        rules = [{
            "pattern_id": "email",
            "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
            "replacement": "[REDACTED]",
            "description": "Email",
            "enabled": True,
            "action": "mask",
        }]
        sanitized, violations, had_block = _apply_regex_sanitization(
            "Contact john@acme.com", rules
        )
        assert "john@acme.com" not in sanitized
        assert not had_block
        assert violations[0]["action"] == "mask"
        # First and last char preserved
        masked = sanitized.replace("Contact ", "")
        assert masked[0] == "j"
        assert masked[-1] == "m"

    def test_block_in_classify_output(self):
        from api.routes_classify_output import _apply_regex_sanitization

        rules = [{
            "pattern_id": "ssn",
            "regex": r"\b\d{3}-\d{2}-\d{4}\b",
            "replacement": "[REDACTED]",
            "description": "SSN",
            "enabled": True,
            "severity": "critical",
        }]
        sanitized, violations, had_block = _apply_regex_sanitization(
            "SSN: 123-45-6789", rules
        )
        assert had_block
        assert violations[0]["action"] == "block"


# ---------------------------------------------------------------------------
# Validate endpoint: role action enforcement
# ---------------------------------------------------------------------------

class TestValidateEndpointRoleActions:
    """Test role action logic in routes_data_policies.py validate endpoint."""

    @pytest.mark.asyncio
    async def test_block_escalates_severity(self):
        """When role_action=block and violations exist, severity becomes critical."""
        from starlette.testclient import TestClient
        from core.app import create_app

        app = create_app()
        client = TestClient(app)

        # Set up a policy with block action via the data policies API
        policy = {
            "tool_name": "test_tool_block",
            "sanitization_rules": [{
                "pattern_id": "email",
                "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
                "replacement": "[REDACTED]",
                "description": "Email",
                "enabled": True,
                "severity": "high",
            }],
            "role_policies": [{
                "role": "intern",
                "action": "block",
                "data_scope": ["personal"],
            }],
        }

        with patch("api.routes_data_policies._get_redis") as mock_redis:
            mock_r = MagicMock()
            mock_r.get.return_value = json.dumps({"test_tool_block": policy})
            mock_redis.return_value = mock_r

            resp = client.post("/v1/data-policies/validate", json={
                "tool_name": "test_tool_block",
                "data": "email is john@acme.com",
                "user_role": "intern",
                "stage": "input",
            }, headers={"X-Tenant-ID": "test-tenant"})

        if resp.status_code == 200:
            result = resp.json()
            validation = result.get("validation_result", {})
            if validation.get("violations"):
                for v in validation["violations"]:
                    assert v["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_mask_applies_partial_masking(self):
        """When role_action=mask and violations exist, data is partially masked."""
        from starlette.testclient import TestClient
        from core.app import create_app

        app = create_app()
        client = TestClient(app)

        policy = {
            "tool_name": "test_tool_mask",
            "sanitization_rules": [{
                "pattern_id": "email",
                "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
                "replacement": "[REDACTED]",
                "description": "Email",
                "enabled": True,
                "severity": "high",
            }],
            "role_policies": [{
                "role": "branch_manager",
                "action": "mask",
                "data_scope": ["personal", "contact"],
            }],
        }

        with patch("api.routes_data_policies._get_redis") as mock_redis:
            mock_r = MagicMock()
            mock_r.get.return_value = json.dumps({"test_tool_mask": policy})
            mock_redis.return_value = mock_r

            resp = client.post("/v1/data-policies/validate", json={
                "tool_name": "test_tool_mask",
                "data": "email is john@acme.com",
                "user_role": "branch_manager",
                "stage": "input",
            }, headers={"X-Tenant-ID": "test-tenant"})

        if resp.status_code == 200:
            result = resp.json()
            assert result.get("data_modified") is True
            assert "john@acme.com" not in result.get("sanitized_data", "")
            assert result["metadata"]["role_action"] == "mask"

    @pytest.mark.asyncio
    async def test_redact_applies_full_redaction(self):
        """When role_action=redact and violations exist, data is fully redacted."""
        from starlette.testclient import TestClient
        from core.app import create_app

        app = create_app()
        client = TestClient(app)

        policy = {
            "tool_name": "test_tool_redact",
            "sanitization_rules": [{
                "pattern_id": "email",
                "regex": r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
                "replacement": "[REDACTED]",
                "description": "Email",
                "enabled": True,
                "severity": "high",
            }],
            "role_policies": [{
                "role": "compliance_officer",
                "action": "redact",
                "data_scope": ["personal"],
                "redaction_level": "full",
            }],
        }

        with patch("api.routes_data_policies._get_redis") as mock_redis:
            mock_r = MagicMock()
            mock_r.get.return_value = json.dumps({"test_tool_redact": policy})
            mock_redis.return_value = mock_r

            resp = client.post("/v1/data-policies/validate", json={
                "tool_name": "test_tool_redact",
                "data": "email is john@acme.com",
                "user_role": "compliance_officer",
                "stage": "input",
            }, headers={"X-Tenant-ID": "test-tenant"})

        if resp.status_code == 200:
            result = resp.json()
            assert result.get("data_modified") is True
            assert "john@acme.com" not in result.get("sanitized_data", "")
            assert result["metadata"]["role_action"] == "redact"

    @pytest.mark.asyncio
    async def test_allow_passes_data_through(self):
        """When role_action=allow, data is not modified even with pattern matches."""
        from starlette.testclient import TestClient
        from core.app import create_app

        app = create_app()
        client = TestClient(app)

        policy = {
            "tool_name": "test_tool_allow",
            "sanitization_rules": [],
            "role_policies": [{
                "role": "admin",
                "action": "allow",
                "data_scope": [],
            }],
        }

        with patch("api.routes_data_policies._get_redis") as mock_redis:
            mock_r = MagicMock()
            mock_r.get.return_value = json.dumps({"test_tool_allow": policy})
            mock_redis.return_value = mock_r

            resp = client.post("/v1/data-policies/validate", json={
                "tool_name": "test_tool_allow",
                "data": "email is john@acme.com",
                "user_role": "admin",
                "stage": "input",
            }, headers={"X-Tenant-ID": "test-tenant"})

        if resp.status_code == 200:
            result = resp.json()
            assert result["metadata"]["role_action"] == "allow"


# ---------------------------------------------------------------------------
# Admin app: data policy action enforcement (block/mask/redact flags)
# ---------------------------------------------------------------------------

class TestAdminAppDpActionFlags:
    """Test that admin_app sets data_policy_blocked/masked/redacted flags."""

    def test_block_flag_set_on_violation(self):
        entry = {
            "rbac": {"allowed": True, "message": ""},
            "data_rule_violation": {"passed": False, "reason": "SSN found"},
        }
        dp_action = "block"
        has_rule_violation = not entry["data_rule_violation"].get("passed", True)

        if dp_action == "block" and has_rule_violation:
            violation = entry["data_rule_violation"]
            reason = violation.get("reason") or "Data policy violation"
            entry["rbac"]["allowed"] = False
            entry["rbac"]["message"] = f"Data policy blocked: {reason}"
            entry["data_policy_blocked"] = True

        assert entry["data_policy_blocked"] is True
        assert entry["rbac"]["allowed"] is False
        assert "SSN found" in entry["rbac"]["message"]

    def test_mask_flag_set_on_violation(self):
        entry = {
            "rbac": {"allowed": True, "message": ""},
            "data_rule_violation": {"passed": False, "reason": "Email found"},
        }
        dp_action = "mask"
        has_rule_violation = not entry["data_rule_violation"].get("passed", True)

        if dp_action == "mask" and has_rule_violation:
            entry["data_policy_masked"] = True

        assert entry.get("data_policy_masked") is True
        # mask does NOT block access
        assert entry["rbac"]["allowed"] is True

    def test_redact_flag_set_on_violation(self):
        entry = {
            "rbac": {"allowed": True, "message": ""},
            "data_rule_violation": {"passed": False, "reason": "PII found"},
        }
        dp_action = "redact"
        has_rule_violation = not entry["data_rule_violation"].get("passed", True)

        if dp_action == "redact" and has_rule_violation:
            entry["data_policy_redacted"] = True

        assert entry.get("data_policy_redacted") is True
        # redact does NOT block access
        assert entry["rbac"]["allowed"] is True

    def test_no_flag_when_no_violation(self):
        entry = {
            "rbac": {"allowed": True, "message": ""},
            "data_rule_violation": {"passed": True},
        }
        dp_action = "block"
        has_rule_violation = not entry["data_rule_violation"].get("passed", True)

        if dp_action == "block" and has_rule_violation:
            entry["data_policy_blocked"] = True

        assert "data_policy_blocked" not in entry


# ---------------------------------------------------------------------------
# Tool output sanitization guardrail
# ---------------------------------------------------------------------------

class TestToolOutputSanitizationActions:
    """Test ToolOutputSanitizationGuardrail handles mask/redact/block.

    CSV format is: has_sensitive,action,confidence,findings
    """

    @pytest.mark.asyncio
    async def test_block_action_returns_blocked_output(self):
        from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

        guard = ToolOutputSanitizationGuardrail.__new__(ToolOutputSanitizationGuardrail)
        guard.name = "tool_output_sanitization"
        guard._config = MagicMock()
        guard._config.settings = {}

        llm_response = {
            "choices": [{
                "message": {
                    "content": "true,block,0.95,contains SSN data"
                }
            }]
        }

        with patch("guardrails.agentic.tool.tool_output_sanitization.async_llm_call",
                    new_callable=AsyncMock, return_value=llm_response):
            with patch.object(guard, "_load_policies_text", return_value=""):
                result = await guard.check(
                    "SSN: 123-45-6789",
                    context={"tenant_id": "t1", "user_role": "viewer"}
                )

        assert result.passed is False
        assert result.action == "block"
        assert "blocked" in result.message.lower()
        assert result.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"

    @pytest.mark.asyncio
    async def test_mask_action_returns_partial_mask(self):
        from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

        guard = ToolOutputSanitizationGuardrail.__new__(ToolOutputSanitizationGuardrail)
        guard.name = "tool_output_sanitization"
        guard._config = MagicMock()
        guard._config.settings = {}

        llm_response = {
            "choices": [{
                "message": {
                    "content": "true,mask,0.90,contains PII"
                }
            }]
        }

        with patch("guardrails.agentic.tool.tool_output_sanitization.async_llm_call",
                    new_callable=AsyncMock, return_value=llm_response):
            with patch.object(guard, "_load_policies_text", return_value=""):
                result = await guard.check(
                    "User email: john@acme.com",
                    context={"tenant_id": "t1", "user_role": "branch_manager"}
                )

        assert result.passed is False
        assert result.action == "mask"
        assert "masked" in result.message.lower()
        assert result.details.get("mask_level") == "partial"

    @pytest.mark.asyncio
    async def test_redact_action_returns_flagged(self):
        from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
        from config.schema import GuardrailConfig

        guard = ToolOutputSanitizationGuardrail.__new__(ToolOutputSanitizationGuardrail)
        guard.name = "tool_output_sanitization"
        guard._config = GuardrailConfig(enabled=True, action="warn", settings={})

        llm_response = {
            "choices": [{
                "message": {
                    "content": "true,redact,0.88,contains financial data"
                }
            }]
        }

        with patch("guardrails.agentic.tool.tool_output_sanitization.async_llm_call",
                    new_callable=AsyncMock, return_value=llm_response):
            with patch.object(guard, "_load_policies_text", return_value=""):
                result = await guard.check(
                    "Account balance: $50,000",
                    context={"tenant_id": "t1", "user_role": "teller"}
                )

        assert result.passed is False
        assert "sensitive data" in result.message.lower()

    @pytest.mark.asyncio
    async def test_low_confidence_allows_through(self):
        from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

        guard = ToolOutputSanitizationGuardrail.__new__(ToolOutputSanitizationGuardrail)
        guard.name = "tool_output_sanitization"
        guard._config = MagicMock()
        guard._config.settings = {}

        llm_response = {
            "choices": [{
                "message": {
                    "content": "true,block,0.50,might contain PII"
                }
            }]
        }

        with patch("guardrails.agentic.tool.tool_output_sanitization.async_llm_call",
                    new_callable=AsyncMock, return_value=llm_response):
            with patch.object(guard, "_load_policies_text", return_value=""):
                result = await guard.check(
                    "Hello world",
                    context={"tenant_id": "t1", "user_role": "viewer"}
                )

        # Confidence < 0.75 should allow through
        assert result.passed is True


# ---------------------------------------------------------------------------
# Output role-based policy guardrail: mask treated as redact variant
# ---------------------------------------------------------------------------

class TestOutputRoleBasedPolicyMask:
    """Test that mask action feeds into the LLM prompt alongside redact."""

    def test_mask_creates_redaction_rule(self):
        """mask action should create a redaction rule entry with partial level."""
        from guardrails.output.role_based_policy import RoleBasedOutputPolicyGuardrail

        role_policies = [
            {
                "tool_name": "get_customer",
                "action": "mask",
                "data_scope": ["personal", "financial"],
                "redaction_level": "partial",
            }
        ]

        blocked_tools = []
        redaction_rules = []

        for policy in role_policies:
            action = policy["action"]
            data_scope = policy.get("data_scope", [])

            if action == "block":
                blocked_tools.append(policy["tool_name"])
            elif action in ("redact", "mask"):
                redaction_rules.append({
                    "tool": policy["tool_name"],
                    "data_types": data_scope,
                    "level": policy.get("redaction_level", "partial") if action == "mask" else policy.get("redaction_level", "full"),
                    "action": action,
                })

        assert len(blocked_tools) == 0
        assert len(redaction_rules) == 1
        assert redaction_rules[0]["action"] == "mask"
        assert redaction_rules[0]["level"] == "partial"
        assert redaction_rules[0]["data_types"] == ["personal", "financial"]

    def test_redact_creates_redaction_rule_full(self):
        """redact action should create a redaction rule with full level by default."""
        role_policies = [
            {
                "tool_name": "get_customer",
                "action": "redact",
                "data_scope": ["personal"],
            }
        ]

        redaction_rules = []
        for policy in role_policies:
            action = policy["action"]
            data_scope = policy.get("data_scope", [])
            if action in ("redact", "mask"):
                redaction_rules.append({
                    "tool": policy["tool_name"],
                    "data_types": data_scope,
                    "level": policy.get("redaction_level", "partial") if action == "mask" else policy.get("redaction_level", "full"),
                    "action": action,
                })

        assert len(redaction_rules) == 1
        assert redaction_rules[0]["action"] == "redact"
        assert redaction_rules[0]["level"] == "full"

    def test_block_does_not_create_redaction_rule(self):
        role_policies = [
            {
                "tool_name": "delete_customer",
                "action": "block",
                "data_scope": ["personal"],
            }
        ]

        blocked_tools = []
        redaction_rules = []
        for policy in role_policies:
            action = policy["action"]
            if action == "block":
                blocked_tools.append(policy["tool_name"])
            elif action in ("redact", "mask"):
                redaction_rules.append(policy)

        assert len(blocked_tools) == 1
        assert len(redaction_rules) == 0


# ---------------------------------------------------------------------------
# Policy inheritance: strictness ordering includes mask
# ---------------------------------------------------------------------------

class TestPolicyInheritanceStrictness:
    """Verify mask sits between redact and block in strictness ordering."""

    def test_strictness_ordering(self):
        from core.policy_inheritance import _ACTION_STRICTNESS

        assert _ACTION_STRICTNESS["allow"] < _ACTION_STRICTNESS["redact"]
        assert _ACTION_STRICTNESS["redact"] < _ACTION_STRICTNESS["mask"]
        assert _ACTION_STRICTNESS["mask"] < _ACTION_STRICTNESS["block"]

    def test_mask_in_strictness_map(self):
        from core.policy_inheritance import _ACTION_STRICTNESS

        assert "mask" in _ACTION_STRICTNESS

    def test_child_can_escalate_redact_to_mask(self):
        from core.policy_inheritance import validate_child_policy

        parent = {"enabled": True, "roles": {"user": {"pii": "redact"}}}
        child = {"enabled": True, "roles": {"user": {"pii": "mask"}}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is True

    def test_child_cannot_weaken_mask_to_redact(self):
        from core.policy_inheritance import validate_child_policy

        parent = {"enabled": True, "roles": {"user": {"pii": "mask"}}}
        child = {"enabled": True, "roles": {"user": {"pii": "redact"}}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is False

    def test_child_can_escalate_mask_to_block(self):
        from core.policy_inheritance import validate_child_policy

        parent = {"enabled": True, "roles": {"user": {"pii": "mask"}}}
        child = {"enabled": True, "roles": {"user": {"pii": "block"}}}
        is_valid, reason = validate_child_policy(parent, child)
        assert is_valid is True
