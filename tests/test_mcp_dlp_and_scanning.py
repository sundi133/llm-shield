"""Per-server DLP, redaction and tool-result scanning (phases 6 and 7).

Two controls, both identity-independent by construction:

* ``dlp.sanitize_as`` fixes the role the output sanitizer is told about. The
  sanitizer puts user_role into its LLM prompt, and the gateway takes that role
  from a header unless verified-identity middleware supplied one — so without
  this a caller could claim ``admin`` and widen its own redaction.
* ``result_scanning`` moves the indirect-injection scan off two process-wide env
  vars and onto the server, so an untrusted SaaS server can be scanned and
  blocking while an internal one is left alone.

Every enforcement assertion here uses a caller claiming ``admin``.
"""

from unittest.mock import patch

import pytest

from core.mcp import enforcement as enf


# ── dlp.sanitize_as ──────────────────────────────────────────────────


def test_no_policy_keeps_the_claimed_role():
    """Unbound servers must behave exactly as before."""
    assert enf.dlp_role_for(None, "admin") == "admin"
    assert enf.dlp_role_for({}, "admin") == "admin"
    assert enf.dlp_role_for({"dlp": {}}, "admin") == "admin"


def test_sanitize_as_overrides_a_self_declared_admin():
    assert enf.dlp_role_for({"dlp": {"sanitize_as": "public"}}, "admin") == "public"


def test_sanitize_as_applies_even_with_no_claimed_role():
    assert enf.dlp_role_for({"dlp": {"sanitize_as": "public"}}, None) == "public"


def test_malformed_dlp_block_is_ignored():
    for bad in ({"dlp": "nonsense"}, {"dlp": None}, {"dlp": []}):
        assert enf.dlp_role_for(bad, "admin") == "admin"


def test_escape_hatch_restores_the_claimed_role():
    with patch.dict("os.environ", {"SHIELD_MCP_FLEET_POLICY": "0"}):
        assert enf.dlp_role_for({"dlp": {"sanitize_as": "public"}}, "admin") == "admin"


@pytest.mark.asyncio
async def test_sanitizer_receives_the_clamped_role():
    """End of the chain: the guard must actually be told the fixed role, since
    that string is what reaches its prompt."""
    seen = {}

    class _Guard:
        async def check(self, content, context):
            seen.update(context)
            return type("R", (), {"passed": True, "action": "pass", "details": {}})()

    with patch.object(enf, "ToolOutputSanitizationGuardrail", lambda: _Guard()), \
         patch.object(enf, "IndirectInjectionGuardrail",
                      lambda: type("I", (), {"scan_enabled": lambda s: False})()):
        await enf.sanitize_tool_result(
            "t", "out", tenant_id="acme", user_role="admin",
            policy={"dlp": {"sanitize_as": "public"}})

    assert seen["user_role"] == "public"
    assert seen["X-User-Role"] == "public"


@pytest.mark.asyncio
async def test_output_guardrails_reach_the_sanitizer_config():
    """output_guardrails tune the sanitizer through the same ContextVar the
    input guards use, so a server can redact harder than the tenant default."""
    from guardrails.base import _request_configs

    seen = {}

    class _Guard:
        async def check(self, content, context):
            seen["cfg"] = (_request_configs.get() or {}).get("tool_output_sanitization")
            return type("R", (), {"passed": True, "action": "pass", "details": {}})()

    with patch.object(enf, "ToolOutputSanitizationGuardrail", lambda: _Guard()), \
         patch.object(enf, "IndirectInjectionGuardrail",
                      lambda: type("I", (), {"scan_enabled": lambda s: False})()):
        await enf.sanitize_tool_result(
            "t", "out", tenant_id="acme", user_role="admin",
            policy={"output_guardrails": {"tool_output_sanitization": {
                "enabled": True, "action": "block",
                "settings": {"max_output_length": 100}}}})

    assert seen["cfg"]["settings"] == {"max_output_length": 100}
    # The ContextVar must not leak past the call.
    assert _request_configs.get() is None


# ── result_scanning ──────────────────────────────────────────────────


def test_no_override_defers_to_the_env_flags():
    """Absent policy must leave the process-wide behavior exactly as it was."""
    assert enf.result_scanning_for(None) is None
    assert enf.result_scanning_for({}) is None
    assert enf.result_scanning_for({"result_scanning": {}}) is None  # no 'enabled'
    assert enf.result_scanning_for({"result_scanning": "nonsense"}) is None


def test_override_enables_and_blocks():
    cfg = enf.result_scanning_for({"result_scanning": {"enabled": True, "action": "block"}})
    assert cfg == {"enabled": True, "block": True}


def test_monitor_action_records_without_withholding():
    cfg = enf.result_scanning_for({"result_scanning": {"enabled": True, "action": "monitor"}})
    assert cfg == {"enabled": True, "block": False}


def test_anything_other_than_block_is_monitor():
    """Fail toward recording rather than silently withholding results on a typo."""
    cfg = enf.result_scanning_for({"result_scanning": {"enabled": True, "action": "blok"}})
    assert cfg["block"] is False


def test_override_can_disable_scanning_for_a_trusted_server():
    cfg = enf.result_scanning_for({"result_scanning": {"enabled": False}})
    assert cfg == {"enabled": False, "block": False}


def test_escape_hatch_drops_the_override():
    with patch.dict("os.environ", {"SHIELD_MCP_FLEET_POLICY": "0"}):
        assert enf.result_scanning_for({"result_scanning": {"enabled": True}}) is None


def _patched(scan_enabled, detected):
    """A sanitizer that passes, and an injection guard with a fixed verdict."""
    class _Guard:
        async def check(self, content, context):
            return type("R", (), {"passed": True, "action": "pass", "details": {}})()

    class _Inj:
        def scan_enabled(self):
            return scan_enabled

        async def check(self, content, context):
            if detected:
                # A detection under env monitor-mode reports action="log".
                return type("R", (), {"passed": False, "action": "log",
                                      "details": {}, "guardrail_name": "indirect_injection",
                                      "message": "x"})()
            return type("R", (), {"passed": True, "action": "pass", "details": {},
                                  "guardrail_name": "indirect_injection",
                                  "message": ""})()

    return (patch.object(enf, "ToolOutputSanitizationGuardrail", lambda: _Guard()),
            patch.object(enf, "IndirectInjectionGuardrail", lambda: _Inj()),
            patch.object(enf, "_record_metrics", lambda *a, **k: None))


@pytest.mark.asyncio
async def test_policy_can_block_a_detection_the_env_would_only_log():
    """The env flags are all-or-nothing across a fleet; a server-level 'block'
    must be able to withhold a result even when the process is monitor-only."""
    g, i, m = _patched(scan_enabled=False, detected=True)
    with g, i, m:
        out = await enf.sanitize_tool_result(
            "t", "out", tenant_id="acme", user_role="admin",
            policy={"result_scanning": {"enabled": True, "action": "block"}})
    assert out["blocked"] is True
    assert "indirect prompt injection" in out["sanitized_output"]


@pytest.mark.asyncio
async def test_policy_monitor_records_but_returns_the_result():
    g, i, m = _patched(scan_enabled=False, detected=True)
    with g, i, m:
        out = await enf.sanitize_tool_result(
            "t", "out", tenant_id="acme", user_role="admin",
            policy={"result_scanning": {"enabled": True, "action": "monitor"}})
    assert out["blocked"] is False
    assert out["sanitized_output"] == "out"


@pytest.mark.asyncio
async def test_policy_can_skip_scanning_a_trusted_server():
    ran = []

    class _Guard:
        async def check(self, content, context):
            return type("R", (), {"passed": True, "action": "pass", "details": {}})()

    class _Inj:
        def scan_enabled(self):
            return True  # env says scan everything

        async def check(self, content, context):
            ran.append(1)
            return type("R", (), {"passed": True, "action": "pass", "details": {}})()

    with patch.object(enf, "ToolOutputSanitizationGuardrail", lambda: _Guard()), \
         patch.object(enf, "IndirectInjectionGuardrail", lambda: _Inj()):
        await enf.sanitize_tool_result(
            "t", "out", tenant_id="acme", user_role="admin",
            policy={"result_scanning": {"enabled": False}})

    assert ran == []


@pytest.mark.asyncio
async def test_without_policy_the_env_still_decides():
    g, i, m = _patched(scan_enabled=False, detected=True)
    with g, i, m:
        out = await enf.sanitize_tool_result("t", "out", tenant_id="acme",
                                             user_role="admin")
    assert out["blocked"] is False  # env scan off -> guard never ran
