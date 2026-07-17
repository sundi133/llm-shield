"""Tests for vault egress materialization + ingress re-tokenization.

The central security property: a secret is substituted only for a destination it
is bound to. A prompt-injected call to any other host receives the inert
placeholder, never the real value.
"""

import base64

import pytest

from core.secret_vault.keyprovider import _reset_provider_for_tests
from core.secret_vault.materialize import (
    _binding_matches,
    materialize_obj,
    materialize_request,
    retokenize,
)
from core.openapi.upstream_call import UpstreamRequest
import storage.vault_store as vs

_TEST_KEK_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()


@pytest.fixture(autouse=True)
def vault_env(monkeypatch):
    monkeypatch.setenv("SECRET_VAULT_ENABLED", "true")
    monkeypatch.setenv("SECRET_VAULT_KEY_PROVIDER", "software")
    monkeypatch.setenv("SECRET_VAULT_KEK", _TEST_KEK_B64)
    _reset_provider_for_tests()
    from storage.tenant_store import _fallback_store
    for k in [k for k in _fallback_store if k.startswith("vault:")]:
        del _fallback_store[k]
    yield
    _reset_provider_for_tests()


# ── binding matcher ─────────────────────────────────────────────────────────

class TestBindingMatch:
    def test_exact_host(self):
        assert _binding_matches("https://api.stripe.com/v1/charges", ["api.stripe.com"])

    def test_exact_host_does_not_cover_subdomain(self):
        # least privilege: binding a host does NOT implicitly cover its subdomains
        assert not _binding_matches("https://eu.api.stripe.com/x", ["api.stripe.com"])

    def test_exact_host_does_not_cover_parent(self):
        assert not _binding_matches("https://api.stripe.com/x", ["stripe.com"])

    def test_leading_dot_covers_subdomain_and_apex(self):
        assert _binding_matches("https://api.stripe.com/x", [".stripe.com"])
        assert _binding_matches("https://stripe.com/x", [".stripe.com"])

    def test_leading_dot_rejects_lookalike(self):
        assert not _binding_matches("https://api.stripe.com.evil.io/x", [".stripe.com"])

    def test_non_matching_host(self):
        assert not _binding_matches("https://attacker.com/x", ["api.stripe.com"])

    def test_sibling_domain_not_matched(self):
        assert not _binding_matches("https://notstripe.com/x", [".stripe.com"])

    def test_bare_host_destination(self):
        assert _binding_matches("api.stripe.com", ["api.stripe.com"])


# ── materialize (the anti-exfil core) ───────────────────────────────────────

class TestMaterialize:
    def _register(self):
        return vs.create_vault_entry(
            "t", "stripe_key", "sk_live_REAL", bindings=["api.stripe.com"],
        )

    def test_substitutes_for_bound_destination(self):
        self._register()
        out = materialize_obj("t", "shield://stripe_key", "https://api.stripe.com/v1")
        assert out == "sk_live_REAL"

    def test_token_form_also_works(self):
        pub = self._register()
        out = materialize_obj("t", pub["token"], "https://api.stripe.com/v1")
        assert out == "sk_live_REAL"

    def test_does_not_substitute_for_other_destination(self):
        # The core security test: exfil attempt to attacker.com gets nothing.
        self._register()
        out = materialize_obj("t", "shield://stripe_key", "https://attacker.com/collect")
        assert out == "shield://stripe_key"
        assert "sk_live_REAL" not in out

    def test_unknown_ref_passes_through(self):
        out = materialize_obj("t", "shield://nope", "https://api.stripe.com")
        assert out == "shield://nope"

    def test_embedded_in_header_string(self):
        self._register()
        out = materialize_obj("t", "Bearer shield://stripe_key", "https://api.stripe.com")
        assert out == "Bearer sk_live_REAL"

    def test_nested_dict_and_list(self):
        self._register()
        payload = {"auth": {"key": "shield://stripe_key"}, "tags": ["shield://stripe_key"]}
        out = materialize_obj("t", payload, "https://api.stripe.com")
        assert out["auth"]["key"] == "sk_live_REAL"
        assert out["tags"] == ["sk_live_REAL"]

    def test_noop_when_vault_disabled(self, monkeypatch):
        self._register()
        monkeypatch.setenv("SECRET_VAULT_ENABLED", "false")
        out = materialize_obj("t", "shield://stripe_key", "https://api.stripe.com")
        assert out == "shield://stripe_key"


# ── materialize_request (real egress object) ────────────────────────────────

class TestMaterializeRequest:
    def _req(self, url):
        return UpstreamRequest(
            method="POST", url=url,
            params={"k": "shield://stripe_key"},
            headers={"Authorization": "Bearer shield://stripe_key"},
            json_body={"nested": {"secret": "shield://stripe_key"}},
        )

    def test_injects_only_for_bound_host(self):
        vs.create_vault_entry("t", "stripe_key", "sk_live_REAL", bindings=["api.stripe.com"])
        req = self._req("https://api.stripe.com/v1/charges")
        materialize_request("t", req)
        assert req.headers["Authorization"] == "Bearer sk_live_REAL"
        assert req.params["k"] == "sk_live_REAL"
        assert req.json_body["nested"]["secret"] == "sk_live_REAL"

    def test_wrong_host_leaves_token_inert(self):
        vs.create_vault_entry("t", "stripe_key", "sk_live_REAL", bindings=["api.stripe.com"])
        req = self._req("https://attacker.com/collect")
        materialize_request("t", req)
        assert req.headers["Authorization"] == "Bearer shield://stripe_key"
        assert "sk_live_REAL" not in str(req.headers) + str(req.params) + str(req.json_body)


# ── retokenize (ingress) ────────────────────────────────────────────────────

class TestRetokenize:
    def test_replaces_leaked_value_with_placeholder(self):
        vs.create_vault_entry("t", "stripe_key", "sk_live_REAL", bindings=["api.stripe.com"])
        out = retokenize("t", {"echo": "your key is sk_live_REAL ok"})
        assert out["echo"] == "your key is shield://stripe_key ok"
        assert "sk_live_REAL" not in str(out)

    def test_noop_when_no_secrets(self):
        assert retokenize("t", {"x": "nothing here"}) == {"x": "nothing here"}


# ── tier-1 tool scoping ─────────────────────────────────────────────────────

class TestToolScoping:
    def _register_scoped(self):
        vs.create_vault_entry(
            "t", "stripe_key", "sk_live_REAL", bindings=["api.stripe.com"],
            tool_ids=["stripe.createCharge"],
        )

    def test_materializes_for_allowed_tool(self):
        self._register_scoped()
        out = materialize_obj("t", "shield://stripe_key", "https://api.stripe.com/v1",
                              tool_id="stripe.createCharge")
        assert out == "sk_live_REAL"

    def test_not_materialized_for_other_tool_even_if_host_matches(self):
        # Host is bound, but a different tool must not be able to use the secret.
        self._register_scoped()
        out = materialize_obj("t", "shield://stripe_key", "https://api.stripe.com/v1",
                              tool_id="stripe.refund")
        assert out == "shield://stripe_key"

    def test_unscoped_secret_ignores_tool_id(self):
        vs.create_vault_entry("t", "k", "V", bindings=["api.stripe.com"])  # no tool_ids
        out = materialize_obj("t", "shield://k", "https://api.stripe.com", tool_id="anything")
        assert out == "V"


# ── MCP tool egress ─────────────────────────────────────────────────────────

class _AllowEnforcer:
    """Always-allow enforcer so the real MCPProxy forward path can be exercised."""
    async def enforce_tool_call(self, name, arguments, **k):
        return {"allowed": True, "risk": "low", "action": "pass",
                "reason": "", "would_block": [], "mode": "enforce"}

    async def sanitize_tool_result(self, name, raw, **k):
        return {"blocked": False, "sanitized_output": raw}

    def filter_tools_for_role(self, tools, **k):
        return tools


class _FakeUpstream:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True}


class TestMcpEgress:
    def test_materialize_helper_binds_to_tool_name(self):
        from core.mcp.proxy_server import _materialize_mcp_args, _retokenize_mcp
        vs.create_vault_entry("t", "gh_token", "ghp_REAL", bindings=["github.create_issue"])
        bound = _materialize_mcp_args("t", "github.create_issue", {"token": "shield://gh_token"})
        assert bound["token"] == "ghp_REAL"
        inert = _materialize_mcp_args("t", "other.tool", {"token": "shield://gh_token"})
        assert inert["token"] == "shield://gh_token"
        assert _retokenize_mcp("t", {"echo": "ghp_REAL"})["echo"] == "shield://gh_token"

    def test_call_tool_materializes_before_forward(self):
        import asyncio
        from core.mcp.proxy_server import MCPProxy
        vs.create_vault_entry("t", "gh_token", "ghp_REAL", bindings=["github.create_issue"])
        up = _FakeUpstream()
        proxy = MCPProxy(up, enforcer=_AllowEnforcer())
        res = asyncio.run(proxy.call_tool(
            "github.create_issue", {"token": "shield://gh_token"},
            agent_key="a", user_role=None, tenant_id="t"))
        assert res["isError"] is False
        assert up.calls[0][1]["token"] == "ghp_REAL"      # real secret reached upstream

    def test_call_tool_wrong_tool_forwards_inert(self):
        import asyncio
        from core.mcp.proxy_server import MCPProxy
        vs.create_vault_entry("t", "gh_token", "ghp_REAL", bindings=["github.create_issue"])
        up = _FakeUpstream()
        proxy = MCPProxy(up, enforcer=_AllowEnforcer())
        asyncio.run(proxy.call_tool(
            "unrelated.tool", {"token": "shield://gh_token"},
            agent_key="a", user_role=None, tenant_id="t"))
        assert up.calls[0][1]["token"] == "shield://gh_token"   # never revealed
