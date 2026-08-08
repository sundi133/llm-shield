"""What identity the LiteLLM hook forwards to Shield, and what it refuses to.

Shield sitting behind LiteLLM sees the hook as its HTTP client, not the agent.
Only what `_extract_shield_headers` forwards survives, so role binding on that
path is exactly as strong as this function.

Two defects these tests pin down:

  * the forwarded role used to be read from the *caller's* own header, so
    trusting the LiteLLM hop laundered the forgery rather than stopping it.
  * no verified user credential was forwarded at all, so `prefer` and `strict`
    had nothing to verify and every LiteLLM-routed request resolved to no role.

`litellm` is not a declared dependency of this repo (the plugin ships with the
proxy, not with Shield). Rather than skip — which is how this entire surface
came to have no CI coverage at all — the three litellm symbols the plugin
touches are stubbed. See tests/_litellm_stub.py.

Spec: docs/spec-proxy-trusted-role-header.md §9
"""
from types import SimpleNamespace

import pytest

from tests import _litellm_stub

_litellm_stub.install()

from votal_guardrail import VotalGuardrail  # noqa: E402

SECRET = "hop-secret"


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("VOTAL_SHIELD_PROXY_TOKEN", raising=False)
    monkeypatch.delenv("VOTAL_ENFORCE_TOOL_RBAC", raising=False)
    return monkeypatch


def _data(*, headers=None, metadata=None):
    return {
        "proxy_server_request": {"headers": headers or {}},
        "metadata": metadata or {},
    }


def _key(**metadata):
    """A LiteLLM UserAPIKeyAuth stand-in: what the caller actually proved."""
    return SimpleNamespace(metadata=metadata or {}, user_role="proxy_admin")


# ── Tier 1: the verified path ────────────────────────────────────────────────


def test_delegated_user_token_is_forwarded(clean_env):
    """The header that keeps role binding VERIFIED behind LiteLLM.

    Unlike a DPoP proof, a bearer user token is not bound to the HTTP request,
    so Shield can still check its signature after we re-originate the call.
    """
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(headers={"x-on-behalf-of": "eyJhbGc.user.tok"}))
    assert h["x-on-behalf-of"] == "eyJhbGc.user.tok"


def test_delegated_token_can_come_from_metadata(clean_env):
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(metadata={"on_behalf_of": "tok-from-meta"}))
    assert h["x-on-behalf-of"] == "tok-from-meta"


def test_absent_delegated_token_is_not_forwarded_as_empty(clean_env):
    """An empty header is not the same as no header — Shield would read the
    empty string as a present-but-broken credential."""
    g = VotalGuardrail()
    assert "x-on-behalf-of" not in g._extract_shield_headers(_data())


def test_oversized_delegated_token_is_dropped(clean_env):
    """A user token is small. Anything larger is not a credential, and this
    hook must not become a way to push megabytes at Shield per request."""
    g = VotalGuardrail()
    huge = "x" * (VotalGuardrail.MAX_OBO_BYTES + 1)
    assert "x-on-behalf-of" not in g._extract_shield_headers(
        _data(headers={"x-on-behalf-of": huge}))


def test_token_at_exactly_the_limit_is_kept(clean_env):
    g = VotalGuardrail()
    ok = "x" * VotalGuardrail.MAX_OBO_BYTES
    assert g._extract_shield_headers(_data(headers={"x-on-behalf-of": ok}))[
        "x-on-behalf-of"] == ok


def test_agent_token_is_forwarded(clean_env):
    """Verified agent identity beats the x-agent-key string Shield can only
    take our word for. Possession stays unproven on this path."""
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(headers={"x-agent-token": "agent.jwt.sig"}))
    assert h["x-agent-token"] == "agent.jwt.sig"


# ── Tier 2: vouching, and what it must exclude ───────────────────────────────


def test_proxy_token_is_injected_when_configured(clean_env):
    clean_env.setenv("VOTAL_SHIELD_PROXY_TOKEN", SECRET)
    g = VotalGuardrail()
    assert g._extract_shield_headers(_data())["x-shield-proxy-token"] == SECRET


def test_no_proxy_token_means_no_header_at_all(clean_env):
    """Not an empty header. Shield compares with hmac.compare_digest against a
    configured secret; an empty value is a failed compare, but sending nothing
    is the honest signal that this hop makes no claim."""
    g = VotalGuardrail()
    assert "x-shield-proxy-token" not in g._extract_shield_headers(_data())


def test_authenticated_key_role_wins_over_a_conflicting_client_header(clean_env):
    """The core fix. The caller can set any x-user-role it likes; only the role
    attached to the virtual key it actually proved is forwarded."""
    g = VotalGuardrail()
    h = g._extract_shield_headers(
        _data(headers={"x-user-role": "sre_lead"}),
        _key(shield_user_role="intern"),
    )
    assert h["x-user-role"] == "intern"


def test_caller_header_is_dropped_entirely_when_vouching(clean_env):
    """If we assert the hop is trusted, forwarding a caller-supplied role would
    launder the forgery through a hop Shield trusts."""
    clean_env.setenv("VOTAL_SHIELD_PROXY_TOKEN", SECRET)
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(headers={"x-user-role": "sre_lead"}))
    assert "x-user-role" not in h
    assert h["x-shield-proxy-token"] == SECRET


def test_litellm_admin_role_is_never_forwarded(clean_env):
    """UserAPIKeyAuth.user_role is LiteLLM's admin model (proxy_admin,
    internal_user), not the application's RBAC role. Forwarding it would inject
    LiteLLM's vocabulary into Shield's policy matrix."""
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(), _key())  # user_role="proxy_admin"
    assert h.get("x-user-role") != "proxy_admin"
    assert "x-user-role" not in h


# ── Backward compatibility ───────────────────────────────────────────────────


def test_header_role_still_works_when_not_vouching(clean_env):
    """Deployments that have not configured the boundary keep today's
    behaviour exactly."""
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(headers={"x-user-role": "doctor"}))
    assert h["x-user-role"] == "doctor"


def test_metadata_role_still_works(clean_env):
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(metadata={"user_role": "nurse"}))
    assert h["x-user-role"] == "nurse"


def test_existing_headers_are_untouched(clean_env):
    g = VotalGuardrail()
    h = g._extract_shield_headers(_data(
        headers={"x-api-key": "k", "x-agent-key": "bot", "x-tenant-id": "t1"}))
    assert h["x-api-key"] == "k"
    assert h["x-agent-key"] == "bot"
    assert h["x-tenant-id"] == "t1"


def test_missing_key_object_does_not_break_resolution(clean_env):
    """Every call site passes it now, but the parameter defaults to None and a
    LiteLLM version that omits it must not take the guardrail down."""
    g = VotalGuardrail()
    assert g._extract_shield_headers(_data(headers={"x-user-role": "doctor"}),
                                     None)["x-user-role"] == "doctor"


def test_malformed_key_metadata_falls_through(clean_env):
    """A key object whose metadata is not a dict must degrade, not raise."""
    g = VotalGuardrail()
    bad = SimpleNamespace(metadata="not-a-dict")
    h = g._extract_shield_headers(_data(headers={"x-user-role": "doctor"}), bad)
    assert h["x-user-role"] == "doctor"
