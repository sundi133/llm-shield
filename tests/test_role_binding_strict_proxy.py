"""`strict_proxy`: a self-asserted role is a role only from a trusted hop.

On a public deployment `strict` is the only safe mode, but it refuses every
caller that legitimately sends X-User-Role — an internal service behind the
gateway, a dev harness, the LiteLLM guardrail hook. `prefer` keeps them working
and leaves the header forgeable by anyone on the internet.

`strict_proxy` distinguishes *who sent the header* using the trusted-proxy
boundary Shield already uses for mTLS and SPIFFE identity.

Spec: docs/spec-proxy-trusted-role-header.md
"""

import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.identity_resolution import (MODE_STRICT_PROXY, SOURCE_BODY,
                                      SOURCE_NONE, SOURCE_OIDC, SOURCE_PROXY,
                                      VERIFIED_SOURCES,
                                      clear_role_binding_cache_for_tests,
                                      resolve_identity, role_binding_mode)

SECRET = "trusted-proxy-secret-value"
PEER_IP = "10.4.0.7"

_ENV_KEYS = (
    "SHIELD_ROLE_BINDING",
    "SHIELD_TRUSTED_PROXY_ONLY",
    "SHIELD_TRUSTED_PROXY_SECRET",
    "SHIELD_TRUSTED_PROXY_IPS",
    "SHIELD_TOKEN_BINDING",
    "SHIELD_DELEGATION",
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    clear_role_binding_cache_for_tests()
    yield
    clear_role_binding_cache_for_tests()


def _request(*, role_header="sre_lead", proxy_token=None, peer=PEER_IP,
             claimed_roles=None):
    headers = {"X-Agent-Key": "bot"}
    if role_header is not None:
        headers["X-User-Role"] = role_header
    if proxy_token is not None:
        headers["X-Shield-Proxy-Token"] = proxy_token

    identity = None
    if claimed_roles is not None:
        identity = SimpleNamespace(
            agent_id="bot", roles=tuple(claimed_roles),
            identity_method="oidc", trust_level="high")

    return SimpleNamespace(
        headers=headers,
        state=SimpleNamespace(identity=identity),
        client=SimpleNamespace(host=peer),
        method="POST",
        url="https://shield.local/guardrails/input",
    )


def _boundary(monkeypatch, *, on=True, secret=SECRET, ips=None):
    if on:
        monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    if secret is not None:
        monkeypatch.setenv("SHIELD_TRUSTED_PROXY_SECRET", secret)
    if ips is not None:
        monkeypatch.setenv("SHIELD_TRUSTED_PROXY_IPS", ips)


def _resolve(monkeypatch, request, *, body_user_role=None,
             mode=MODE_STRICT_PROXY):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", mode)
    clear_role_binding_cache_for_tests()
    return resolve_identity(request, body_user_role=body_user_role)


# ── Happy path ───────────────────────────────────────────────────────────────


def test_trusted_proxy_header_is_accepted(monkeypatch):
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    assert r.user_role == "sre_lead"
    assert r.role_source == SOURCE_PROXY


def test_body_role_takes_precedence_over_the_header(monkeypatch):
    """Body over header, exactly as `off` orders them."""
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(proxy_token=SECRET),
                 body_user_role="oncall_engineer")
    assert r.user_role == "oncall_engineer"
    assert r.role_source == SOURCE_PROXY


def test_audit_tells_vouched_apart_from_verified(monkeypatch):
    """The whole point of a separate source: an auditor must be able to
    separate a proven role from one a proxy vouched for."""
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    fields = r.audit_fields()
    assert fields["role_source"] == SOURCE_PROXY
    assert fields["role_binding_mode"] == MODE_STRICT_PROXY
    assert fields["role_verified"] is False
    assert r.role_verified is False


# ── Refusals: everything that is not a proven hop ────────────────────────────


def test_boundary_disabled_behaves_exactly_like_strict(monkeypatch):
    """The mode is inert unless the boundary is actually enabled.

    Otherwise an operator sets strict_proxy, never configures the boundary, and
    believes they have a control that is doing nothing.
    """
    _boundary(monkeypatch, on=False, secret=SECRET)
    r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    assert r.user_role == ""
    assert r.role_source == SOURCE_NONE


def test_boundary_on_but_nothing_configured_trusts_nobody(monkeypatch):
    """proxy_trust is fail-closed: no secret and no IP list trusts nobody."""
    monkeypatch.setenv("SHIELD_TRUSTED_PROXY_ONLY", "true")
    r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    assert r.user_role == ""


def test_wrong_secret_is_refused(monkeypatch):
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(proxy_token="not-the-secret"))
    assert r.user_role == ""
    assert r.role_source == SOURCE_NONE


def test_missing_secret_header_is_refused(monkeypatch):
    """The forged-header case this mode exists to close."""
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(proxy_token=None))
    assert r.user_role == ""


def test_trusted_peer_with_no_role_header_gets_no_role(monkeypatch):
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(role_header=None, proxy_token=SECRET))
    assert r.user_role == ""
    assert r.role_source == SOURCE_NONE


def test_whitespace_role_is_not_a_role(monkeypatch):
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(role_header="   ", proxy_token=SECRET))
    assert r.user_role == ""
    assert r.role_source == SOURCE_NONE


# ── IP allowlist interaction ─────────────────────────────────────────────────


def test_matching_ip_and_secret_is_accepted(monkeypatch):
    _boundary(monkeypatch, ips="10.4.0.0/24")
    r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    assert r.user_role == "sre_lead"


def test_secret_alone_is_not_enough_when_an_ip_list_is_set(monkeypatch):
    """Both constraints must pass. The secret is authoritative but the IP list,
    when configured, further constrains — an operator who sets it means it."""
    _boundary(monkeypatch, ips="192.168.0.0/24")
    r = _resolve(monkeypatch, _request(proxy_token=SECRET, peer="10.4.0.7"))
    assert r.user_role == ""


# ── Fail-closed on internal failure ──────────────────────────────────────────


def test_missing_proxy_trust_module_refuses(monkeypatch):
    """A missing optional module must not become an open door."""
    _boundary(monkeypatch)
    monkeypatch.setitem(sys.modules, "core.proxy_trust", None)
    r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    assert r.user_role == ""


def test_peer_check_raising_refuses(monkeypatch):
    _boundary(monkeypatch)
    with patch("core.proxy_trust.peer_is_trusted", side_effect=RuntimeError("boom")):
        r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    assert r.user_role == ""


def test_resolution_never_raises(monkeypatch):
    """No role, not a 500. A resolver that throws on the guard path is worse
    than one that denies."""
    _boundary(monkeypatch)
    with patch("core.proxy_trust.trusted_proxy_only", side_effect=RuntimeError("boom")):
        assert _resolve(monkeypatch, _request(proxy_token=SECRET)) is not None


# ── Precedence: a vouched role never beats a proven one ──────────────────────


def test_verified_claim_beats_the_trusted_proxy_header(monkeypatch):
    _boundary(monkeypatch)
    r = _resolve(monkeypatch,
                 _request(proxy_token=SECRET, claimed_roles=("intern",)))
    assert r.user_role == "intern"
    assert r.role_source == SOURCE_OIDC
    assert r.role_verified is True
    assert r.header_overridden is True


def test_verified_delegation_beats_the_trusted_proxy_header(monkeypatch):
    """Delegation short-circuits ahead of every mode, including this one."""
    _boundary(monkeypatch)
    deleg = SimpleNamespace(verified=True, user_roles=("doctor",),
                            user_sub="user-42", error="", present=True)
    with patch("core.delegation.resolve_delegation", return_value=deleg):
        r = _resolve(monkeypatch, _request(proxy_token=SECRET))
    assert r.user_role == "doctor"
    assert r.role_source == SOURCE_OIDC
    assert r.acting_for == "user-42"
    assert r.delegation_verified is True


# ── Invariants a future refactor must not break ──────────────────────────────


def test_proxy_is_not_a_verified_source():
    """Explicit, because promoting it would silently rewrite the meaning of
    role_verified in every audit record that already exists."""
    assert SOURCE_PROXY not in VERIFIED_SOURCES


def test_tenant_config_accepts_the_new_mode(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    fake = SimpleNamespace(get=lambda k: '{"mode": "strict_proxy"}')
    clear_role_binding_cache_for_tests()
    with patch("storage.tenant_store._get_redis", return_value=fake):
        assert role_binding_mode("tenant-a") == MODE_STRICT_PROXY


def test_tenant_config_rejects_garbage(monkeypatch):
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
    fake = SimpleNamespace(get=lambda k: '{"mode": "strict_proxyy"}')
    clear_role_binding_cache_for_tests()
    with patch("storage.tenant_store._get_redis", return_value=fake):
        assert role_binding_mode("tenant-b") == "prefer"


def test_env_off_still_overrides_a_tenant_opting_in(monkeypatch):
    """SHIELD_ROLE_BINDING=off remains the operator kill switch."""
    monkeypatch.setenv("SHIELD_ROLE_BINDING", "off")
    fake = SimpleNamespace(get=lambda k: '{"mode": "strict_proxy"}')
    clear_role_binding_cache_for_tests()
    with patch("storage.tenant_store._get_redis", return_value=fake):
        assert role_binding_mode("tenant-c") == "off"


def test_body_source_constant_unused_by_this_mode(monkeypatch):
    """A body role under strict_proxy is reported as proxy-vouched, not as
    SOURCE_BODY — the warrant is the hop, and the audit should say so."""
    _boundary(monkeypatch)
    r = _resolve(monkeypatch, _request(role_header=None, proxy_token=SECRET),
                 body_user_role="ci_bot")
    assert r.user_role == "ci_bot"
    assert r.role_source == SOURCE_PROXY != SOURCE_BODY
