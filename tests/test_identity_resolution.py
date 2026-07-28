"""Identity provenance for authorization decisions.

`resolve_identity()` must return exactly what the header-reading code returned —
it is a seam, not a behaviour change — while reporting where each value came
from. These tests pin both halves: the values (so nothing breaks) and the
sources (so the audit is truthful).
"""
from types import SimpleNamespace

import pytest

from core.identity import IdentityTuple
from core.identity_resolution import (
    SOURCE_AGENT_TOKEN, SOURCE_BODY, SOURCE_HEADER, SOURCE_NONE, SOURCE_OIDC,
    resolve_identity,
)


def _req(headers=None, identity=None):
    return SimpleNamespace(headers=headers or {}, state=SimpleNamespace(identity=identity))


def _tuple(agent_id="signed-bot", method="agent_token", trust="high"):
    return IdentityTuple(
        user_sub="u1", agent_id=agent_id, agent_instance_id="i1", tenant_id="t1",
        build_hash="b" * 64, model_version="m1", session_id="s1",
        trust_level=trust, identity_method=method,
    )


class TestValuesAreUnchanged:
    """The seam must not move any value the old code would have used."""

    def test_header_agent_and_role(self):
        r = resolve_identity(_req({"X-Agent-Key": "bot", "X-User-Role": "support"}))
        assert (r.agent_key, r.user_role) == ("bot", "support")

    def test_body_wins_over_header_for_role(self):
        r = resolve_identity(_req({"X-User-Role": "from-header"}), body_user_role="from-body")
        assert r.user_role == "from-body"

    def test_lowercase_headers_resolve(self):
        r = resolve_identity(_req({"x-agent-key": "bot", "x-user-role": "support"}))
        assert (r.agent_key, r.user_role) == ("bot", "support")

    def test_absent_is_empty_not_none(self):
        r = resolve_identity(_req())
        assert (r.agent_key, r.user_role) == ("", "")

    def test_whitespace_is_stripped(self):
        r = resolve_identity(_req(), body_agent_key="  bot  ", body_user_role="  support  ")
        assert (r.agent_key, r.user_role) == ("bot", "support")

    def test_blank_body_falls_through_to_header(self):
        r = resolve_identity(_req({"X-User-Role": "support"}), body_user_role="   ")
        assert (r.user_role, r.role_source) == ("support", SOURCE_HEADER)


class TestProvenance:
    def test_header_role_is_marked_unverified(self):
        """The finding, pinned: nothing today carries a verified role claim."""
        r = resolve_identity(_req({"X-User-Role": "payments_officer"}))
        assert r.role_source == SOURCE_HEADER
        assert r.role_verified is False

    def test_body_role_is_also_unverified(self):
        r = resolve_identity(_req(), body_user_role="payments_officer")
        assert (r.role_source, r.role_verified) == (SOURCE_BODY, False)

    def test_verified_token_agent_outranks_headers(self):
        r = resolve_identity(
            _req({"X-Agent-Key": "spoofed"}, identity=_tuple(agent_id="signed-bot")),
            body_agent_key="also-spoofed",
        )
        assert r.agent_key == "signed-bot"
        assert (r.agent_source, r.agent_verified) == (SOURCE_AGENT_TOKEN, True)

    def test_oidc_identity_method_maps_to_oidc_source(self):
        r = resolve_identity(_req(identity=_tuple(method="oidc_sa")))
        assert (r.agent_source, r.agent_verified) == (SOURCE_OIDC, True)

    def test_identity_method_and_trust_are_carried(self):
        r = resolve_identity(_req(identity=_tuple(method="mtls", trust="high")))
        assert (r.identity_method, r.trust_level) == ("mtls", "high")

    def test_missing_values_report_none_source(self):
        r = resolve_identity(_req())
        assert (r.agent_source, r.role_source) == (SOURCE_NONE, SOURCE_NONE)


class TestAuditFields:
    def test_audit_carries_both_sources(self):
        r = resolve_identity(_req({"X-User-Role": "admin"}, identity=_tuple()))
        f = r.audit_fields()
        assert f["role_source"] == SOURCE_HEADER
        assert f["agent_source"] == SOURCE_AGENT_TOKEN
        assert f["role_verified"] is False and f["agent_verified"] is True

    def test_audit_fields_are_flat_and_serialisable(self):
        import json
        json.dumps(resolve_identity(_req()).audit_fields())


class TestRobustness:
    @pytest.mark.parametrize("req", [
        SimpleNamespace(),                                    # no headers, no state
        SimpleNamespace(headers={}),                          # no state
        SimpleNamespace(headers={}, state=SimpleNamespace()),  # state without identity
    ])
    def test_degenerate_requests_do_not_raise(self, req):
        """This sits on the guard path. It must never be the thing that 500s."""
        assert resolve_identity(req).agent_key == ""


# ── verified role claims + binding modes ────────────────────────────────────

from core.identity_resolution import (  # noqa: E402
    MODE_OFF, MODE_PREFER, MODE_STRICT, clear_role_binding_cache_for_tests,
    role_binding_mode,
)


@pytest.fixture(autouse=True)
def _clean_binding(monkeypatch):
    monkeypatch.delenv("SHIELD_ROLE_BINDING", raising=False)
    clear_role_binding_cache_for_tests()
    yield
    clear_role_binding_cache_for_tests()


def _tuple_with_roles(roles, method="agent_token"):
    return IdentityTuple(
        user_sub="u1", agent_id="signed-bot", agent_instance_id="i1", tenant_id="t1",
        build_hash="b" * 64, model_version="m1", session_id="s1",
        trust_level="high", identity_method=method, roles=tuple(roles),
    )


class TestMode:
    def test_defaults_to_off(self):
        assert role_binding_mode() == MODE_OFF

    @pytest.mark.parametrize("v,expected", [
        ("prefer", MODE_PREFER), ("strict", MODE_STRICT), ("off", MODE_OFF),
        ("PREFER", MODE_PREFER), ("  strict ", MODE_STRICT),
    ])
    def test_env_values(self, monkeypatch, v, expected):
        monkeypatch.setenv("SHIELD_ROLE_BINDING", v)
        assert role_binding_mode() == expected

    @pytest.mark.parametrize("v", ["1", "true", "on", "yes", "prefer-please", ""])
    def test_unrecognised_env_is_off(self, monkeypatch, v):
        """An unrecognised value must not half-enable an authorization change."""
        monkeypatch.setenv("SHIELD_ROLE_BINDING", v)
        assert role_binding_mode() == MODE_OFF

    def test_env_off_is_a_global_kill_switch(self, monkeypatch):
        """Even with tenant config, off means off — the operator override."""
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "off")
        assert role_binding_mode("any-tenant") == MODE_OFF


class TestClaimIsInertWhenOff:
    def test_claimed_role_is_not_used_by_default(self):
        """The whole non-breaking guarantee: a token may carry roles, and with
        binding off the header still decides exactly as before."""
        r = resolve_identity(
            _req({"X-User-Role": "customer_support"},
                 identity=_tuple_with_roles(["payments_officer"])))
        assert r.user_role == "customer_support"
        assert (r.role_source, r.role_verified) == (SOURCE_HEADER, False)

    def test_claim_is_still_reported_when_unused(self):
        """Visible in the audit before it is enforced — that is how an operator
        sizes the change before switching it on."""
        r = resolve_identity(_req({"X-User-Role": "customer_support"},
                                  identity=_tuple_with_roles(["payments_officer"])))
        assert r.claimed_roles == ("payments_officer",)


class TestPreferMode:
    def test_verified_claim_beats_a_forged_header(self, monkeypatch):
        """The escalation case. A support agent asserts payments_officer; the
        signed claim says customer_support, and the claim wins."""
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        r = resolve_identity(
            _req({"X-User-Role": "payments_officer"},
                 identity=_tuple_with_roles(["customer_support"])))
        assert r.user_role == "customer_support"
        assert (r.role_source, r.role_verified) == (SOURCE_AGENT_TOKEN, True)
        assert r.header_overridden is True

    def test_body_role_is_also_overridden(self, monkeypatch):
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        r = resolve_identity(_req(identity=_tuple_with_roles(["customer_support"])),
                             body_user_role="payments_officer")
        assert r.user_role == "customer_support"

    def test_no_claim_falls_back_to_the_header(self, monkeypatch):
        """prefer is not strict: a credential without a role claim keeps working."""
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        r = resolve_identity(_req({"X-User-Role": "support"}, identity=_tuple()))
        assert (r.user_role, r.role_source) == ("support", SOURCE_HEADER)
        assert r.role_verified is False

    def test_oidc_claim_is_marked_oidc(self, monkeypatch):
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        r = resolve_identity(
            _req(identity=_tuple_with_roles(["payments_officer"], method="oidc_sa")))
        assert (r.role_source, r.role_verified) == (SOURCE_OIDC, True)

    def test_first_role_is_used_deterministically(self, monkeypatch):
        """Multi-role claims must resolve the same way every time — the order
        as issued, never set iteration."""
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        roles = ["payments_officer", "branch_manager", "fraud_analyst"]
        seen = {resolve_identity(_req(identity=_tuple_with_roles(roles))).user_role
                for _ in range(20)}
        assert seen == {"payments_officer"}


class TestAuditReflectsBinding:
    def test_mode_and_verification_are_audited(self, monkeypatch):
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        f = resolve_identity(
            _req({"X-User-Role": "spoofed"},
                 identity=_tuple_with_roles(["customer_support"]))).audit_fields()
        assert f["role_verified"] is True
        assert f["role_binding_mode"] == "prefer"
        assert f["role_source"] == SOURCE_AGENT_TOKEN


# ── roles from a verified OIDC credential (Keycloak shape) ──────────────────

from core.identity_resolution import extract_roles  # noqa: E402


class _WI:
    def __init__(self, claims):
        self.claims = claims


def _req_wl(claims, headers=None):
    st = SimpleNamespace(identity=None, workload_identity=_WI(claims))
    return SimpleNamespace(headers=headers or {}, state=st)


KEYCLOAK = {"iss": "https://kc/realms/bank", "aud": "votal-shield", "sub": "omar",
            "realm_access": {"roles": ["payments_officer", "default-roles-bank"]}}


class TestExtractRoles:
    def test_keycloak_nested_claim(self):
        assert extract_roles(KEYCLOAK, "realm_access.roles")[0] == "payments_officer"

    def test_flat_claim(self):
        assert extract_roles({"roles": ["a", "b"]}, "roles") == ("a", "b")

    def test_single_string_claim(self):
        """Some IdPs issue a scalar rather than a list."""
        assert extract_roles({"role": "analyst"}, "role") == ("analyst",)

    def test_missing_claim_is_empty_not_an_error(self):
        assert extract_roles(KEYCLOAK, "resource_access.shield.roles") == ()

    def test_role_map_renames(self):
        out = extract_roles(KEYCLOAK, "realm_access.roles",
                            {"payments_officer": "payments"})
        assert out[0] == "payments"

    def test_order_is_preserved_and_deduped(self):
        out = extract_roles({"roles": ["b", "a", "b"]}, "roles")
        assert out == ("b", "a")

    @pytest.mark.parametrize("claims", [{}, {"realm_access": None},
                                        {"realm_access": {"roles": None}},
                                        {"realm_access": "not-a-dict"}])
    def test_malformed_claims_do_not_raise(self, claims):
        assert extract_roles(claims, "realm_access.roles") == ()


class TestOIDCRolesOnTheGuardPath:
    def test_ignored_when_binding_is_off(self):
        """Default posture: a verified OIDC role changes nothing."""
        r = resolve_identity(_req_wl(KEYCLOAK, {"X-User-Role": "customer_support"}))
        assert (r.user_role, r.role_verified) == ("customer_support", False)

    def test_used_in_prefer_mode(self, monkeypatch):
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        r = resolve_identity(_req_wl(KEYCLOAK, {"X-User-Role": "spoofed"}))
        assert r.user_role == "payments_officer"
        assert (r.role_source, r.role_verified) == (SOURCE_OIDC, True)

    def test_agent_token_claim_wins_over_oidc(self, monkeypatch):
        """Both present: the agent token is the more specific credential."""
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        st = SimpleNamespace(identity=_tuple_with_roles(["from_token"]),
                             workload_identity=_WI(KEYCLOAK))
        r = resolve_identity(SimpleNamespace(headers={}, state=st))
        assert r.user_role == "from_token"

    def test_no_workload_identity_falls_back_to_header(self, monkeypatch):
        monkeypatch.setenv("SHIELD_ROLE_BINDING", "prefer")
        r = resolve_identity(_req({"X-User-Role": "support"}))
        assert (r.user_role, r.role_verified) == ("support", False)


# ── token binding (proof-of-possession) ─────────────────────────────────────

import base64 as _b64, time as _time  # noqa: E402

from core.identity_resolution import (  # noqa: E402
    BINDING_FAILED, BINDING_OFF, BINDING_UNBOUND, BINDING_VERIFIED,
    BIND_OFF, BIND_OPTIONAL, BIND_REQUIRED, token_binding_mode,
    verify_token_binding,
)

_jwt = pytest.importorskip("jwt")
from core.dpop import clear_jti_store_for_tests, jwk_thumbprint  # noqa: E402


@pytest.fixture
def kp():
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    n = priv.public_key().public_numbers()
    b = lambda i: _b64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("=")
    return priv, {"kty": "EC", "crv": "P-256", "x": b(n.x), "y": b(n.y)}


@pytest.fixture(autouse=True)
def _clean_jti():
    clear_jti_store_for_tests()
    yield
    clear_jti_store_for_tests()


_URL = "https://api.example.com/v1/shield/tool/check"


def _bound_req(kp, *, proof=True, jti=None, url=_URL, method="POST"):
    priv, pub = kp
    claims = {"cnf": {"jkt": jwk_thumbprint(pub)}}
    headers = {}
    if proof:
        headers["DPoP"] = _jwt.encode(
            {"htm": "POST", "htu": _URL, "iat": int(_time.time()),
             "jti": jti or f"j{_time.time_ns()}"},
            priv, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": pub})
    st = SimpleNamespace(identity=None, workload_identity=_WI(claims))
    return SimpleNamespace(headers=headers, state=st, method=method, url=url)


class TestBindingMode:
    def test_defaults_to_off(self, monkeypatch):
        monkeypatch.delenv("SHIELD_TOKEN_BINDING", raising=False)
        assert token_binding_mode() == BIND_OFF

    @pytest.mark.parametrize("v", ["1", "true", "yes", "requiredd", ""])
    def test_unrecognised_is_off(self, monkeypatch, v):
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", v)
        assert token_binding_mode() == BIND_OFF


class TestBindingChecks:
    def test_off_reads_no_header_and_reports_off(self, monkeypatch, kp):
        monkeypatch.delenv("SHIELD_TOKEN_BINDING", raising=False)
        status, _ = verify_token_binding(_bound_req(kp), {"cnf": {"jkt": "x"}})
        assert status == BINDING_OFF

    def test_valid_proof_verifies(self, monkeypatch, kp):
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
        req = _bound_req(kp)
        status, err = verify_token_binding(req, req.state.workload_identity.claims)
        assert (status, err) == (BINDING_VERIFIED, "")

    def test_bound_token_without_a_proof_fails(self, monkeypatch, kp):
        """The stolen-token case: attacker has the token, not the key."""
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
        req = _bound_req(kp, proof=False)
        status, err = verify_token_binding(req, req.state.workload_identity.claims)
        assert status == BINDING_FAILED and "without a DPoP proof" in err

    def test_unbound_token_is_not_a_failure(self, monkeypatch, kp):
        """A token with no cnf is unbound, not broken — that is how migration
        works while some clients still send plain tokens."""
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
        status, _ = verify_token_binding(_bound_req(kp), {"sub": "x"})
        assert status == BINDING_UNBOUND

    def test_replayed_proof_is_refused(self, monkeypatch, kp):
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
        req = _bound_req(kp, jti="fixed-jti")
        claims = req.state.workload_identity.claims
        assert verify_token_binding(req, claims)[0] == BINDING_VERIFIED
        status, err = verify_token_binding(req, claims)
        assert status == BINDING_FAILED and "replayed" in err

    def test_proof_for_a_different_uri_is_refused(self, monkeypatch, kp):
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
        req = _bound_req(kp, url="https://api.example.com/v1/shield/cap/mint")
        status, err = verify_token_binding(req, req.state.workload_identity.claims)
        assert status == BINDING_FAILED and "htu" in err

    def test_check_never_raises(self, monkeypatch):
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
        broken = SimpleNamespace(headers={"DPoP": "not-a-jwt"},
                                 state=SimpleNamespace(), method="POST", url=_URL)
        assert verify_token_binding(broken, {"cnf": {"jkt": "x"}})[0] == BINDING_FAILED


class TestBindingSurfacesOnResolvedIdentity:
    def test_failure_is_flagged_and_audited(self, monkeypatch, kp):
        monkeypatch.setenv("SHIELD_TOKEN_BINDING", "required")
        r = resolve_identity(_bound_req(kp, proof=False))
        assert r.binding_failed is True
        assert r.audit_fields()["token_binding"] == BINDING_FAILED

    def test_off_by_default_does_not_flag(self, monkeypatch, kp):
        monkeypatch.delenv("SHIELD_TOKEN_BINDING", raising=False)
        r = resolve_identity(_bound_req(kp, proof=False))
        assert r.binding_failed is False
