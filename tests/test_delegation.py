"""Agent acting on behalf of a user, and what that means for authorization.

The property being pinned is that a decision carries TWO principals — which
agent, and whose authority — and that neither can be asserted by the caller.
Both tokens verify against the tenant's trusted issuers.

Intersection is not tested here because it is not implemented here: the tool
allowlist already enforces "agent AND role"
(guardrails/agentic/tool/tool_allowlist.py:62). What these tests pin is that the
role fed into that intersection comes from a *verified* user token rather than a
header, which is what makes it mean anything.
"""
import base64
import json
import time
from types import SimpleNamespace

import pytest

jwt = pytest.importorskip("jwt")

from core.delegation import (  # noqa: E402
    HEADER, MODE_OFF, MODE_OPTIONAL, MODE_REQUIRED, actor_from_act_claim,
    delegation_mode, resolve_delegation, verify_user_token,
)
from core.identity_resolution import resolve_identity  # noqa: E402

ISS = "https://kc.example.com/realms/bank"
AUD = "votal-shield"


@pytest.fixture(scope="module")
def rsa():
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    return _rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def _env(monkeypatch, rsa):
    monkeypatch.setenv("SHIELD_DELEGATION", "optional")
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", ISS)
    monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_AUDIENCE", AUD)
    monkeypatch.delenv("SHIELD_ROLE_BINDING", raising=False)
    monkeypatch.delenv("SHIELD_TOKEN_BINDING", raising=False)

    # Resolve the signing key locally rather than fetching a JWKS over the wire.
    import core.workload_identity.providers as prov
    monkeypatch.setattr(prov, "_resolve_signing_key",
                        lambda issuer, token: rsa.public_key())


def _user_token(rsa, *, sub="omar", roles=("payments_officer",), iss=ISS,
                aud=AUD, ttl=300):
    claims = {"iss": iss, "aud": aud, "sub": sub,
              "realm_access": {"roles": list(roles)},
              "iat": int(time.time()), "exp": int(time.time()) + ttl}
    return jwt.encode(claims, rsa, algorithm="RS256")


def _req(rsa=None, token=None, headers=None):
    h = dict(headers or {})
    if token:
        h[HEADER] = token
    return SimpleNamespace(headers=h, state=SimpleNamespace(identity=None),
                           method="POST", url="https://api.example.com/x")


class TestMode:
    def test_defaults_to_off(self, monkeypatch):
        monkeypatch.delenv("SHIELD_DELEGATION", raising=False)
        assert delegation_mode() == MODE_OFF

    @pytest.mark.parametrize("v", ["1", "true", "yes", "requiredd", ""])
    def test_unrecognised_is_off(self, monkeypatch, v):
        monkeypatch.setenv("SHIELD_DELEGATION", v)
        assert delegation_mode() == MODE_OFF

    def test_off_reads_no_header(self, monkeypatch, rsa):
        monkeypatch.setenv("SHIELD_DELEGATION", "off")
        d = resolve_delegation(_req(token=_user_token(rsa)))
        assert (d.present, d.verified) == (False, False)


class TestVerification:
    def test_valid_user_token_is_verified(self, rsa):
        d = verify_user_token(_user_token(rsa))
        assert d.verified is True
        assert d.user_sub == "omar"
        assert d.user_roles == ("payments_officer",)

    def test_untrusted_issuer_is_refused(self, rsa):
        d = verify_user_token(_user_token(rsa, iss="https://evil.example/realms/x"))
        assert d.verified is False and "not allow-listed" in d.error

    def test_wrong_audience_is_refused(self, rsa):
        """A token minted for another service must not be replayable here."""
        d = verify_user_token(_user_token(rsa, aud="some-other-api"))
        assert d.verified is False and d.error

    def test_expired_token_is_refused(self, rsa):
        d = verify_user_token(_user_token(rsa, ttl=-60))
        assert d.verified is False and d.error

    def test_unsigned_garbage_is_refused(self):
        assert verify_user_token("not-a-jwt").verified is False

    def test_oversized_token_is_refused(self):
        d = verify_user_token("a" * 9000)
        assert d.verified is False and "too large" in d.error

    def test_no_issuer_allowlist_refuses_everything(self, monkeypatch, rsa):
        """Without an allowlist, "verified" would only mean "signed by
        somebody" — refuse rather than accept any signed token."""
        monkeypatch.setenv("SHIELD_WORKLOAD_OIDC_ISSUERS", "")
        d = verify_user_token(_user_token(rsa))
        assert d.verified is False and "no trusted issuers" in d.error

    def test_bearer_prefix_is_tolerated(self, rsa):
        d = resolve_delegation(_req(token="Bearer " + _user_token(rsa)))
        assert d.verified is True


class TestOnTheDecision:
    def test_delegated_user_role_is_used(self, rsa):
        """The point: the role comes from the user's signed token, and feeds
        the allowlist's existing agent-AND-role intersection."""
        r = resolve_identity(_req(token=_user_token(rsa),
                                  headers={"X-User-Role": "spoofed_admin"}))
        assert r.user_role == "payments_officer"
        assert r.delegated is True
        assert r.acting_for == "omar"

    def test_forged_header_cannot_override_a_verified_user(self, rsa):
        r = resolve_identity(_req(token=_user_token(rsa, roles=("customer_support",)),
                                  headers={"X-User-Role": "payments_officer"}))
        assert r.user_role == "customer_support"

    def test_unverified_delegation_does_not_grant(self, rsa):
        """A rejected user token must not silently fall back to its claims."""
        r = resolve_identity(_req(token=_user_token(rsa, iss="https://evil.example/x"),
                                  headers={"X-User-Role": "support"}))
        assert r.delegated is False
        assert r.user_role == "support"          # header, as before
        assert r.delegation_error

    def test_audit_records_both_principals(self, rsa):
        f = resolve_identity(_req(token=_user_token(rsa))).audit_fields()
        assert f["acting_for"] == "omar"
        assert f["delegation_verified"] is True

    def test_off_by_default_changes_nothing(self, monkeypatch, rsa):
        monkeypatch.setenv("SHIELD_DELEGATION", "off")
        r = resolve_identity(_req(token=_user_token(rsa),
                                  headers={"X-User-Role": "support"}))
        assert r.user_role == "support"
        assert r.delegated is False


class TestActClaim:
    def test_reads_sub(self):
        assert actor_from_act_claim({"act": {"sub": "agent-payments-bot"}}) == "agent-payments-bot"

    def test_falls_back_to_client_id(self):
        assert actor_from_act_claim({"act": {"client_id": "bot"}}) == "bot"

    @pytest.mark.parametrize("claims", [{}, {"act": None}, {"act": "nope"}, {"act": {}}])
    def test_absent_or_malformed_is_empty(self, claims):
        """Population varies across IdP versions, so this is opportunistic and
        must never be required."""
        assert actor_from_act_claim(claims) == ""
