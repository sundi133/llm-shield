"""Tests for capability tokens (AuthZ artifact layer)."""

import time

import pytest

from core.capabilities import (
    CAP_MAX_TTL_SECONDS,
    CapabilityError,
    clear_nonce_store_for_tests,
    mint_cap,
    reset_cap_signer_cache_for_tests,
    verify_cap,
)
from core.identity import IdentityTuple
from storage.revocation import clear_all_for_tests, revoke_jti


@pytest.fixture
def identity():
    return IdentityTuple(
        user_sub="user-1",
        agent_id="billing-bot",
        agent_instance_id="inst-1",
        tenant_id="t1",
        build_hash="b",
        model_version="m",
        session_id="s",
    )


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.delenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", raising=False)
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    yield
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()


class TestMintVerifyRoundtrip:
    def test_roundtrip(self, identity):
        cap = mint_cap(
            identity=identity, tool="send_email", resource="user/42/inbox",
            scope=["to:user@example.com"], clearance_max="internal",
        )
        claims = verify_cap(cap, expected_tool="send_email")
        assert claims.tool == "send_email"
        assert claims.resource == "user/42/inbox"
        assert claims.user_sub == "user-1"
        assert claims.agent_id == "billing-bot"
        assert claims.clearance_max == "internal"
        assert "to:user@example.com" in claims.scope

    def test_identity_bound_into_cap(self, identity):
        cap = mint_cap(identity=identity, tool="db_query", resource="orders")
        claims = verify_cap(cap, expected_tool="db_query")
        # The cap carries the AuthN identity tuple, baked in at mint time
        assert claims.user_sub == identity.user_sub
        assert claims.agent_instance_id == identity.agent_instance_id
        assert claims.tenant_id == identity.tenant_id


class TestTTL:
    def test_rejects_ttl_too_long(self, identity):
        with pytest.raises(CapabilityError, match="ttl_seconds"):
            mint_cap(
                identity=identity, tool="t", resource="r",
                ttl_seconds=CAP_MAX_TTL_SECONDS + 1,
            )

    def test_rejects_ttl_zero(self, identity):
        with pytest.raises(CapabilityError, match="ttl_seconds"):
            mint_cap(identity=identity, tool="t", resource="r", ttl_seconds=0)

    def test_expired_cap_rejected(self, identity):
        cap = mint_cap(identity=identity, tool="t", resource="r", ttl_seconds=1)
        import core.capabilities as mod
        original = mod.time.time
        try:
            mod.time.time = lambda: int(original()) + 30
            with pytest.raises(CapabilityError, match="expired"):
                verify_cap(cap, expected_tool="t")
        finally:
            mod.time.time = original


class TestToolBinding:
    def test_tool_mismatch_rejected(self, identity):
        cap = mint_cap(identity=identity, tool="db_query", resource="orders")
        with pytest.raises(CapabilityError, match="tool mismatch"):
            verify_cap(cap, expected_tool="send_email")

    def test_resource_mismatch_rejected(self, identity):
        cap = mint_cap(identity=identity, tool="db_query", resource="orders")
        with pytest.raises(CapabilityError, match="resource mismatch"):
            verify_cap(cap, expected_tool="db_query", expected_resource="users")

    def test_resource_check_skipped_when_not_provided(self, identity):
        cap = mint_cap(identity=identity, tool="db_query", resource="orders")
        # Not passing expected_resource: just tool check
        claims = verify_cap(cap, expected_tool="db_query")
        assert claims.resource == "orders"


class TestNonceOneShot:
    def test_first_use_succeeds(self, identity):
        cap = mint_cap(identity=identity, tool="t", resource="r")
        claims = verify_cap(cap, expected_tool="t")
        assert claims.tool == "t"

    def test_replay_rejected(self, identity):
        cap = mint_cap(identity=identity, tool="t", resource="r")
        verify_cap(cap, expected_tool="t")  # burns nonce
        with pytest.raises(CapabilityError, match="replay"):
            verify_cap(cap, expected_tool="t")

    def test_no_burn_allows_repeated_verify(self, identity):
        """burn_nonce=False is for diagnostic/dry-run verification."""
        cap = mint_cap(identity=identity, tool="t", resource="r")
        c1 = verify_cap(cap, expected_tool="t", burn_nonce=False)
        c2 = verify_cap(cap, expected_tool="t", burn_nonce=False)
        assert c1.nonce == c2.nonce


class TestSignature:
    def test_tampered_payload_rejected(self, identity):
        cap = mint_cap(identity=identity, tool="t", resource="r")
        parts = cap.split(".")
        # Flip a char in the payload segment (middle part)
        payload = parts[1]
        mid = len(payload) // 2
        flip = "X" if payload[mid] != "X" else "Y"
        bad_payload = payload[:mid] + flip + payload[mid + 1:]
        with pytest.raises(CapabilityError):
            verify_cap(f"{parts[0]}.{bad_payload}.{parts[2]}", expected_tool="t")

    def test_tampered_signature_rejected(self, identity):
        cap = mint_cap(identity=identity, tool="t", resource="r")
        parts = cap.split(".")
        # Flip a char in the signature segment (last part)
        sig = parts[2]
        mid = len(sig) // 2
        flip = "X" if sig[mid] != "X" else "Y"
        bad_sig = sig[:mid] + flip + sig[mid + 1:]
        with pytest.raises(CapabilityError, match="invalid"):
            verify_cap(f"{parts[0]}.{parts[1]}.{bad_sig}", expected_tool="t")


class TestRevocation:
    def test_revoked_cap_id_rejected(self, identity):
        cap = mint_cap(identity=identity, tool="t", resource="r")
        # Peek the cap_id without burning the nonce
        claims = verify_cap(cap, expected_tool="t", burn_nonce=False)
        # Mint a fresh one and revoke its id
        cap2 = mint_cap(identity=identity, tool="t", resource="r")
        claims2 = verify_cap(cap2, expected_tool="t", burn_nonce=False)
        revoke_jti(claims2.cap_id)
        with pytest.raises(CapabilityError, match="revoked"):
            verify_cap(cap2, expected_tool="t")


class TestClearance:
    def test_invalid_clearance_rejected(self, identity):
        with pytest.raises(CapabilityError, match="clearance_max"):
            mint_cap(identity=identity, tool="t", resource="r", clearance_max="ultra-secret")

    def test_known_clearance_levels(self, identity):
        for lvl in ("public", "internal", "confidential", "restricted"):
            cap = mint_cap(identity=identity, tool="t", resource="r", clearance_max=lvl)
            claims = verify_cap(cap, expected_tool="t")
            assert claims.clearance_max == lvl


class TestAudienceIssuerBinding:
    """H1: caps carry iss + aud, distinct from agent-token aud."""

    def test_default_cap_aud_is_distinct_from_agent_aud(self, identity):
        from core.agent_tokens import DEFAULT_AGENT_AUDIENCE, decode_claims_unverified
        cap = mint_cap(identity=identity, tool="t", resource="r")
        claims = decode_claims_unverified(cap)
        assert claims["aud"] == "shield-capabilities"
        # Must differ from the agent-token default aud, otherwise H1 is moot
        assert claims["aud"] != DEFAULT_AGENT_AUDIENCE

    def test_cap_audience_mismatch_rejected(self, identity, monkeypatch):
        monkeypatch.setenv("SHIELD_CAP_AUDIENCE", "aud-A")
        cap = mint_cap(identity=identity, tool="t", resource="r")
        monkeypatch.setenv("SHIELD_CAP_AUDIENCE", "aud-B")
        with pytest.raises(CapabilityError, match="cap audience mismatch"):
            verify_cap(cap, expected_tool="t")

    def test_cap_issuer_mismatch_rejected(self, identity, monkeypatch):
        monkeypatch.setenv("SHIELD_ISSUER", "shield-staging")
        cap = mint_cap(identity=identity, tool="t", resource="r")
        monkeypatch.setenv("SHIELD_ISSUER", "shield-prod")
        with pytest.raises(CapabilityError, match="cap issuer mismatch"):
            verify_cap(cap, expected_tool="t")


class TestCapRetiredKids:
    """M2 for caps: cap signing kids in SHIELD_RETIRED_KIDS must not verify."""

    def test_retired_cap_kid_rejected(self, identity, monkeypatch):
        cap = mint_cap(identity=identity, tool="t", resource="r")
        monkeypatch.setenv("SHIELD_RETIRED_KIDS", "cap-env,other")
        with pytest.raises(CapabilityError, match="cap kid retired: cap-env"):
            verify_cap(cap, expected_tool="t")


class TestMissingFields:
    def test_tool_required(self, identity):
        with pytest.raises(CapabilityError):
            mint_cap(identity=identity, tool="", resource="r")

    def test_resource_required(self, identity):
        with pytest.raises(CapabilityError):
            mint_cap(identity=identity, tool="t", resource="")
