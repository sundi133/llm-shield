"""Tests for agent tokens (AuthN layer)."""

import os
import time

import pytest

from core.agent_tokens import (
    DEFAULT_TOKEN_TTL_SECONDS,
    MAX_TOKEN_TTL_SECONDS,
    TokenError,
    decode_claims_unverified,
    get_signer,
    mint_agent_token,
    reset_signer_cache_for_tests,
    verify_agent_token,
)
from core.identity import IdentityTuple
from storage.revocation import (
    clear_all_for_tests,
    revoke_instance,
    revoke_jti,
    revoke_user,
)


VALID_CLAIMS = dict(
    user_sub="user-42",
    agent_id="billing-bot",
    agent_instance_id="inst-abc-1",
    tenant_id="tenant-1",
    build_hash="sha256:deadbeef",
    model_version="claude-opus-4.7",
    session_id="sess-123",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Each test gets a fresh signer and clean revocation store."""
    monkeypatch.delenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_AGENT_ALLOWED_BUILDS", raising=False)
    reset_signer_cache_for_tests()
    clear_all_for_tests()
    # Force redis-less path so revocation tests are deterministic
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    yield
    reset_signer_cache_for_tests()
    clear_all_for_tests()


class TestMintAndVerify:
    def test_roundtrip(self):
        token = mint_agent_token(**VALID_CLAIMS)
        identity = verify_agent_token(token)
        assert isinstance(identity, IdentityTuple)
        assert identity.user_sub == "user-42"
        assert identity.agent_id == "billing-bot"
        assert identity.agent_instance_id == "inst-abc-1"
        assert identity.tenant_id == "tenant-1"
        assert identity.trust_level == "high"
        assert identity.identity_method == "agent_token"

    def test_carries_parent_agent_id(self):
        token = mint_agent_token(parent_agent_id="orchestrator", **VALID_CLAIMS)
        identity = verify_agent_token(token)
        assert identity.parent_agent_id == "orchestrator"

    def test_decode_unverified_does_not_check_sig(self):
        token = mint_agent_token(**VALID_CLAIMS)
        # Corrupt the signature half but keep payload intact
        payload, _ = token.split(".", 1)
        bogus = payload + ".AAAA"
        claims = decode_claims_unverified(bogus)
        assert claims["user_sub"] == "user-42"


class TestRequiredClaims:
    def test_rejects_missing_user_sub(self):
        bad = dict(VALID_CLAIMS, user_sub="")
        with pytest.raises(TokenError, match="missing required claim"):
            mint_agent_token(**bad)

    def test_rejects_missing_session_id(self):
        bad = dict(VALID_CLAIMS, session_id="")
        with pytest.raises(TokenError, match="missing required claim"):
            mint_agent_token(**bad)


class TestTTL:
    def test_rejects_ttl_too_long(self):
        with pytest.raises(TokenError, match="ttl_seconds"):
            mint_agent_token(ttl_seconds=MAX_TOKEN_TTL_SECONDS + 1, **VALID_CLAIMS)

    def test_rejects_ttl_zero(self):
        with pytest.raises(TokenError, match="ttl_seconds"):
            mint_agent_token(ttl_seconds=0, **VALID_CLAIMS)

    def test_expired_token_rejected(self):
        # Mint with the minimum positive TTL, then jump time forward
        token = mint_agent_token(ttl_seconds=1, **VALID_CLAIMS)
        # Sleep just past expiry + clock-skew window
        time.sleep(1.2)
        # Patch time so the test is reliable even on fast hosts
        import core.agent_tokens as mod
        original = mod.time.time
        try:
            mod.time.time = lambda: int(original()) + 30
            with pytest.raises(TokenError, match="expired"):
                verify_agent_token(token)
        finally:
            mod.time.time = original


class TestSignatureIntegrity:
    def test_rejects_tampered_payload(self):
        token = mint_agent_token(**VALID_CLAIMS)
        payload, sig = token.split(".", 1)
        # Flip a char in the middle of the payload (safe from base64 padding edge)
        mid = len(payload) // 2
        flip = "X" if payload[mid] != "X" else "Y"
        tampered_payload = payload[:mid] + flip + payload[mid + 1:]
        bad = f"{tampered_payload}.{sig}"
        with pytest.raises(TokenError):
            verify_agent_token(bad)

    def test_rejects_tampered_signature(self):
        token = mint_agent_token(**VALID_CLAIMS)
        payload, sig = token.split(".", 1)
        mid = len(sig) // 2
        flip = "X" if sig[mid] != "X" else "Y"
        bad_sig = sig[:mid] + flip + sig[mid + 1:]
        with pytest.raises(TokenError, match="invalid signature"):
            verify_agent_token(f"{payload}.{bad_sig}")

    def test_rejects_malformed_token(self):
        with pytest.raises(TokenError, match="malformed"):
            verify_agent_token("not-a-token")

    def test_rejects_empty_token(self):
        with pytest.raises(TokenError):
            verify_agent_token("")


class TestRevocation:
    def test_revoked_instance_rejected(self):
        token = mint_agent_token(**VALID_CLAIMS)
        revoke_instance("inst-abc-1")
        with pytest.raises(TokenError, match="instance_id revoked"):
            verify_agent_token(token)

    def test_revoked_user_rejected(self):
        token = mint_agent_token(**VALID_CLAIMS)
        revoke_user("user-42")
        with pytest.raises(TokenError, match="user revoked"):
            verify_agent_token(token)

    def test_revoked_jti_rejected(self):
        token = mint_agent_token(**VALID_CLAIMS)
        claims = decode_claims_unverified(token)
        revoke_jti(claims["jti"])
        with pytest.raises(TokenError, match="token revoked"):
            verify_agent_token(token)

    def test_revoking_one_does_not_revoke_others(self):
        t1 = mint_agent_token(**VALID_CLAIMS)
        t2 = mint_agent_token(**dict(VALID_CLAIMS, agent_instance_id="inst-other"))
        revoke_instance("inst-abc-1")
        with pytest.raises(TokenError):
            verify_agent_token(t1)
        # t2 still works
        identity = verify_agent_token(t2)
        assert identity.agent_instance_id == "inst-other"


class TestBuildAllowlist:
    def test_no_allowlist_accepts_any_build(self, monkeypatch):
        monkeypatch.delenv("SHIELD_AGENT_ALLOWED_BUILDS", raising=False)
        token = mint_agent_token(**dict(VALID_CLAIMS, build_hash="anything"))
        identity = verify_agent_token(token)
        assert identity.build_hash == "anything"

    def test_allowlist_blocks_unknown_build(self, monkeypatch):
        token = mint_agent_token(**dict(VALID_CLAIMS, build_hash="sha256:bad"))
        monkeypatch.setenv("SHIELD_AGENT_ALLOWED_BUILDS", "sha256:good1,sha256:good2")
        with pytest.raises(TokenError, match="build_hash not allowed"):
            verify_agent_token(token)

    def test_allowlist_passes_known_build(self, monkeypatch):
        token = mint_agent_token(**dict(VALID_CLAIMS, build_hash="sha256:good1"))
        monkeypatch.setenv("SHIELD_AGENT_ALLOWED_BUILDS", "sha256:good1,sha256:good2")
        identity = verify_agent_token(token)
        assert identity.build_hash == "sha256:good1"


class TestKeyFromEnv:
    def test_uses_env_key_when_present(self, monkeypatch):
        # Generate a deterministic key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.generate()
        raw = sk.private_bytes_raw().hex()
        monkeypatch.setenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raw)
        monkeypatch.setenv("SHIELD_AGENT_TOKEN_KID", "prod-key-1")
        reset_signer_cache_for_tests()

        signer = get_signer()
        assert signer.kid == "prod-key-1"

        token = mint_agent_token(**VALID_CLAIMS)
        identity = verify_agent_token(token)
        assert identity.user_sub == "user-42"

    def test_invalid_env_key_raises(self, monkeypatch):
        monkeypatch.setenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "not-hex")
        reset_signer_cache_for_tests()
        with pytest.raises(TokenError, match="misconfigured"):
            get_signer()
