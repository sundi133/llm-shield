"""Tests for the pluggable signer backend dispatcher."""

import os
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.agent_tokens import (
    TokenError,
    mint_agent_token,
    reset_signer_cache_for_tests,
    verify_agent_token,
)
from core.capabilities import (
    CapabilityError,
    clear_nonce_store_for_tests,
    mint_cap,
    reset_cap_signer_cache_for_tests,
    verify_cap,
)
from core.identity import IdentityTuple
from core.signers import (
    LocalEd25519Signer,
    PKCS11Signer,
    SignerError,
    VaultTransitSigner,
    build_signer,
)
from storage.revocation import clear_all_for_tests


VALID_CLAIMS = dict(
    user_sub="u", agent_id="a", agent_instance_id="i", tenant_id="t",
    build_hash="b", model_version="m", session_id="s",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    for var in (
        "SHIELD_SIGNER_BACKEND", "SHIELD_SIGNER_BACKEND_AGENT", "SHIELD_SIGNER_BACKEND_CAP",
        "SHIELD_AGENT_TOKEN_PRIVATE_KEY", "SHIELD_CAP_TOKEN_PRIVATE_KEY",
        "SHIELD_PKCS11_LIBRARY", "SHIELD_PKCS11_TOKEN_LABEL", "SHIELD_PKCS11_KEY_LABEL",
        "SHIELD_PKCS11_USER_PIN_FILE", "SHIELD_PKCS11_PUBLIC_KEY",
        "SHIELD_VAULT_ADDR", "SHIELD_VAULT_TOKEN_FILE", "SHIELD_VAULT_TRANSIT_KEY",
        "SHIELD_VAULT_PUBLIC_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    yield
    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()


# ── Dispatcher ──────────────────────────────────────────────────────────


class TestBuildSigner:
    def test_default_is_local(self):
        s = build_signer(kid="k1")
        assert isinstance(s, LocalEd25519Signer)
        assert s.kid == "k1"

    def test_local_explicit(self, monkeypatch):
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
        s = build_signer(kid="k1")
        assert isinstance(s, LocalEd25519Signer)

    def test_unknown_backend_rejected(self, monkeypatch):
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "ozymandias")
        with pytest.raises(SignerError, match="unknown signer backend"):
            build_signer(kid="k1")

    def test_pkcs11_routes_to_stub(self, monkeypatch):
        # Provide a valid 32-byte pubkey file plus other required vars,
        # then assert the stub raises NotImplementedError at init.
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 32)
            pk_path = f.name
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "pkcs11")
        monkeypatch.setenv("SHIELD_PKCS11_PUBLIC_KEY", pk_path)
        monkeypatch.setenv("SHIELD_PKCS11_LIBRARY", "/x/libsofthsm2.so")
        monkeypatch.setenv("SHIELD_PKCS11_TOKEN_LABEL", "tok")
        monkeypatch.setenv("SHIELD_PKCS11_KEY_LABEL", "key")
        monkeypatch.setenv("SHIELD_PKCS11_USER_PIN_FILE", "/x/pin")
        with pytest.raises(NotImplementedError, match="PKCS11Signer"):
            build_signer(kid="k1")
        os.unlink(pk_path)

    def test_vault_routes_to_stub(self, monkeypatch):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 32)
            pk_path = f.name
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "vault")
        monkeypatch.setenv("SHIELD_VAULT_PUBLIC_KEY", pk_path)
        monkeypatch.setenv("SHIELD_VAULT_ADDR", "https://vault.internal:8200")
        monkeypatch.setenv("SHIELD_VAULT_TOKEN_FILE", "/x/token")
        monkeypatch.setenv("SHIELD_VAULT_TRANSIT_KEY", "shield-agent")
        with pytest.raises(NotImplementedError, match="VaultTransitSigner"):
            build_signer(kid="k1")
        os.unlink(pk_path)


# ── Stub config validation runs before NotImplementedError ──────────────


class TestPKCS11Stub:
    def test_missing_public_key_path(self):
        with pytest.raises(SignerError, match="SHIELD_PKCS11_PUBLIC_KEY"):
            PKCS11Signer(kid="k")

    def test_wrong_pubkey_length(self, monkeypatch):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 17)  # not 32 bytes
            path = f.name
        monkeypatch.setenv("SHIELD_PKCS11_PUBLIC_KEY", path)
        with pytest.raises(SignerError, match="32 raw bytes"):
            PKCS11Signer(kid="k")
        os.unlink(path)

    def test_missing_other_envs(self, monkeypatch):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 32)
            path = f.name
        monkeypatch.setenv("SHIELD_PKCS11_PUBLIC_KEY", path)
        # No library / token / key / pin
        with pytest.raises(SignerError, match="SHIELD_PKCS11_"):
            PKCS11Signer(kid="k")
        os.unlink(path)


class TestVaultStub:
    def test_missing_public_key_path(self):
        with pytest.raises(SignerError, match="SHIELD_VAULT_PUBLIC_KEY"):
            VaultTransitSigner(kid="k")

    def test_missing_other_envs(self, monkeypatch):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 32)
            path = f.name
        monkeypatch.setenv("SHIELD_VAULT_PUBLIC_KEY", path)
        with pytest.raises(SignerError, match="SHIELD_VAULT_"):
            VaultTransitSigner(kid="k")
        os.unlink(path)


# ── Local signer behavior ───────────────────────────────────────────────


class TestLocalSigner:
    def test_ephemeral_when_no_key(self):
        s = LocalEd25519Signer(kid="k")
        sig = s.sign(b"hi")
        s.verify(b"hi", sig)  # no raise

    def test_uses_explicit_hex(self):
        sk = Ed25519PrivateKey.generate()
        hex_key = sk.private_bytes_raw().hex()
        s = LocalEd25519Signer(kid="k", private_key_hex=hex_key)
        sig = s.sign(b"payload")
        s.verify(b"payload", sig)

    def test_invalid_hex_raises(self):
        with pytest.raises(SignerError, match="invalid Ed25519"):
            LocalEd25519Signer(kid="k", private_key_hex="not-hex-data")

    def test_reads_from_env_var(self, monkeypatch):
        sk = Ed25519PrivateKey.generate()
        monkeypatch.setenv("MY_KEY", sk.private_bytes_raw().hex())
        s = LocalEd25519Signer(kid="k", env_var="MY_KEY")
        sig = s.sign(b"x")
        s.verify(b"x", sig)


# ── Agent token / cap signer wiring uses the dispatcher ────────────────


class TestAgentTokensThroughDispatcher:
    def test_default_local_still_works(self):
        token = mint_agent_token(**VALID_CLAIMS)
        identity = verify_agent_token(token)
        assert isinstance(identity, IdentityTuple)

    def test_pkcs11_backend_fails_loudly(self, monkeypatch):
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND_AGENT", "pkcs11")
        # No PKCS11 env -> SignerError -> TokenError
        with pytest.raises(TokenError, match="misconfigured"):
            mint_agent_token(**VALID_CLAIMS)

    def test_unknown_backend_fails_loudly(self, monkeypatch):
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND_AGENT", "starlight")
        with pytest.raises(TokenError, match="unknown signer backend"):
            mint_agent_token(**VALID_CLAIMS)

    def test_independent_backends_per_token_type(self, monkeypatch):
        """SHIELD_SIGNER_BACKEND_AGENT and SHIELD_SIGNER_BACKEND_CAP are independent."""
        # Agent stays local, cap goes pkcs11 (and explodes).
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND_AGENT", "local")
        monkeypatch.setenv("SHIELD_SIGNER_BACKEND_CAP", "pkcs11")
        # Agent token still mints fine
        token = mint_agent_token(**VALID_CLAIMS)
        identity = verify_agent_token(token)
        # Cap mint fails because cap signer is pkcs11 and unconfigured
        with pytest.raises(CapabilityError, match="misconfigured"):
            mint_cap(identity=identity, tool="t", resource="r")
