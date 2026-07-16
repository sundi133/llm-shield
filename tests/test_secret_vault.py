"""Tests for the secret vault encryption foundation (PR1).

Covers: envelope crypto round-trip, no-plaintext-at-rest, fail-closed key backend,
store CRUD + binding validation, and the internal-only egress resolve path.
See docs/spec-secret-vault-egress.md.
"""

import base64
import json
import os

import pytest

from core.secret_vault import crypto
from core.secret_vault.keyprovider import (
    SoftwareKeyProvider,
    VaultConfigError,
    _reset_provider_for_tests,
    get_key_provider,
    vault_enabled,
)

# A fixed 32-byte KEK (base64) for deterministic tests.
_TEST_KEK_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()


@pytest.fixture(autouse=True)
def vault_env(monkeypatch):
    """Configure a software KEK and clear cached provider + fallback store."""
    monkeypatch.setenv("SECRET_VAULT_ENABLED", "true")
    monkeypatch.setenv("SECRET_VAULT_KEY_PROVIDER", "software")
    monkeypatch.setenv("SECRET_VAULT_KEK", _TEST_KEK_B64)
    _reset_provider_for_tests()
    from storage.tenant_store import _fallback_store
    for k in [k for k in _fallback_store if k.startswith("vault:")]:
        del _fallback_store[k]
    yield
    _reset_provider_for_tests()


# ── Crypto ────────────────────────────────────────────────────────────────

class TestEnvelopeCrypto:
    def test_round_trip(self):
        provider = get_key_provider()
        enc = crypto.encrypt_value("sk_live_super_secret", provider)
        assert crypto.decrypt_value(enc, provider) == "sk_live_super_secret"

    def test_no_plaintext_in_ciphertext(self):
        provider = get_key_provider()
        enc = crypto.encrypt_value("sk_live_super_secret", provider)
        blob = json.dumps(enc)
        assert "sk_live_super_secret" not in blob
        assert set(enc.keys()) == {"ciphertext", "nonce", "wrapped_dek"}

    def test_unique_nonce_per_encryption(self):
        provider = get_key_provider()
        a = crypto.encrypt_value("same-value", provider)
        b = crypto.encrypt_value("same-value", provider)
        assert a["ciphertext"] != b["ciphertext"]  # semantic security
        assert a["nonce"] != b["nonce"]

    def test_tampered_ciphertext_raises(self):
        provider = get_key_provider()
        enc = crypto.encrypt_value("secret", provider)
        tampered = dict(enc)
        raw = bytearray(base64.b64decode(enc["ciphertext"]))
        raw[0] ^= 0xFF
        tampered["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(Exception):
            crypto.decrypt_value(tampered, provider)

    def test_wrong_kek_cannot_decrypt(self):
        enc = crypto.encrypt_value("secret", get_key_provider())
        other = SoftwareKeyProvider(b"ffffffffffffffffffffffffffffffff")
        with pytest.raises(Exception):
            crypto.decrypt_value(enc, other)


# ── Key provider (fail-closed) ──────────────────────────────────────────────

class TestKeyProvider:
    def test_vault_enabled_flag(self, monkeypatch):
        monkeypatch.setenv("SECRET_VAULT_ENABLED", "false")
        assert vault_enabled() is False
        monkeypatch.setenv("SECRET_VAULT_ENABLED", "on")
        assert vault_enabled() is True

    def test_missing_kek_fails_closed(self, monkeypatch):
        monkeypatch.delenv("SECRET_VAULT_KEK", raising=False)
        _reset_provider_for_tests()
        with pytest.raises(VaultConfigError):
            get_key_provider()

    def test_unimplemented_backend_fails_closed(self, monkeypatch):
        monkeypatch.setenv("SECRET_VAULT_KEY_PROVIDER", "vault-transit")
        _reset_provider_for_tests()
        with pytest.raises(VaultConfigError):
            get_key_provider()

    def test_unknown_backend_fails_closed(self, monkeypatch):
        monkeypatch.setenv("SECRET_VAULT_KEY_PROVIDER", "banana")
        _reset_provider_for_tests()
        with pytest.raises(VaultConfigError):
            get_key_provider()

    def test_kek_from_file(self, monkeypatch, tmp_path):
        keyfile = tmp_path / "kek"
        keyfile.write_bytes(base64.b64decode(_TEST_KEK_B64))
        monkeypatch.setenv("SECRET_VAULT_KEK", str(keyfile))
        _reset_provider_for_tests()
        provider = get_key_provider()
        enc = crypto.encrypt_value("v", provider)
        assert crypto.decrypt_value(enc, provider) == "v"


# ── Store ───────────────────────────────────────────────────────────────────

@pytest.mark.usefixtures("vault_env")
class TestVaultStore:
    def _store(self):
        import storage.vault_store as vs
        return vs

    def test_create_and_list_public_only(self):
        vs = self._store()
        pub = vs.create_vault_entry(
            "t1", "stripe_key", "sk_live_x", bindings=["api.stripe.com"],
        )
        # public view carries metadata, never crypto material or the value
        assert pub["ref"] == "stripe_key"
        assert pub["token"].startswith("svlt_")
        assert pub["bindings"] == ["api.stripe.com"]
        for f in ("ciphertext", "nonce", "wrapped_dek"):
            assert f not in pub

        listing = vs.list_vault_entries("t1")
        assert len(listing) == 1
        assert "ciphertext" not in listing[0]

    def test_value_not_stored_plaintext(self):
        vs = self._store()
        vs.create_vault_entry("t1", "k", "TOP-SECRET-VALUE", bindings=["h"])
        from storage.tenant_store import _fallback_store
        blob = _fallback_store["vault:t1"]
        assert "TOP-SECRET-VALUE" not in blob

    def test_resolve_secret_value_round_trip(self):
        vs = self._store()
        vs.create_vault_entry("t1", "k", "the-real-value", bindings=["h"])
        assert vs.resolve_secret_value("t1", "k") == "the-real-value"
        assert vs.resolve_secret_value("t1", "missing") is None

    def test_binding_required(self):
        vs = self._store()
        with pytest.raises(ValueError):
            vs.create_vault_entry("t1", "k", "v", bindings=[])

    def test_empty_value_rejected(self):
        vs = self._store()
        with pytest.raises(ValueError):
            vs.create_vault_entry("t1", "k", "", bindings=["h"])

    def test_oversized_value_rejected(self):
        vs = self._store()
        with pytest.raises(ValueError):
            vs.create_vault_entry("t1", "k", "x" * 9000, bindings=["h"])

    def test_bad_mode_rejected(self):
        vs = self._store()
        with pytest.raises(ValueError):
            vs.create_vault_entry("t1", "k", "v", bindings=["h"], mode="nope")

    def test_upsert_keeps_token_and_created_at(self):
        vs = self._store()
        first = vs.create_vault_entry("t1", "k", "v1", bindings=["h"])
        second = vs.create_vault_entry("t1", "k", "v2", bindings=["h2"], mode="token")
        assert second["token"] == first["token"]          # stable handle
        assert second["created_at"] == first["created_at"]
        assert vs.resolve_secret_value("t1", "k") == "v2"  # value replaced
        assert len(vs.list_vault_entries("t1")) == 1       # no duplicate
        assert second["bindings"] == ["h2"]

    def test_delete(self):
        vs = self._store()
        vs.create_vault_entry("t1", "k", "v", bindings=["h"])
        assert vs.delete_vault_entry("t1", "k") is True
        assert vs.delete_vault_entry("t1", "k") is False
        assert vs.list_vault_entries("t1") == []

    def test_tenant_isolation(self):
        vs = self._store()
        vs.create_vault_entry("t1", "k", "t1-value", bindings=["h"])
        vs.create_vault_entry("t2", "k", "t2-value", bindings=["h"])
        assert vs.resolve_secret_value("t1", "k") == "t1-value"
        assert vs.resolve_secret_value("t2", "k") == "t2-value"
        assert len(vs.list_vault_entries("t1")) == 1

    def test_dek_cache_avoids_repeat_unwrap(self, monkeypatch):
        from core.secret_vault import keyprovider
        vs = self._store()
        vs.create_vault_entry("t1", "k", "V", bindings=["h"])
        keyprovider._dek_cache.clear()
        prov = keyprovider.get_key_provider()
        calls = {"n": 0}
        orig = prov.unwrap_dek

        def counting(w):
            calls["n"] += 1
            return orig(w)

        monkeypatch.setattr(prov, "unwrap_dek", counting)
        assert vs.resolve_secret_value("t1", "k") == "V"
        assert vs.resolve_secret_value("t1", "k") == "V"   # second read
        assert calls["n"] == 1                             # served from DEK cache
