"""Key management for the secret vault — on-prem only, no cloud KMS.

A KeyProvider wraps/unwraps per-secret data-encryption keys (DEKs) with a
key-encryption key (KEK) that never touches the datastore. Backends:

    software      — KEK loaded at boot from SECRET_VAULT_KEK (value or file path).
                    Only dependency is `cryptography`. Default; fits self-host.
    vault-transit — HashiCorp Vault / OpenBao Transit engine (stub in PR1).
    pkcs11        — SoftHSM / hardware HSM (future).

Envelope encryption still holds with a software KEK: a datastore dump yields only
ciphertext + wrapped DEK; the attacker also needs the KEK, which lives in app
secret config, not in Redis.
"""

import hashlib
import os
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultConfigError(RuntimeError):
    """Raised when the vault is enabled but its key backend is misconfigured.

    Callers must treat this as fail-closed: deny rather than proceed without a
    real credential.
    """


def vault_enabled() -> bool:
    """Whether the secret vault feature is turned on (opt-in, default off)."""
    return os.getenv("SECRET_VAULT_ENABLED", "false").strip().lower() in (
        "1", "true", "yes", "on",
    )


class KeyProvider(ABC):
    """Wrap/unwrap a 32-byte DEK. The KEK never leaves the provider."""

    @abstractmethod
    def wrap_dek(self, dek: bytes) -> bytes:
        """Encrypt a DEK for storage. Returns opaque wrapped bytes."""

    @abstractmethod
    def unwrap_dek(self, wrapped: bytes) -> bytes:
        """Recover a DEK from its wrapped form. Raises on tamper/wrong key."""


class SoftwareKeyProvider(KeyProvider):
    """AES-GCM key wrapping with a locally held KEK.

    Wrapped format is ``nonce(12) || ciphertext`` so each wrap is uniquely nonced.
    """

    def __init__(self, kek: bytes):
        if len(kek) != 32:
            raise VaultConfigError("KEK must be 32 bytes after derivation")
        self._aead = AESGCM(kek)

    def wrap_dek(self, dek: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, dek, b"shield-vault-dek")

    def unwrap_dek(self, wrapped: bytes) -> bytes:
        if len(wrapped) < 13:
            raise VaultConfigError("wrapped DEK is malformed")
        nonce, ct = wrapped[:12], wrapped[12:]
        return self._aead.decrypt(nonce, ct, b"shield-vault-dek")


def _derive_kek(raw: bytes) -> bytes:
    """Derive a 32-byte KEK from the configured material.

    Accepts a raw 32-byte key, a base64 32-byte key, or any passphrase (hashed to
    32 bytes). A passphrase is the weakest option; document that operators should
    supply a 32-byte random key via a mounted secret in production.
    """
    if len(raw) == 32:
        return raw
    import base64
    try:
        decoded = base64.b64decode(raw, validate=True)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    return hashlib.sha256(raw).digest()


def _load_kek_material() -> bytes:
    """Read SECRET_VAULT_KEK as either an inline value or a path to a mounted secret."""
    val = os.getenv("SECRET_VAULT_KEK", "")
    if not val:
        raise VaultConfigError(
            "SECRET_VAULT_KEK is required when the vault is enabled with the "
            "software key provider"
        )
    # If it names a readable file (e.g. a k8s mounted Secret), use its contents.
    if os.path.isfile(val):
        with open(val, "rb") as fh:
            return _derive_kek(fh.read().strip())
    return _derive_kek(val.encode())


_provider: KeyProvider | None = None


def get_key_provider() -> KeyProvider:
    """Return the process-wide KeyProvider, building it on first use.

    Fail-closed: raises VaultConfigError if enabled but misconfigured, and for any
    not-yet-implemented backend, so no code path silently proceeds without a KEK.
    """
    global _provider
    if _provider is not None:
        return _provider

    backend = os.getenv("SECRET_VAULT_KEY_PROVIDER", "software").strip().lower()
    if backend == "software":
        _provider = SoftwareKeyProvider(_load_kek_material())
    elif backend in ("vault-transit", "pkcs11"):
        raise VaultConfigError(
            f"key provider '{backend}' is not implemented yet; use 'software'"
        )
    else:
        raise VaultConfigError(f"unknown SECRET_VAULT_KEY_PROVIDER: {backend!r}")
    return _provider


def _reset_provider_for_tests() -> None:
    """Clear the cached provider so tests can swap env/KEK between cases."""
    global _provider
    _provider = None
