"""Envelope encryption for vault secret values.

Each value gets a fresh random 32-byte DEK. The value is sealed with AES-GCM under
the DEK; the DEK is wrapped by the KeyProvider's KEK. Only ciphertext + nonce +
wrapped DEK are ever persisted — never the plaintext value or the raw DEK.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.secret_vault.keyprovider import KeyProvider

_AAD = b"shield-vault-value"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def encrypt_value(plaintext: str, provider: KeyProvider) -> dict:
    """Envelope-encrypt a secret value.

    Returns a dict of base64 strings safe to persist:
    ``{"ciphertext", "nonce", "wrapped_dek"}``. Contains no plaintext.
    """
    dek = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), _AAD)
    wrapped = provider.wrap_dek(dek)
    return {
        "ciphertext": _b64(ciphertext),
        "nonce": _b64(nonce),
        "wrapped_dek": _b64(wrapped),
    }


def decrypt_value(entry: dict, provider: KeyProvider) -> str:
    """Recover the plaintext value from a persisted vault entry.

    Raises (via the AEAD / provider) on tamper or wrong key — callers must
    fail-closed on any exception.
    """
    dek = provider.unwrap_dek(_b64d(entry["wrapped_dek"]))
    ciphertext = _b64d(entry["ciphertext"])
    nonce = _b64d(entry["nonce"])
    return AESGCM(dek).decrypt(nonce, ciphertext, _AAD).decode("utf-8")


def decrypt_entry_cached(entry: dict) -> str:
    """Decrypt using the process KeyProvider with a memoized DEK unwrap.

    For server-side egress reads that always use the global provider. Keeps
    ``decrypt_value`` pure (tests pass their own provider) while making repeated
    reads and retokenize() cheap.
    """
    from core.secret_vault.keyprovider import unwrap_dek_cached
    dek = unwrap_dek_cached(_b64d(entry["wrapped_dek"]))
    ciphertext = _b64d(entry["ciphertext"])
    nonce = _b64d(entry["nonce"])
    return AESGCM(dek).decrypt(nonce, ciphertext, _AAD).decode("utf-8")
