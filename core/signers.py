"""Pluggable signing backends for agent and capability tokens.

This module defines the Signer protocol and three concrete backends:

  LocalEd25519Signer   process-resident private key (default; on-prem ready)
  PKCS11Signer         hardware HSM via PKCS#11 (stub; structural wiring only)
  VaultTransitSigner   HashiCorp Vault Transit secret engine (stub; structural)

Backend selection is via SHIELD_SIGNER_BACKEND env var, resolved separately
per token type so agent tokens and cap tokens can use different backends
(e.g. agent tokens through HSM, caps in-process for throughput).

Public-key verification stays in-process for ALL backends — we cache the
raw Ed25519 public key bytes locally and verify with `cryptography`, so
the hot path (verify_agent_token / verify_cap) never makes an HSM or
Vault round trip.

The PKCS11 and Vault implementations are stubs on purpose: they document
the integration shape without pulling optional dependencies into the
default install. A deployment that needs them fills in three methods.
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = logging.getLogger("votal.signers")


class SignerError(Exception):
    """Raised when a signer is misconfigured or a backend operation fails."""


@runtime_checkable
class Signer(Protocol):
    """The contract every signing backend must implement.

    `sign` is allowed to be slow (HSM round trip). `verify` is on the
    request hot path and MUST be local — implementations cache a public
    key and verify with `cryptography`.
    """

    kid: str

    def sign(self, payload: bytes) -> bytes: ...

    def verify(self, payload: bytes, signature: bytes) -> None: ...

    def public_key_bytes(self) -> bytes: ...


# ── Local in-process signer (default, on-prem ready) ─────────────────────


class LocalEd25519Signer:
    """Ed25519 keypair held in process memory.

    Suitable for on-prem deployments where:
      * the host is hardened (key is mlock-able / TPM-sealed at boot),
      * throughput dominates HSM compliance requirements,
      * or the deployment is dev/staging.

    Private key source resolution:
      1. explicit `private_key_hex` (32-byte hex)
      2. env var named in `env_var` (default differs per token type)
      3. ephemeral generation (dev only, logs a warning)
    """

    def __init__(
        self,
        kid: str,
        *,
        private_key_hex: Optional[str] = None,
        env_var: Optional[str] = None,
    ):
        self.kid = kid
        hex_src = (private_key_hex or "").strip()
        if not hex_src and env_var:
            hex_src = os.environ.get(env_var, "").strip()

        if hex_src:
            try:
                self._sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_src))
            except Exception as e:
                raise SignerError(f"invalid Ed25519 private key (kid={kid}): {e}") from e
        else:
            self._sk = Ed25519PrivateKey.generate()
            logger.warning(
                f"signers: ephemeral Ed25519 key generated (kid={kid}). "
                "DO NOT use in production."
            )
        self._pk: Ed25519PublicKey = self._sk.public_key()

    def sign(self, payload: bytes) -> bytes:
        return self._sk.sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> None:
        # InvalidSignature propagates — callers convert to their domain error.
        self._pk.verify(signature, payload)

    def public_key_bytes(self) -> bytes:
        return self._pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ── PKCS#11 HSM stub ─────────────────────────────────────────────────────


class PKCS11Signer:
    """Signer that delegates signing to a PKCS#11 HSM (stub).

    A real implementation uses `python-pkcs11`:

        import pkcs11
        lib = pkcs11.lib(os.environ["SHIELD_PKCS11_LIBRARY"])
        token = lib.get_token(token_label=os.environ["SHIELD_PKCS11_TOKEN_LABEL"])
        with token.open(user_pin=_read_pin_file()) as session:
            priv = session.get_key(label=os.environ["SHIELD_PKCS11_KEY_LABEL"],
                                   object_class=pkcs11.ObjectClass.PRIVATE_KEY)
            sig = priv.sign(payload, mechanism=pkcs11.Mechanism.EDDSA)

    Config (env vars):
      SHIELD_PKCS11_LIBRARY        path to e.g. libsofthsm2.so, libCryptoki2_64.so
      SHIELD_PKCS11_TOKEN_LABEL    HSM token label
      SHIELD_PKCS11_KEY_LABEL      Ed25519 private key label inside the token
      SHIELD_PKCS11_USER_PIN_FILE  file containing the user PIN (mode 0400)
      SHIELD_PKCS11_PUBLIC_KEY     path to a file with the raw 32-byte Ed25519 pubkey

    Public key is loaded from disk at startup so verify stays in-process.
    """

    def __init__(self, kid: str):
        self.kid = kid
        # Public key path is required: verify must be local.
        pk_path = os.environ.get("SHIELD_PKCS11_PUBLIC_KEY", "").strip()
        if not pk_path:
            raise SignerError(
                "PKCS11Signer requires SHIELD_PKCS11_PUBLIC_KEY (path to raw Ed25519 pubkey)"
            )
        try:
            with open(pk_path, "rb") as f:
                pk_bytes = f.read()
            if len(pk_bytes) != 32:
                raise SignerError(
                    f"SHIELD_PKCS11_PUBLIC_KEY must be exactly 32 raw bytes, got {len(pk_bytes)}"
                )
            self._pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
        except OSError as e:
            raise SignerError(f"cannot read SHIELD_PKCS11_PUBLIC_KEY: {e}") from e

        for var in ("SHIELD_PKCS11_LIBRARY", "SHIELD_PKCS11_TOKEN_LABEL",
                    "SHIELD_PKCS11_KEY_LABEL", "SHIELD_PKCS11_USER_PIN_FILE"):
            if not os.environ.get(var):
                raise SignerError(f"PKCS11Signer requires {var}")

        # A real impl opens the HSM session here (or lazily on first sign).
        # The stub stops short of importing python-pkcs11 so the default
        # install has no optional deps.
        raise NotImplementedError(
            "PKCS11Signer is a structural stub. To enable: "
            "`pip install python-pkcs11`, then implement sign() to call "
            "`session.sign(payload, mechanism=Mechanism.EDDSA)` and remove this raise."
        )

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError("PKCS11Signer.sign — see class docstring")

    def verify(self, payload: bytes, signature: bytes) -> None:
        # Verify is local — uses the public key loaded from disk.
        self._pk.verify(signature, payload)

    def public_key_bytes(self) -> bytes:
        return self._pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ── HashiCorp Vault Transit stub ─────────────────────────────────────────


class VaultTransitSigner:
    """Signer that delegates signing to HashiCorp Vault's Transit engine (stub).

    A real implementation uses `hvac`:

        import hvac, base64
        client = hvac.Client(url=VAULT_ADDR, token=_read_token())
        resp = client.secrets.transit.sign_data(
            name=KEY_NAME,
            hash_input=base64.b64encode(payload).decode(),
            hash_algorithm="none",        # Ed25519 signs raw
            signature_algorithm="ed25519",
        )
        # resp["data"]["signature"] looks like 'vault:v1:<base64>'
        return base64.b64decode(resp["data"]["signature"].split(":", 2)[2])

    Config (env vars):
      SHIELD_VAULT_ADDR            e.g. https://vault.internal:8200
      SHIELD_VAULT_TOKEN_FILE      AppRole / token file path (mode 0400)
      SHIELD_VAULT_TRANSIT_KEY     transit key name (must be Ed25519)
      SHIELD_VAULT_PUBLIC_KEY      path to raw 32-byte Ed25519 pubkey
      SHIELD_VAULT_NAMESPACE       (optional) Vault namespace for Enterprise

    Public key is loaded from disk so verify stays in-process.

    For high-throughput deployments, consider running Transit in batch mode
    or fronting it with an envelope-signing layer: cache a Vault-issued
    short-lived Ed25519 keypair in pod memory, rotate every N minutes.
    """

    def __init__(self, kid: str):
        self.kid = kid
        pk_path = os.environ.get("SHIELD_VAULT_PUBLIC_KEY", "").strip()
        if not pk_path:
            raise SignerError(
                "VaultTransitSigner requires SHIELD_VAULT_PUBLIC_KEY (path to raw Ed25519 pubkey)"
            )
        try:
            with open(pk_path, "rb") as f:
                pk_bytes = f.read()
            if len(pk_bytes) != 32:
                raise SignerError(
                    f"SHIELD_VAULT_PUBLIC_KEY must be exactly 32 raw bytes, got {len(pk_bytes)}"
                )
            self._pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
        except OSError as e:
            raise SignerError(f"cannot read SHIELD_VAULT_PUBLIC_KEY: {e}") from e

        for var in ("SHIELD_VAULT_ADDR", "SHIELD_VAULT_TOKEN_FILE", "SHIELD_VAULT_TRANSIT_KEY"):
            if not os.environ.get(var):
                raise SignerError(f"VaultTransitSigner requires {var}")

        raise NotImplementedError(
            "VaultTransitSigner is a structural stub. To enable: "
            "`pip install hvac`, then implement sign() against "
            "client.secrets.transit.sign_data(...) and remove this raise."
        )

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError("VaultTransitSigner.sign — see class docstring")

    def verify(self, payload: bytes, signature: bytes) -> None:
        self._pk.verify(signature, payload)

    def public_key_bytes(self) -> bytes:
        return self._pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ── Backend dispatcher ───────────────────────────────────────────────────


def build_signer(
    *,
    kid: str,
    backend_env: str = "SHIELD_SIGNER_BACKEND",
    local_key_env: Optional[str] = None,
) -> Signer:
    """Construct a signer based on env var dispatch.

    Args:
        kid:            key id (carried in the token `kid` claim)
        backend_env:    env var naming the backend (default SHIELD_SIGNER_BACKEND)
        local_key_env:  env var holding the local Ed25519 hex key
                        (only used when backend == 'local')

    Backends:
        local | (unset)   LocalEd25519Signer
        pkcs11            PKCS11Signer
        vault             VaultTransitSigner
    """
    backend = os.environ.get(backend_env, "local").strip().lower()
    if backend in ("", "local"):
        return LocalEd25519Signer(kid=kid, env_var=local_key_env)
    if backend == "pkcs11":
        return PKCS11Signer(kid=kid)
    if backend == "vault":
        return VaultTransitSigner(kid=kid)
    raise SignerError(
        f"unknown signer backend {backend!r} (set {backend_env} to one of: local, pkcs11, vault)"
    )
