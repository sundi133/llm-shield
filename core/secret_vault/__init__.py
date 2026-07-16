"""Secret vault — keep developer secrets out of the LLM path.

Secrets are stored envelope-encrypted (ciphertext + wrapped data key) per tenant.
The real value is materialized only at the egress boundary, never returned to a
caller or the model. Key management is on-prem only (no cloud KMS): a software KEK
by default, with HashiCorp Vault / OpenBao Transit as an upgrade path behind the
same KeyProvider interface.

See docs/spec-secret-vault-egress.md. This package (PR1) provides the encryption
core; egress materialization is wired in a later PR.
"""

from core.secret_vault.crypto import decrypt_value, encrypt_value
from core.secret_vault.keyprovider import (
    KeyProvider,
    SoftwareKeyProvider,
    VaultConfigError,
    get_key_provider,
    vault_enabled,
)

__all__ = [
    "KeyProvider",
    "SoftwareKeyProvider",
    "VaultConfigError",
    "get_key_provider",
    "vault_enabled",
    "encrypt_value",
    "decrypt_value",
]
