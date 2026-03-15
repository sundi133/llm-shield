"""Utility to generate API keys for LLM Shield."""

import hashlib
import secrets


def generate_api_key(prefix: str = "shld") -> tuple[str, str]:
    """Generate a new API key and its SHA-256 hash.

    Returns:
        (plaintext_key, "sha256:<hash>") — give the plaintext to the developer,
        store the hash in config.
    """
    raw = secrets.token_urlsafe(32)
    key = f"{prefix}_{raw}"
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, f"sha256:{key_hash}"


if __name__ == "__main__":
    import sys

    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    for _ in range(count):
        key, hashed = generate_api_key()
        print(f"API Key:    {key}")
        print(f"Config hash: {hashed}")
        print()
