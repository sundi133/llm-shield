"""Putting the device CA in the machine's trust store, and checking it is there.

Windows: `certutil -addstore Root` as the service (LocalSystem) is silent and
adds to the machine store; the previous CA is removed by thumbprint.

macOS: since Big Sur a root process cannot mark a certificate trusted without
someone authorizing it interactively; only an MDM configuration profile
(com.apple.security.root) can do it silently. `trust` therefore reports
`needs_mdm` on macOS instead of pretending, and `is_trusted` checks the
result either way. How a per-device CA reaches an MDM profile is the open
decision recorded in the spec (§3.1, task 6 notes).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from votal_device_agent.platform import Run, run as _run, system


def sha1_thumbprint(cert_path: str | Path) -> str:
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    return cert.fingerprint(hashes.SHA1()).hex()


def trust(cert_path: str | Path, *, previous: Optional[str] = None,
          os_name: Optional[str] = None, run: Run = _run) -> str:
    """trusted, needs_mdm (macOS), failed: <why>, or unsupported."""
    os_name = os_name or system()
    if os_name == "windows":
        if previous:
            run(["certutil", "-delstore", "Root", previous])
        rc, _o, err = run(["certutil", "-addstore", "-f", "Root", str(cert_path)])
        return "trusted" if rc == 0 else f"failed: {err[:200]!r}"
    if os_name == "macos":
        return "trusted" if is_trusted(cert_path, os_name="macos", run=run) else "needs_mdm"
    return "unsupported"


def untrust(thumbprint: str, *, os_name: Optional[str] = None, run: Run = _run) -> None:
    os_name = os_name or system()
    if os_name == "windows":
        run(["certutil", "-delstore", "Root", thumbprint])
    elif os_name == "macos":
        run(["security", "delete-certificate", "-Z", thumbprint.upper(),
             "/Library/Keychains/System.keychain"])


def is_trusted(cert_path: str | Path, *, os_name: Optional[str] = None, run: Run = _run) -> bool:
    os_name = os_name or system()
    if os_name == "macos":
        rc, _o, _e = run(["security", "verify-cert", "-c", str(cert_path), "-p", "basic", "-L"])
        return rc == 0
    if os_name == "windows":
        rc, _o, _e = run(["certutil", "-verifystore", "Root", sha1_thumbprint(cert_path)])
        return rc == 0
    return False
