"""What the local proxy trusts on its own connections to AI services.

Spec: docs/specs/device-agent-vpn-validation.md (R5). By default the proxy
verifies upstream certificates against mitmproxy's bundle (certifi). Behind a
VPN that inspects TLS (Zscaler Z-Tunnel 2.0, Netskope), the agent's upstream
connection is re-signed by the VPN's root, which certifi does not hold, so AI
sites fail. Two managed settings fix it:

  UpstreamTrust: system   trust the OS root store (where MDM already put the
                          VPN's root for the browsers)
  UpstreamCA: <path>      a PEM file with the VPN's root, ADDED to certifi's
                          roots (never instead of them: with the VPN off, every
                          other upstream would then fail)

Either way the agent writes state/upstream-ca.pem and hands it to mitmproxy.
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Optional

from votal_device_agent.platform import Run, run as _run

FILE = "upstream-ca.pem"
MIN_ROOTS = 50
MAC_KEYCHAINS = ("/System/Library/Keychains/SystemRootCertificates.keychain",
                 "/Library/Keychains/System.keychain")
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
_WIN_EXPORT = ("Get-ChildItem Cert:\\LocalMachine\\Root | ForEach-Object { "
               "'-----BEGIN CERTIFICATE-----'; "
               "[Convert]::ToBase64String($_.RawData, 'InsertLineBreaks'); "
               "'-----END CERTIFICATE-----' }")


def _pems(data: bytes) -> list[bytes]:
    seen, out = set(), []
    for m in _PEM.finditer(data or b""):
        block = b"\n".join(line.strip() for line in m.group(0).splitlines() if line.strip()) + b"\n"
        if block not in seen:
            seen.add(block)
            out.append(block)
    return out


def os_roots(os_name: str, run: Run = _run) -> list[bytes]:
    if os_name == "macos":
        code, out, _ = run(["/usr/bin/security", "find-certificate", "-a", "-p", *MAC_KEYCHAINS])
    elif os_name == "windows":
        code, out, _ = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_EXPORT])
    else:
        return []
    return _pems(out) if code == 0 else []


def _certifi() -> bytes:
    try:
        import certifi
        return Path(certifi.where()).read_bytes()
    except Exception:
        return b""


def _write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def build(state_dir: str | Path, os_name: str, *, trust: str = "", ca_path: str = "",
          run: Run = _run) -> tuple[Optional[str], str]:
    """(path for mitmproxy or None for its default, a note for the log)."""
    out = Path(state_dir) / FILE
    if trust == "system":
        roots = os_roots(os_name, run)
        if len(roots) < MIN_ROOTS:
            return None, (f"UpstreamTrust system: the OS store exported {len(roots)} roots; "
                          "keeping the default upstream trust")
        _write(out, b"".join(roots))
        return str(out), f"upstream trust: {len(roots)} OS roots"
    if ca_path:
        try:
            extra = _pems(Path(ca_path).read_bytes())
        except OSError as e:
            return None, f"UpstreamCA {ca_path}: {e}"
        if not extra:
            return None, f"UpstreamCA {ca_path}: no certificate in the file"
        base = _certifi()
        if not base:
            return None, "UpstreamCA: no default bundle to add it to"
        _write(out, base.rstrip(b"\n") + b"\n" + b"".join(extra))
        return str(out), f"upstream trust: default roots plus {len(extra)} from {ca_path}"
    return None, ""
