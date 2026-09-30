"""Where the device key is kept (spec §5.2): the macOS System keychain, Windows
DPAPI, or a 0600 file for development. Same interface as sync.CredentialStore:
load() -> Credentials | None, save(creds), clear().

macOS: written through `security -i` on stdin, so the key never appears in a
process argument list that other local users could read. Windows: encrypted
with DPAPI under the service account (LocalSystem), in a file whose ACL admits
only SYSTEM and Administrators.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Optional

from votal_device_agent.platform import Run, run as _run, system
from votal_device_agent.sync import CredentialStore, Credentials

SERVICE = "ai.votal.device-agent"
ACCOUNT = "device"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"


def _encode(creds: Credentials) -> str:
    return base64.b64encode(json.dumps(asdict(creds)).encode()).decode()


def _decode(b64: bytes | str) -> Optional[Credentials]:
    try:
        return Credentials(**json.loads(base64.b64decode(b64)))
    except (ValueError, TypeError):
        return None


class KeychainStore:
    def __init__(self, run: Run = _run, keychain: str = SYSTEM_KEYCHAIN):
        self.run, self.keychain = run, keychain

    def load(self) -> Optional[Credentials]:
        rc, out, _ = self.run(["security", "find-generic-password", "-a", ACCOUNT, "-s", SERVICE,
                               "-w", self.keychain])
        return _decode(out.strip()) if rc == 0 and out.strip() else None

    def save(self, creds: Credentials) -> None:
        line = (f"add-generic-password -U -a {ACCOUNT} -s {SERVICE} -w {_encode(creds)} "
                f"\"{self.keychain}\"\n")
        rc, _out, err = self.run(["security", "-i"], input=line.encode())
        if rc != 0:
            raise OSError(f"could not store the device key in the keychain: {err[:200]!r}")

    def clear(self) -> None:
        self.run(["security", "delete-generic-password", "-a", ACCOUNT, "-s", SERVICE,
                  self.keychain])


def _dpapi(data: bytes, protect: bool) -> bytes:        # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    inp, out = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), Blob()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    description = "votal-device-agent" if protect else None     # out-param when unprotecting
    ok = fn(ctypes.byref(inp), description, None, None, None, 0x1, ctypes.byref(out))
    if not ok:
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


class DpapiStore:
    """flags 0x1 = CRYPTPROTECT_UI_FORBIDDEN; no LOCAL_MACHINE flag, so only the
    account that wrote it (the service, LocalSystem) can decrypt."""

    def __init__(self, state_dir: str | Path, run: Run = _run,
                 protect: Optional[Callable[[bytes], bytes]] = None,
                 unprotect: Optional[Callable[[bytes], bytes]] = None):
        self.path = Path(state_dir) / "credentials.dpapi"
        self.run = run
        self.protect = protect or (lambda b: _dpapi(b, True))
        self.unprotect = unprotect or (lambda b: _dpapi(b, False))

    def load(self) -> Optional[Credentials]:
        try:
            return _decode(self.unprotect(self.path.read_bytes()))
        except (OSError, ValueError):
            return None

    def save(self, creds: Credentials) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(self.protect(_encode(creds).encode()))
        os.replace(tmp, self.path)
        self.run(["icacls", str(self.path), "/inheritance:r", "/grant:r", "SYSTEM:F",
                  "Administrators:F"])

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def default_store(state_dir: str | Path, os_name: Optional[str] = None, run: Run = _run):
    os_name = os_name or system()
    if os_name == "macos" and os.geteuid() == 0:
        return KeychainStore(run)
    if os_name == "windows":
        return DpapiStore(state_dir, run)
    return CredentialStore(state_dir)          # development: a 0600 file
