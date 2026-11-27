"""Terminal coverage: CLIs, SDKs and command-line agents through the agent.

Spec: docs/specs/device-kit-firefox-terminal.md (R1, task 2). Terminals cannot
read the PAC file and mostly ship their own CA list, so with the MDM setting
`TerminalCoverage` the agent:

1. writes two trust files next to its state, readable by every user:
     trust/device-ca.pem   the certificate clients must trust (the tenant root on
                           macOS, the device CA on Windows): for NODE_EXTRA_CA_CERTS,
                           which ADDS to Node's roots
     trust/ca-bundle.pem   the OS trust store's roots plus that certificate: for
                           REQUESTS_CA_BUNDLE, SSL_CERT_FILE and CURL_CA_BUNDLE, which
                           REPLACE a client's roots, so they must never point at the
                           device CA alone (that breaks HTTPS to every other site)
2. sets the proxy and CA variables for new terminals:
     macOS    a marked block in /etc/zshenv and /etc/profile that exports them
              only while the agent's port answers, and never over a value that
              is already set
     Windows  machine environment variables, set once the proxy listens and
              removed when the service stops

Terminals always fail open: a global proxy variable cannot fall back per host
the way the PAC does, and failing closed would break git, pip and npm whenever
the agent restarts. Non-AI traffic through the proxy is tunnelled untouched,
and the CA is name-constrained to the policy's AI hosts.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Callable, Optional

from votal_device_agent.platform import Paths, Run, run as _run

MARK_BEGIN = "# >>> votal-device-agent"
MARK_END = "# <<< votal-device-agent"
MAC_FILES = (Path("/etc/zshenv"), Path("/etc/profile"))
MAC_KEYCHAINS = ("/System/Library/Keychains/SystemRootCertificates.keychain",
                 "/Library/Keychains/System.keychain")
MIN_ROOTS = 50
DEVICE_CA = "device-ca.pem"
BUNDLE = "ca-bundle.pem"
OWNED = "terminal-owned.json"
CA_CERT = "mitmproxy-ca-cert.pem"          # ca.CERT_FILE, without importing cryptography
#: Variables that replace a client's default trust store.
REPLACING = ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE")
OFF_SWITCH = "VOTAL_TERMINAL_PROXY"
WIN_ENV_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
_WIN_EXPORT = ("Get-ChildItem Cert:\\LocalMachine\\Root | ForEach-Object { "
               "'-----BEGIN CERTIFICATE-----'; "
               "[Convert]::ToBase64String($_.RawData, 'InsertLineBreaks'); "
               "'-----END CERTIFICATE-----' }")


def trust_dir(p: Paths) -> Path:
    return p.state_dir.parent / "trust"


# ── trust files ───────────────────────────────────────────────────────

def export_roots(os_name: str, run: Run = _run) -> list[bytes]:
    """The OS trust store's root certificates as PEM blocks (deduplicated)."""
    if os_name == "macos":
        code, out, _err = run(["/usr/bin/security", "find-certificate", "-a", "-p", *MAC_KEYCHAINS])
    elif os_name == "windows":
        code, out, _err = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WIN_EXPORT])
    else:
        return []
    if code != 0 or not out:
        return []
    seen, roots = set(), []
    for m in _PEM.finditer(out):
        block = b"\n".join(line.strip() for line in m.group(0).splitlines() if line.strip()) + b"\n"
        if block not in seen:
            seen.add(block)
            roots.append(block)
    return roots


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def write_trust(p: Paths, os_name: str, run: Run = _run) -> dict:
    """Write device-ca.pem and, when the OS store exports, ca-bundle.pem.
    {device_ca, bundle (or None), roots, reason}."""
    td = trust_dir(p)
    src = p.state_dir / "ca" / CA_CERT
    if not src.exists():
        return {"device_ca": None, "bundle": None, "roots": 0, "reason": "no device CA yet"}
    ca = src.read_bytes().strip() + b"\n"
    _write(td / DEVICE_CA, ca)
    roots = export_roots(os_name, run)
    if len(roots) < MIN_ROOTS:
        (td / BUNDLE).unlink(missing_ok=True)
        return {"device_ca": str(td / DEVICE_CA), "bundle": None, "roots": len(roots),
                "reason": f"the OS trust store exported {len(roots)} roots (fewer than {MIN_ROOTS}): "
                          "CA bundle variables not set"}
    _write(td / BUNDLE, b"".join(roots) + ca)
    return {"device_ca": str(td / DEVICE_CA), "bundle": str(td / BUNDLE), "roots": len(roots),
            "reason": ""}


def variables(port: int, trust: dict) -> dict:
    """The variables to set. The replacing ones only with a full bundle."""
    proxy = f"http://127.0.0.1:{port}"
    env = {"HTTPS_PROXY": proxy, "https_proxy": proxy, "HTTP_PROXY": proxy, "http_proxy": proxy,
           "NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
           "NODE_USE_ENV_PROXY": "1"}
    if trust.get("device_ca"):
        env["NODE_EXTRA_CA_CERTS"] = trust["device_ca"]
    if trust.get("bundle"):
        for k in REPLACING:
            env[k] = trust["bundle"]
    return env


# ── macOS: a marked block in the shell startup files ──────────────────

def shell_block(port: int, env: dict) -> str:
    lines = [MARK_BEGIN + " (managed by the Votal device agent; do not edit)",
             f'if [ "${{{OFF_SWITCH}:-on}}" != "off" ] && '
             f"/usr/bin/nc -z -G 1 127.0.0.1 {port} >/dev/null 2>&1; then"]
    for k, v in env.items():
        # `:=` keeps a value someone already set (the customer, another tool).
        lines.append(f'  : "${{{k}:={v}}}"; export {k}')
    lines += ["fi", MARK_END]
    return "\n".join(lines) + "\n"


def strip_block(text: str) -> str:
    """The file without our block; every other line byte-identical."""
    out, skip = [], False
    for line in text.splitlines(keepends=True):
        if line.startswith(MARK_BEGIN):
            skip = True
            continue
        if skip:
            if line.startswith(MARK_END):
                skip = False
            continue
        out.append(line)
    return "".join(out)


def apply_block(path: Path, block: Optional[str]) -> str:
    """Write (block) or remove (None) our block. 'unchanged', 'written',
    'removed' or 'error: ...'. Never raises."""
    try:
        old = path.read_text() if path.exists() else ""
        new = strip_block(old)
        if block:
            if new and not new.endswith("\n"):
                new += "\n"
            new += block
        if new == old:
            return "unchanged"
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
        _write(path, new.encode())
        os.chmod(path, mode)
        return "written" if block else "removed"
    except OSError as e:
        return f"error: {e}"


def foreign(path: Path, names) -> list[str]:
    """Variables a line outside our block already sets in this file."""
    try:
        text = strip_block(path.read_text())
    except OSError:
        return []
    return [n for n in names if re.search(rf"(?m)^\s*(?:export\s+)?{re.escape(n)}=", text)]


# ── Windows: machine environment variables ────────────────────────────

class WinEnv:
    """Machine environment variables (HKLM), and the broadcast that tells new
    processes they changed. Injected in tests."""

    def get(self, name: str) -> Optional[str]:
        import winreg  # type: ignore
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WIN_ENV_KEY) as k:
                return str(winreg.QueryValueEx(k, name)[0])
        except OSError:
            return None

    def set(self, name: str, value: str) -> None:
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WIN_ENV_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)

    def delete(self, name: str) -> None:
        import winreg  # type: ignore
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WIN_ENV_KEY, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass

    def broadcast(self) -> None:
        try:
            import ctypes
            result = ctypes.c_ulong()
            ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002,
                                                     5000, ctypes.byref(result))
        except Exception:
            pass


def _owned(p: Paths) -> dict:
    try:
        return json.loads((trust_dir(p) / OWNED).read_text())
    except (OSError, ValueError):
        return {}


def apply_windows(p: Paths, env: dict, win: WinEnv) -> dict:
    """Set our variables, never over a value someone else set. {set, foreign}."""
    owned = _owned(p)
    done, skipped = {}, []
    for k, v in env.items():
        if k.islower():
            continue                          # Windows variable names are case-insensitive
        cur = win.get(k)
        if cur is not None and k not in owned:
            skipped.append(k)
            continue
        if cur != v:
            win.set(k, v)
        done[k] = v
    for k in set(owned) - set(done):          # ours, no longer wanted
        if win.get(k) == owned[k]:
            win.delete(k)
    _write(trust_dir(p) / OWNED, json.dumps(done, indent=2).encode())
    win.broadcast()
    return {"set": sorted(done), "foreign": sorted(skipped)}


def clear_windows(p: Paths, win: WinEnv) -> list[str]:
    """Remove the variables we set (only while they still hold our value)."""
    owned = _owned(p)
    removed = []
    for k, v in owned.items():
        if win.get(k) == v:
            win.delete(k)
            removed.append(k)
    (trust_dir(p) / OWNED).unlink(missing_ok=True)
    if removed:
        win.broadcast()
    return removed


# ── entry points ──────────────────────────────────────────────────────

def apply(p: Paths, os_name: str, port: int, *, run: Run = _run, win: Optional[WinEnv] = None,
          mac_files=MAC_FILES) -> dict:
    """Turn terminal coverage on (service start, CA rotation). Never raises."""
    try:
        trust = write_trust(p, os_name, run)
    except OSError as e:
        trust = {"device_ca": None, "bundle": None, "roots": 0, "reason": f"trust files: {e}"}
    env = variables(port, trust)
    out = {"trust": trust}
    if os_name == "macos":
        block = shell_block(port, env)
        out["files"] = {str(f): apply_block(f, block) for f in mac_files}
    elif os_name == "windows":
        try:
            out["windows"] = apply_windows(p, env, win or WinEnv())
        except OSError as e:
            out["windows"] = {"error": str(e)}
    return out


def remove(p: Paths, os_name: str, *, win: Optional[WinEnv] = None, mac_files=MAC_FILES) -> dict:
    """Turn terminal coverage off (setting off, service stop on Windows, uninstall)."""
    out: dict = {}
    if os_name == "macos":
        out["files"] = {str(f): apply_block(f, None) for f in mac_files}
    elif os_name == "windows":
        try:
            out["removed"] = clear_windows(p, win or WinEnv())
        except OSError as e:
            out["error"] = str(e)
    return out


def status(p: Paths, os_name: str, *, win: Optional[WinEnv] = None, mac_files=MAC_FILES,
           read: Callable[[Path], str] = lambda f: f.read_text()) -> tuple[bool, str]:
    """For `verify`: (ok, detail)."""
    td = trust_dir(p)
    bundle, ca = td / BUNDLE, td / DEVICE_CA
    if not ca.exists():
        return False, "no trust files yet (the agent writes them at start)"
    detail = []
    if bundle.exists():
        roots = len(_PEM.findall(bundle.read_bytes()))
        detail.append(f"CA bundle {roots} certificates")
    else:
        detail.append("no CA bundle (root export failed): CA bundle variables not set")
    ok = bundle.exists()
    if os_name == "macos":
        for f in mac_files:
            try:
                has = MARK_BEGIN in read(f)
            except OSError:
                has = False
            ok = ok and has
            other = foreign(f, ("HTTPS_PROXY", "https_proxy", *REPLACING))
            detail.append(f"{f.name}: {'block in place' if has else 'no block'}"
                          + (f", set by another tool: {', '.join(other)}" if other else ""))
    elif os_name == "windows":
        owned = _owned(p)
        ok = ok and "HTTPS_PROXY" in owned
        detail.append("variables: " + (", ".join(sorted(owned)) or "none"))
    return ok, "; ".join(detail)
