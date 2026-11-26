"""The proxy settings the OS is actually using, for the capture self-check.

Spec: docs/specs/device-agent-vpn-validation.md (R5). The agent sees AI traffic
only while the system proxy points at its PAC file; a VPN client that pushes
its own PAC or proxy takes that away silently. These readers return the
effective settings as a plain dict, or None when they cannot be read:

  {"pac_enabled": bool, "pac_url": str | None, "manual_proxy": str | None,
   "per_user": bool}

macOS   `scutil --proxy`: the effective dictionary of the primary service, which
        is what browsers use (VPN services' own settings appear there once the
        VPN is primary; the __SCOPED__ entries are per-interface and ignored).
Windows the machine-wide settings the Intune script writes (HKLM AutoConfigURL,
        ProxyEnable / ProxyServer, and the ProxySettingsPerUser policy). The
        agent runs as SYSTEM, so a per-user read would see SYSTEM's settings,
        not the signed-in user's; with ProxySettingsPerUser=0 the machine
        settings are what every user gets, and a VPN that switches the machine
        back to per-user settings is reported as `per_user`.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from votal_device_agent.platform import Run, run as _run

SCUTIL = "/usr/sbin/scutil"
TIMEOUT_S = 2.0
WIN_INTERNET = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
WIN_POLICY = r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
_LINE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*:\s*(.*?)\s*$")


def parse_scutil(text: str) -> dict:
    """The top-level keys of `scutil --proxy` (nested dictionaries skipped)."""
    top: dict = {}
    depth = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith("{"):
            if depth == 1:
                m = _LINE.match(stripped[:-1].rstrip())
                if m:
                    top[m.group(1)] = "<nested>"
            depth += 1
            continue
        if stripped == "}":
            depth -= 1
            continue
        if depth == 1:
            m = _LINE.match(stripped)
            if m:
                top[m.group(1)] = m.group(2)
    return top


def _from_scutil(d: dict) -> dict:
    pac_on = d.get("ProxyAutoConfigEnable") == "1"
    manual = None
    for proto in ("HTTPS", "HTTP"):
        if d.get(f"{proto}Enable") == "1" and d.get(f"{proto}Proxy"):
            port = d.get(f"{proto}Port")
            manual = d[f"{proto}Proxy"] + (f":{port}" if port else "")
            break
    return {"pac_enabled": pac_on, "pac_url": d.get("ProxyAutoConfigURLString") if pac_on else None,
            "manual_proxy": manual, "per_user": False}


def read_mac(run: Run = _run) -> Optional[dict]:
    code, out, _err = run([SCUTIL, "--proxy"], timeout=TIMEOUT_S)
    if code != 0 or not out:
        return None
    try:
        return _from_scutil(parse_scutil(out.decode("utf-8", "replace")))
    except Exception:
        return None


def _winreg_reader(key_path: str) -> dict:
    import winreg  # type: ignore
    out: dict = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            i = 0
            while True:
                try:
                    name, value, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = value
                i += 1
    except OSError:
        pass
    return out


def read_windows(reader: Optional[Callable[[str], dict]] = None) -> Optional[dict]:
    """reader(HKLM key path) -> {name: value}; defaults to winreg."""
    try:
        reader = reader or _winreg_reader
        machine = reader(WIN_INTERNET) or {}
        policy = reader(WIN_POLICY) or {}
    except Exception:
        return None
    per_user = str(policy.get("ProxySettingsPerUser", 1)) != "0"
    pac = str(machine.get("AutoConfigURL") or "").strip() or None
    manual = None
    if str(machine.get("ProxyEnable", 0)) == "1" and machine.get("ProxyServer"):
        manual = str(machine["ProxyServer"])
    return {"pac_enabled": bool(pac), "pac_url": pac, "manual_proxy": manual, "per_user": per_user}


def read_effective(os_name: str, *, run: Run = _run,
                   reader: Optional[Callable[[str], dict]] = None) -> Optional[dict]:
    """The effective settings, or None when they cannot be read. Never raises."""
    try:
        if os_name == "macos":
            return read_mac(run)
        if os_name == "windows":
            return read_windows(reader)
    except Exception:
        return None
    return None
