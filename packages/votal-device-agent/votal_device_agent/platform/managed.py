"""Settings pushed by MDM, turned into agent.json (spec §8).

  macOS    configuration profile, custom settings for the preference domain
           ai.votal.device-agent -> /Library/Managed Preferences/ai.votal.device-agent.plist
  Windows  registry policy HKLM\\SOFTWARE\\Policies\\Votal\\DeviceAgent (Intune: a
           custom OMA-URI or the MSI's properties, see packaging/)

Keys (the same names on both):

  ShieldURL         required  https URL of Shield's data plane
  TenantID          required
  Fleet             required  lowercase letters, digits, . _ -
  PinnedPublicKey   required  64 hex: the bundle signing key, from the portal
  EnrollmentToken   first run only: vde.<tenant>.<secret>
  ExtensionIDs      optional  browser extension ids allowed to reach the agent
  Capture           optional  proxy (default) or off
  ModelInline       optional  auto (default), always or never
  FallbackRulesPath optional  path to a secrets-only rules file

The pinned key arrives here and nowhere else: never from the network.
"""

from __future__ import annotations

import json
import os
import plistlib
import re
from pathlib import Path
from typing import Callable, Optional

from votal_device_agent.platform import Paths

MAC_PLIST = Path("/Library/Managed Preferences/ai.votal.device-agent.plist")
WIN_KEY = r"SOFTWARE\Policies\Votal\DeviceAgent"
KEYS = ("ShieldURL", "TenantID", "Fleet", "PinnedPublicKey", "EnrollmentToken", "ExtensionIDs",
        "Capture", "ModelInline", "FallbackRulesPath")
_EXT_ID = re.compile(r"^[a-p]{32}$")
_FLEET = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class ManagedError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def read_mac(path: Path = MAC_PLIST) -> dict:
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}
    return {k: data[k] for k in KEYS if k in data}


def read_windows(reader: Optional[Callable[[str], dict]] = None) -> dict:
    """reader(key_path) -> {name: value}; defaults to winreg on HKLM."""
    if reader is None:
        try:
            import winreg  # type: ignore
        except ImportError:
            return {}

        def reader(key_path):
            out = {}
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
    # The MSI writes every property, set or not: an empty value means unset.
    data = {k: v for k, v in (reader(WIN_KEY) or {}).items() if v not in ("", None)}
    ids = data.get("ExtensionIDs")
    if isinstance(ids, str):                    # REG_SZ, comma separated
        data["ExtensionIDs"] = [i.strip() for i in ids.split(",") if i.strip()]
    return {k: data[k] for k in KEYS if k in data}


def validate(m: dict) -> dict:
    errors = []
    for k in ("ShieldURL", "TenantID", "Fleet", "PinnedPublicKey"):
        if not isinstance(m.get(k), str) or not m[k].strip():
            errors.append(f"{k}: required")
    url = str(m.get("ShieldURL") or "")
    if url and not (url.startswith("https://") or url.startswith("http://127.0.0.1")
                    or url.startswith("http://localhost")):
        errors.append("ShieldURL: must be https")
    if m.get("Fleet") and not _FLEET.match(str(m["Fleet"])):
        errors.append("Fleet: lowercase letters, digits, . _ -")
    key = str(m.get("PinnedPublicKey") or "").strip().lower()
    if key and not re.match(r"^[0-9a-f]{64}$", key):
        errors.append("PinnedPublicKey: 64 hex characters")
    token = m.get("EnrollmentToken")
    if token and not str(token).startswith("vde."):
        errors.append("EnrollmentToken: starts with vde.")
    ids = m.get("ExtensionIDs") or []
    if not isinstance(ids, list) or not all(isinstance(i, str) and _EXT_ID.match(i) for i in ids):
        errors.append("ExtensionIDs: a list of 32-letter extension ids")
    if m.get("Capture", "proxy") not in ("proxy", "off"):
        errors.append("Capture: proxy or off")
    if m.get("ModelInline", "auto") not in ("auto", "always", "never"):
        errors.append("ModelInline: auto, always or never")
    if errors:
        raise ManagedError(errors)
    return {**m, "PinnedPublicKey": key, "ShieldURL": url.rstrip("/")}


def agent_json(m: dict, p: Paths) -> dict:
    """The agent.json the agent runs from (see sync.AgentConfig)."""
    m = validate(m)
    return {"shield_url": m["ShieldURL"], "tenant_id": m["TenantID"], "fleet": m["Fleet"],
            "pinned_public_key": m["PinnedPublicKey"], "state_dir": str(p.state_dir),
            "capture": m.get("Capture", "proxy"), "model_inline": m.get("ModelInline", "auto"),
            "fallback_path": m.get("FallbackRulesPath", "")}


def write_agent_json(m: dict, p: Paths) -> Path:
    """Write agent.json atomically, readable by local users (the native host reads
    the port from it); it holds no secret: the enrollment token is not copied."""
    cfg = agent_json(m, p)
    p.state_dir.mkdir(parents=True, exist_ok=True)
    tmp = p.config.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.chmod(tmp, 0o644)
    os.replace(tmp, p.config)
    return p.config


def read(os_name: str, **kw) -> dict:
    if os_name == "macos":
        return read_mac(kw.get("plist_path", MAC_PLIST))
    if os_name == "windows":
        return read_windows(kw.get("reader"))
    path = kw.get("json_path")
    try:
        return json.loads(Path(path).read_text()) if path else {}
    except (OSError, ValueError):
        return {}
