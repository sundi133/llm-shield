"""Registering the native-messaging host with Chrome and Edge, machine-wide.

  macOS    /Library/Google/Chrome/NativeMessagingHosts/ai.votal.device_agent.json
           /Library/Microsoft/Edge/NativeMessagingHosts/ai.votal.device_agent.json
  Windows  the manifest in the install directory, pointed at by
           HKLM\\SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\ai.votal.device_agent
           HKLM\\SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\ai.votal.device_agent

Only the extension ids MDM lists may start the host (allowed_origins).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from votal_device_agent.native_host import NAME, host_manifest
from votal_device_agent.platform import Run, run as _run, system

MAC_DIRS = (Path("/Library/Google/Chrome/NativeMessagingHosts"),
            Path("/Library/Microsoft/Edge/NativeMessagingHosts"))
WIN_KEYS = (rf"HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\{NAME}",
            rf"HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\{NAME}")


def install(host_executable: str, extension_ids: list[str], *, os_name: Optional[str] = None,
            manifest_dir: Optional[Path] = None, mac_dirs=MAC_DIRS, run: Run = _run) -> list[str]:
    """Write the manifests; returns where. No extension ids, nothing to register."""
    if not extension_ids:
        return []
    os_name = os_name or system()
    manifest = json.dumps(host_manifest(host_executable, extension_ids), indent=2)
    written = []
    if os_name == "macos":
        for d in mac_dirs:
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{NAME}.json").write_text(manifest)
            written.append(str(d / f"{NAME}.json"))
    elif os_name == "windows":
        Path(manifest_dir).mkdir(parents=True, exist_ok=True)
        path = Path(manifest_dir) / f"{NAME}.json"
        path.write_text(manifest)
        for key in WIN_KEYS:
            run(["reg", "add", key, "/ve", "/t", "REG_SZ", "/d", str(path), "/f"])
            written.append(key)
    return written


def uninstall(*, os_name: Optional[str] = None, manifest_dir: Optional[Path] = None,
              mac_dirs=MAC_DIRS, run: Run = _run) -> None:
    os_name = os_name or system()
    if os_name == "macos":
        for d in mac_dirs:
            (d / f"{NAME}.json").unlink(missing_ok=True)
    elif os_name == "windows":
        for key in WIN_KEYS:
            run(["reg", "delete", key, "/f"])
        if manifest_dir:
            (Path(manifest_dir) / f"{NAME}.json").unlink(missing_ok=True)
