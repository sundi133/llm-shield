"""Is the system proxy still the agent's own PAC? (the capture self-check)

Spec: docs/specs/device-agent-vpn-validation.md (R5). Pure: settings in, a
verdict out. The heartbeat carries the result as `capture`:

  {"state": "ok | overridden | missing | unknown",
   "kind":  "pac | manual_proxy | none",
   "effective": "<host and path of what is in effect>",
   "since": <epoch when this state started>}

  ok          the effective PAC is the agent's, or one the tenant allows
              (`capture.allowed_pac_urls`: a VPN PAC chained to the agent)
  overridden  another PAC, a manual proxy, or per-user settings are in effect
  missing     no proxy configuration at all (profile removed, or capture off)
  unknown     the OS settings could not be read
"""
from __future__ import annotations

from typing import Iterable, Optional
from urllib.parse import urlsplit

STATES = ("ok", "overridden", "missing", "unknown")
KINDS = ("pac", "manual_proxy", "none")
EFFECTIVE_MAX = 200


def normalize_url(url: str) -> str:
    """Scheme, host and path only: lower case, localhost as 127.0.0.1, default
    ports and a trailing slash dropped, no query or fragment."""
    raw = (url or "").strip()
    try:
        u = urlsplit(raw if "://" in raw else "http://" + raw)
        host = (u.hostname or "").lower()
        port = u.port
    except ValueError:
        return raw.lower()[:EFFECTIVE_MAX]
    if host == "localhost":
        host = "127.0.0.1"
    scheme = (u.scheme or "http").lower()
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = (u.path or "").rstrip("/")
    return f"{scheme}://{host}{path}"[:EFFECTIVE_MAX]


def classify(settings: Optional[dict], own_pac_url: str, allowed: Iterable[str] = (),
             capture_mode: str = "proxy") -> dict:
    if capture_mode == "off":
        return {"state": "missing", "kind": "none", "effective": ""}
    if not isinstance(settings, dict):
        return {"state": "unknown", "kind": "none", "effective": ""}
    ok_urls = {normalize_url(own_pac_url)} | {normalize_url(u) for u in allowed or () if u}
    if settings.get("per_user"):
        # Windows back on per-user settings: the machine PAC the kit set is not
        # what users get any more.
        return {"state": "overridden", "kind": "none", "effective": "per-user proxy settings"}
    if settings.get("pac_enabled") and settings.get("pac_url"):
        eff = normalize_url(settings["pac_url"])
        return {"state": "ok" if eff in ok_urls else "overridden", "kind": "pac", "effective": eff}
    if settings.get("manual_proxy"):
        return {"state": "overridden", "kind": "manual_proxy",
                "effective": str(settings["manual_proxy"])[:EFFECTIVE_MAX]}
    return {"state": "missing", "kind": "none", "effective": ""}


class CaptureState:
    """The last verdict, with `since` changing only on a real change (a VPN
    that flaps while connecting does not reset it)."""

    def __init__(self):
        self.current: Optional[dict] = None

    def update(self, verdict: dict, now: float) -> dict:
        cur = self.current
        if cur is None or (cur["state"], cur["kind"], cur["effective"]) != (
                verdict["state"], verdict["kind"], verdict["effective"]):
            self.current = {**verdict, "since": int(now)}
        return self.current
