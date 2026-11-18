"""Tier 2 detectors A7 to A10 and the device prevalence baseline (spec 2.3, 3.4).

Lab prototype: hand-set starting thresholds, every verdict with its reasons.
Rules the spec fixes, enforced here:
- A9 (environment) is supporting only: it adds to the score only when some
  other detector already fired, so a VDI user is never flagged for it.
- A10 counts a missing tag only on a protected form submit, and weakly
  (ad blockers stop tags too).
- A8 (automation traces) is often the customer's bot manager's job, so the
  lab reports detection with and without it.
- A device fingerprint links sessions only when it is rare in the baseline of
  earlier non-fleet sessions (the production counterpart is the 24-hour
  prevalence counters).
"""

from __future__ import annotations

import json
from pathlib import Path

from sessions import FORM_FIELDS

PREVALENCE_MAX = 0.001


def a7_interaction(s, tag, _signals):
    """Clicks and typing like a program: values set by script, exact centres, pointer jumps, steady keys."""
    if not tag or not tag.joined:
        return 0.0, None
    it = tag.interaction()
    touch = int(tag.device.get("touch", 0) or 0) > 0
    found = []
    if it["inputs_without_keys"] >= 2:
        found.append(f"{it['inputs_without_keys']} fields changed with no key presses")
    if it["untrusted_events"] > 0:
        found.append(f"{it['untrusted_events']} synthetic (untrusted) events")
    if not touch and it["clicks"] >= 2:
        if it["centre_clicks"] / it["clicks"] >= 0.8:
            found.append(f"{it['centre_clicks']} of {it['clicks']} clicks within 2 px of the element centre")
        if it["clicks_without_move"] / it["clicks"] >= 0.8:
            found.append(f"{it['clicks_without_move']} of {it['clicks']} clicks with no pointer path before them")
    if it["keys"] >= 20 and it["key_gap_cv"] is not None and it["key_gap_cv"] < 0.25:
        found.append(f"steady typing (key gap variation {it['key_gap_cv']:.2f})")
    if it["keys"] >= 40 and it["corrections"] == 0:
        found.append(f"{it['keys']} key presses and no corrections")
    if not found:
        return 0.0, None
    return (1.0 if len(found) >= 2 else 0.5), "; ".join(found)


def a8_automation(s, tag, signals):
    if not tag or (not tag.device and not tag.automation):
        return 0.0, None
    a = tag.automation
    found = []
    if a.get("webdriver"):
        found.append("navigator.webdriver is set")
    if a.get("cdp"):
        found.append("a browser-control (CDP) client is attached")
    weak = []
    if a.get("headless_shape"):
        weak.append("headless window shape")
    if a.get("hints_mismatch") and not signals.get("A6"):
        weak.append(f"client hints contradict the user agent ({a['hints_mismatch']})")
    if found:
        return 1.0, "; ".join(found + weak)
    return (0.5, "; ".join(weak)) if weak else (0.0, None)


def a9_environment(s, tag, signals):
    """Supporting only: counts when some other detector fired."""
    if not tag or not tag.device:
        return 0.0, None
    cls = tag.device.get("renderer_class", "")
    found = []
    if cls in ("software", "vm"):
        found.append(f"{'software' if cls == 'software' else 'virtual machine'} graphics "
                     f"({tag.device.get('renderer', '')[:60]})")
    if cls == "none":
        found.append("no WebGL at all")
    if not found:
        return 0.0, None
    others = any(v for k, v in signals.items() if k not in ("A9",))
    if not others:
        return 0.0, None
    return 1.0, "; ".join(found)


def a10_tag_state(s, tag, _signals):
    submitted = any(e["method"] == "POST" and e["uri"] in FORM_FIELDS for e in s.events)
    if not tag or not tag.joined:
        return (0.5, "a protected form was submitted with no tag beacon") if submitted else (0.0, None)
    found = []
    if tag.beacon_uas and tag.beacon_uas != {s.ua}:
        found.append("beacons came from a different client than the page requests")
    if len(tag.device_hashes) > 1:
        found.append(f"device changed {len(tag.device_hashes) - 1} time(s) mid-session")
    return (1.0, "; ".join(found)) if found else (0.0, None)


DETECTORS = [  # id, function, weight; run after tier 1, in this order (A9 reads the others)
    ("A7", a7_interaction, 0.60), ("A8", a8_automation, 0.50), ("A10", a10_tag_state, 0.40),
    ("A9", a9_environment, 0.25),
]


# ── device prevalence baseline (spec 3.4) ────────────────────────────────

class DeviceBaseline:
    """Counts of device fingerprints among earlier non-fleet, human-like sessions."""

    def __init__(self, path: Path):
        self.path = path
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            data = {}
        self.sessions = int(data.get("sessions", 0))
        self.devices: dict[str, int] = dict(data.get("devices", {}))

    def share(self, device_hash: str) -> float:
        return self.devices.get(device_hash, 0) / self.sessions if self.sessions else 0.0

    def rare(self, device_hash: str) -> bool:
        return bool(device_hash) and self.share(device_hash) < PREVALENCE_MAX

    def add(self, device_hashes) -> None:
        for h in device_hashes:
            if h:
                self.sessions += 1
                self.devices[h] = self.devices.get(h, 0) + 1

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"sessions": self.sessions, "devices": self.devices}, indent=1))
