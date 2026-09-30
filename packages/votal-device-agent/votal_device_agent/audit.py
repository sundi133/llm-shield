"""The device's decision log (spec §3.3): shield-mavlink's hash-chained offline
audit chain, one record per recorded decision, synced to Shield as runtime
events of kind "dlp".

A record never holds the prompt. It holds its SHA-256 and length, what was
decided and why, and, only when the tenant turns on privacy.capture_excerpt,
the first 200 characters with every rule match masked.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterator

from votal_device_agent._deps import OfflineAuditChain, VerifyResult

FIELDS = ("verdict", "action", "enforced", "mode", "trust", "bundle_version", "destination",
          "app", "source", "prompt_sha256", "prompt_len", "rule_ids", "category",
          "model_verdict", "p_category", "confidence", "exfil", "probabilities", "model_state",
          "chunks_judged", "justified", "justify_reason", "reason", "evaluated_ms")
SEVERITY = {"block": "high", "justify": "medium", "redact": "medium", "monitor": "low",
            "uncertain": "low", "allow": "info"}


class AuditLog:
    def __init__(self, audit_dir: str | Path, device_id: str = ""):
        self.chain = OfflineAuditChain(audit_dir)
        self.dir = Path(audit_dir)
        self.device_id = device_id

    def record(self, d) -> dict:
        core = {"at": round(time.time(), 3), "device_id": self.device_id,
                **{f: getattr(d, f) for f in FIELDS}}
        if d.excerpt:
            core["excerpt"] = d.excerpt
        return self.chain.append(core)

    def records(self) -> Iterator[dict]:
        return self.chain.records()

    def verify(self) -> VerifyResult:
        return self.chain.verify()


def to_event(r: dict) -> dict:
    """One audit record as a runtime event (POST /v1/shield/runtime/events).
    Shield stamps device_id from the device's key whatever this says."""
    verdict = r.get("verdict", "allow")
    detail = {k: r.get(k) for k in ("verdict", "action", "enforced", "mode", "trust",
                                    "category", "model_verdict", "rule_ids", "destination",
                                    "app", "source", "prompt_sha256", "prompt_len",
                                    "probabilities", "model_state", "justified",
                                    "justify_reason", "bundle_version", "seq", "record_hash",
                                    "device_id") if r.get(k) not in (None, "", [], {})}
    if r.get("rule_ids"):
        detail["rule_id"] = r["rule_ids"][0]
    if r.get("excerpt"):
        detail["excerpt"] = r["excerpt"]
    return {"source": "custom", "kind": "dlp",
            "decision": "deny" if r.get("action") == "block" else
                        ("allow" if verdict == "allow" else "audit"),
            "severity": SEVERITY.get(verdict, "info"),
            "agent_id": r.get("device_id") or "", "agent_instance_id": r.get("device_id") or "",
            "at": r.get("at"), "detail": detail}
