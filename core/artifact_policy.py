"""Approval policy evaluator for artifacts.

Evaluates whether an artifact may be moved from DRAFT to APPROVED. Returns
a structured decision so callers can surface every failed requirement.

Defaults are permissive (everything optional) so existing flows don't break;
strict mode is opted into via env vars:

    SHIELD_ARTIFACT_REQUIRE_SIGNATURE=true
    SHIELD_ARTIFACT_REQUIRE_SBOM=true
    SHIELD_ARTIFACT_LICENSE_ALLOWLIST=Apache-2.0,MIT,BSD-3-Clause
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from core.artifacts import Artifact


def _flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("true", "1", "yes")


def _allowlist() -> list[str]:
    raw = os.environ.get("SHIELD_ARTIFACT_LICENSE_ALLOWLIST", "")
    return [s.strip() for s in raw.split(",") if s.strip()]


@dataclass
class ApprovalDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reasons": self.reasons}


def evaluate_for_approval(artifact: Artifact) -> ApprovalDecision:
    """Evaluate the approval gate for an artifact. Pure function — no I/O."""
    reasons: list[str] = []

    if _flag("SHIELD_ARTIFACT_REQUIRE_SIGNATURE"):
        if artifact.provenance.signature_status != "verified":
            reasons.append(
                f"signature_status={artifact.provenance.signature_status}, expected 'verified'"
            )

    if _flag("SHIELD_ARTIFACT_REQUIRE_SBOM"):
        if not artifact.provenance.sbom_uri:
            reasons.append("sbom_uri missing")

    allowlist = _allowlist()
    if allowlist:
        lic = (artifact.provenance.license or "").strip()
        if not lic:
            reasons.append("license missing")
        elif lic not in allowlist:
            reasons.append(f"license '{lic}' not in allowlist {allowlist}")

    return ApprovalDecision(allowed=not reasons, reasons=reasons)
