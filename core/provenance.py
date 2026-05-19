"""Artifact integrity & provenance helpers.

Record-only at register time: nothing here hard-fails registration. The
approval policy in core.artifact_policy is what decides whether an
artifact may transition to APPROVED.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
from typing import Optional

from core.artifacts import Artifact, Provenance

logger = logging.getLogger("votal.provenance")


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data: bytes, expected: str) -> bool:
    if not expected:
        return False
    return hashlib.sha256(data).hexdigest().lower() == expected.lower()


def verify_cosign_signature(source_uri: str, signature: Optional[str]) -> str:
    """Best-effort cosign verification.

    Returns one of: "verified", "invalid", "absent", "unverified".
    Never raises — verification failures degrade to "unverified" so registration
    is not blocked. Approval-time policy decides whether unverified is acceptable.
    """
    if not signature:
        return "absent"
    if shutil.which("cosign") is None:
        logger.info("cosign binary not present; signature recorded but not verified")
        return "unverified"
    try:
        result = subprocess.run(
            ["cosign", "verify", source_uri, "--signature", signature],
            capture_output=True,
            timeout=15,
            check=False,
        )
        return "verified" if result.returncode == 0 else "invalid"
    except Exception as e:
        logger.warning("cosign verification raised: %s", e)
        return "unverified"


def annotate_provenance(artifact: Artifact) -> Artifact:
    """Fill in signature_status (and similar) without mutating user-supplied fields."""
    p: Provenance = artifact.provenance
    if p.signature_status in (None, "", "unverified") and p.signature:
        p.signature_status = verify_cosign_signature(artifact.source_uri, p.signature)
    elif not p.signature and p.signature_status in (None, "", "unverified"):
        p.signature_status = "absent"
    return artifact


def scan_sbom(sbom_uri: Optional[str]) -> dict:
    """SBOM scan stub. Real implementations would call grype/trivy/etc.
    Returns {"scanned": bool, "critical": int, "high": int} — counts are
    None when unknown.
    """
    if not sbom_uri:
        return {"scanned": False, "critical": None, "high": None}
    # No scanner wired up yet. Record that an SBOM exists.
    return {"scanned": False, "critical": None, "high": None, "sbom_uri": sbom_uri}
