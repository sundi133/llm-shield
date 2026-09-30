"""What the agent reuses from the Shield repo instead of copying (spec §8).

- shield_mavlink.bundle   the verifier every Shield edge device uses
- shield_mavlink.audit    the hash-chained offline audit log
- icap.rules              the DLP rule engine the ICAP adapter runs
- icap.decompress, icap.extract   reading a provider's request body, as ICAP does

Installed, they import normally; from a Shield checkout they are found beside
this package. The installers (task 6) bundle all three.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PACKAGES = Path(__file__).resolve().parents[2]

try:
    from shield_mavlink.audit import OfflineAuditChain, VerifyResult
    from shield_mavlink.bundle import BundleError, verify_bundle
except ImportError:                                        # running from a Shield checkout
    sys.path.insert(0, str(_PACKAGES / "shield-mavlink"))
    from shield_mavlink.audit import OfflineAuditChain, VerifyResult
    from shield_mavlink.bundle import BundleError, verify_bundle

try:
    from icap.rules import Bundle, compile_bundle, evaluate, redact
except ImportError:                                        # running from a Shield checkout
    sys.path.insert(0, str(_PACKAGES.parent))
    from icap.rules import Bundle, compile_bundle, evaluate, redact

# Extraction exactly as the ICAP adapter does it: decode first (claude.ai
# compresses its request bodies), then pull the prompt out of the provider's shape.
from icap.decompress import decode  # noqa: E402
from icap.extract import Extracted, extract  # noqa: E402

__all__ = ["Bundle", "BundleError", "Extracted", "OfflineAuditChain", "VerifyResult",
           "compile_bundle", "decode", "evaluate", "extract", "redact", "verify_bundle"]
