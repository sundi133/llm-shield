"""Validated financial identifiers and SSNs in prompts, plain or encoded.

Spec: docs/specs/builtin-financial-patterns-decoded-pii.md (R3, task 3). The
same detectors the device agent and ICAP run (core/dlp/detectors.py, a copy of
icap/detectors.py): card numbers (Luhn), IBAN (mod-97), ABA routing, SWIFT/BIC,
bank account numbers and US SSNs, after a decode pass for spaced, Unicode,
base64, hex, URL and HTML-entity encodings.

Off by default (config/default.yaml). Regex and arithmetic only, no model
call: p95 about 1 ms at 4 KB and 13 ms at 64 KB, with a hard deadline after
which it fails open (`timeout: true` in details), like the DLP floor.

Settings:
    detectors: list[str]      which detectors run (default: all)
    decode: bool              run the decode pass (default true)
    ignore_test_values: bool  skip published test values such as 4111... (default false)
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from core.dlp import detectors
from core.models import GuardrailResult
from core.text_utils import REDACTED_TEXT_KEY
from guardrails.base import BaseGuardrail

log = logging.getLogger("votal.guardrails")

#: Scans that hit the deadline and failed open (for operators and tests).
TIMEOUTS = 0


def _deadline_s() -> float:
    try:
        ms = float(os.environ.get("SHIELD_SENSITIVE_IDENTIFIERS_DEADLINE_MS", "25"))
    except ValueError:
        ms = 25.0
    return max(1.0, min(ms, 1000.0)) / 1000.0


class SensitiveIdentifiersGuardrail(BaseGuardrail):
    name = "sensitive_identifiers"
    tier = "fast"
    stage = "input"

    async def check(self, content: str, context: Optional[dict] = None) -> GuardrailResult:
        global TIMEOUTS
        wanted = self.setting("detectors", list(detectors.DETECTORS))
        if not isinstance(wanted, (list, tuple)):
            wanted = list(detectors.DETECTORS)
        res = detectors.scan(content or "", [d for d in wanted if d in detectors.DETECTORS],
                             decode=bool(self.setting("decode", True)),
                             ignore_test_values=bool(self.setting("ignore_test_values", False)),
                             deadline_s=_deadline_s())
        details = res.details()
        if res.timeout:
            TIMEOUTS += 1
            log.warning("sensitive_identifiers: scan deadline reached, failing open")
        if not res.matches:
            return GuardrailResult(passed=True, action="pass", guardrail_name=self.name,
                                   message="No financial identifiers or SSNs found", details=details)
        names = ", ".join(f.detector for f in res.findings)
        action = self.configured_action
        if action == "redact":
            details[REDACTED_TEXT_KEY] = detectors.redact(content, res.matches)
        return GuardrailResult(passed=False, action=action, guardrail_name=self.name,
                               message=f"Sensitive identifiers found: {names}", details=details)
