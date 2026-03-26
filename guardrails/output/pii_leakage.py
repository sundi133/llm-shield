"""PII leakage detection for LLM outputs — fast tier using regex + presidio."""

import logging
import re
import time
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

logger = logging.getLogger(__name__)

# Built-in regex patterns for common PII/secrets (no LLM needed)
_BUILTIN_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_number": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "api_key": re.compile(
        r"\b(?:sk-|pk-|api[_-]?key[=:\s]+)[A-Za-z0-9_\-]{20,}\b", re.IGNORECASE
    ),
    "password": re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "date_of_birth": re.compile(
        r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
    ),
    "passport_number": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "bank_account": re.compile(r"\b\d{8,17}\b"),  # basic routing/account number pattern
    "address": re.compile(
        r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s?){1,4}(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court|Pl|Place|Way)\b",
        re.IGNORECASE,
    ),
}

# Map from UI-friendly PII type names to regex pattern keys
_PII_TYPE_MAP = {
    "SSN": "ssn",
    "Credit Card": "credit_card",
    "Email": "email",
    "Phone Number": "phone_number",
    "API Key": "api_key",
    "Password": "password",
    "Address": "address",
    "Date of Birth": "date_of_birth",
    "Passport Number": "passport_number",
    "Bank Account": "bank_account",
    # Also accept lowercase/underscore variants
    "ssn": "ssn",
    "credit_card": "credit_card",
    "email": "email",
    "phone_number": "phone_number",
    "api_key": "api_key",
    "password": "password",
    "address": "address",
    "date_of_birth": "date_of_birth",
    "passport_number": "passport_number",
    "bank_account": "bank_account",
    "ip_address": "ip_address",
}

# Map from UI-friendly PII type names to presidio entity names
_PRESIDIO_ENTITY_MAP = {
    "SSN": "US_SSN",
    "Credit Card": "CREDIT_CARD",
    "Email": "EMAIL_ADDRESS",
    "Phone Number": "PHONE_NUMBER",
    "Address": "LOCATION",
    "Date of Birth": "DATE_TIME",
    "Passport Number": "US_PASSPORT",
    "Bank Account": "US_BANK_NUMBER",
    "API Key": None,  # no presidio equivalent
    "Password": None,
}


class PIILeakageGuardrail(BaseGuardrail):
    """Detect and flag sensitive data (SSNs, credit cards, API keys, etc.) in LLM outputs.

    Fast tier — uses regex patterns and optionally presidio-analyzer. No LLM call needed.
    """

    name = "pii_leakage"
    tier = "fast"
    stage = "output"

    def __init__(self):
        settings = self.settings
        # Accept both pii_types (from UI) and entities (legacy)
        self._pii_types: list[str] = settings.get(
            "pii_types",
            settings.get(
                "entities",
                [
                    "SSN",
                    "Credit Card",
                    "Email",
                    "Phone Number",
                    "API Key",
                    "Password",
                    "Address",
                    "Date of Birth",
                    "Passport Number",
                    "Bank Account",
                ],
            ),
        )
        self._threshold: float = settings.get(
            "threshold", settings.get("score_threshold", 0.7)
        )
        self._auto_redact: bool = settings.get("auto_redact", False)
        self._mode: str = settings.get("mode", "mask")  # mask, remove, redact
        self._use_presidio: bool = settings.get("use_presidio", True)
        self._analyzer = None

        # Build active regex patterns based on selected PII types
        self._active_patterns: dict[str, re.Pattern] = {}
        for pii_type in self._pii_types:
            key = _PII_TYPE_MAP.get(pii_type, pii_type.lower().replace(" ", "_"))
            if key in _BUILTIN_PATTERNS:
                self._active_patterns[key] = _BUILTIN_PATTERNS[key]

        # Build active presidio entities
        self._presidio_entities: list[str] = []
        if self._use_presidio:
            for pii_type in self._pii_types:
                entity = _PRESIDIO_ENTITY_MAP.get(pii_type)
                if entity:
                    self._presidio_entities.append(entity)

            if self._presidio_entities:
                try:
                    from presidio_analyzer import AnalyzerEngine

                    self._analyzer = AnalyzerEngine()
                except ImportError:
                    logger.warning(
                        "presidio-analyzer not installed; PII leakage guardrail will use regex-only mode."
                    )

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()
        all_detections = []

        # Phase 1: fast regex scan (only active patterns)
        for pattern_name, pattern in self._active_patterns.items():
            for match in pattern.finditer(content):
                all_detections.append(
                    {
                        "type": pattern_name,
                        "value_preview": _redact_preview(match.group()),
                        "start": match.start(),
                        "end": match.end(),
                        "source": "regex",
                    }
                )

        # Phase 2: presidio scan (if available and entities selected)
        if self._analyzer is not None and self._presidio_entities:
            try:
                results = self._analyzer.analyze(
                    text=content,
                    entities=self._presidio_entities,
                    language="en",
                    score_threshold=self._threshold,
                )
                for r in results:
                    if not any(
                        d["start"] == r.start and d["end"] == r.end
                        for d in all_detections
                    ):
                        all_detections.append(
                            {
                                "type": r.entity_type.lower(),
                                "score": round(r.score, 3),
                                "start": r.start,
                                "end": r.end,
                                "source": "presidio",
                            }
                        )
            except Exception as e:
                logger.warning("Presidio analysis failed: %s", e)

        elapsed = (time.perf_counter() - start) * 1000

        # Apply auto-redaction if enabled
        redacted_output = None
        if all_detections and self._auto_redact:
            redacted_output = _apply_redaction(content, all_detections, self._mode)

        if all_detections:
            types = sorted(set(d["type"] for d in all_detections))
            details = {
                "detections": all_detections,
                "pii_types_checked": self._pii_types,
                "threshold": self._threshold,
                "mode": self._mode,
                "auto_redact": self._auto_redact,
            }
            if redacted_output is not None:
                details["redacted_output"] = redacted_output

            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=f"PII/sensitive data detected in output: {', '.join(types)} ({len(all_detections)} instance(s))",
                details=details,
                latency_ms=round(elapsed, 2),
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No PII or sensitive data detected in output",
            details={
                "pii_types_checked": self._pii_types,
                "threshold": self._threshold,
            },
            latency_ms=round(elapsed, 2),
        )


def _redact_preview(value: str) -> str:
    """Show first 2 and last 2 characters, mask the rest."""
    if len(value) <= 6:
        return value[:1] + "***" + value[-1:]
    return value[:2] + "***" + value[-2:]


def _apply_redaction(content: str, detections: list[dict], mode: str) -> str:
    """Apply redaction to content based on mode."""
    # Sort detections by start position descending to replace from end
    sorted_dets = sorted(detections, key=lambda d: d["start"], reverse=True)
    result = content
    for det in sorted_dets:
        s, e = det["start"], det["end"]
        if mode == "remove":
            result = result[:s] + result[e:]
        elif mode == "redact":
            result = result[:s] + "[REDACTED]" + result[e:]
        else:  # mask
            length = e - s
            result = result[:s] + "*" * length + result[e:]
    return result
