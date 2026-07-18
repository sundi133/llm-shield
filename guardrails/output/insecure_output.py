"""Insecure output handling detection — fast tier using regex matching.

Covers OWASP LLM02 (Insecure Output Handling): XSS/HTML injection, markdown
links with dangerous URI schemes, SQL injection fragments, and (opt-in)
code-execution primitives in model output, before the response is rendered
by a downstream app. Spec: docs/specs/insecure-output-guardrail.md
"""

import html
import re
import time
from typing import Optional

from core.models import GuardrailResult
from guardrails.base import BaseGuardrail

# Category -> list of (pattern_name, compiled_regex). Patterns are compiled at
# import so a bad pattern fails at boot, never mid-request.
_CATEGORY_PATTERNS: dict[str, list[tuple[str, re.Pattern]]] = {
    "html_injection": [
        ("script_tag", re.compile(r"<\s*/?\s*script\b", re.IGNORECASE)),
        (
            "dangerous_tag",
            re.compile(r"<\s*(iframe|object|embed|form|base|meta)\b", re.IGNORECASE),
        ),
        (
            "event_handler",
            re.compile(r"<[^>]{0,500}\bon[a-z]{3,30}\s*=", re.IGNORECASE),
        ),
        ("javascript_uri", re.compile(r"javascript\s*:", re.IGNORECASE)),
        ("data_html_uri", re.compile(r"data\s*:\s*text/html", re.IGNORECASE)),
        ("srcdoc_attr", re.compile(r"\bsrcdoc\s*=", re.IGNORECASE)),
    ],
    "markdown_injection": [
        (
            "dangerous_link_scheme",
            re.compile(
                r"\[[^\]]{0,500}\]\(\s*(?:javascript|vbscript|data)\s*:",
                re.IGNORECASE,
            ),
        ),
        (
            "dangerous_ref_scheme",
            re.compile(r"\]:\s*(?:javascript|vbscript|data)\s*:", re.IGNORECASE),
        ),
    ],
    "sql_injection": [
        ("union_select", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
        (
            "tautology",
            re.compile(
                r"['\"]\s*(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE
            ),
        ),
        (
            "stacked_statement",
            re.compile(
                r";\s*(?:drop|truncate|alter)\s+(?:table|database)\b", re.IGNORECASE
            ),
        ),
        ("into_outfile", re.compile(r"\binto\s+(?:out|dump)file\b", re.IGNORECASE)),
        ("xp_cmdshell", re.compile(r"\bxp_cmdshell\b", re.IGNORECASE)),
    ],
    "code_execution": [
        ("eval_call", re.compile(r"\b(?:eval|exec)\s*\(")),
        ("os_system", re.compile(r"\bos\.system\s*\(")),
        ("subprocess_call", re.compile(r"\bsubprocess\.(?:run|call|Popen)\s*\(")),
        ("child_process", re.compile(r"\bchild_process\b")),
    ],
}

_DEFAULT_CATEGORIES = ["html_injection", "markdown_injection", "sql_injection"]

_FENCED_CODE = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)

_SCHEME_NEUTRALIZE = re.compile(r"(?:javascript|vbscript|data)\s*:", re.IGNORECASE)


def _mask_fenced_code(content: str) -> str:
    """Space-fill fenced code blocks so offsets into the original are preserved."""
    return _FENCED_CODE.sub(lambda m: " " * len(m.group(0)), content)


def _sanitize(content: str, detections: list[dict]) -> str:
    """Escape/neutralize HTML and markdown findings; SQL/code are left as-is.

    Overlapping spans (a javascript: URI inside an event-handler match) are
    merged before replacement so offsets stay valid.
    """
    spans = [
        d
        for d in detections
        if d["category"] in ("html_injection", "markdown_injection")
    ]
    merged: list[dict] = []
    for d in sorted(spans, key=lambda d: (d["start"], d["end"])):
        if merged and d["start"] <= merged[-1]["end"]:
            merged[-1]["end"] = max(merged[-1]["end"], d["end"])
            if d["category"] == "html_injection":
                merged[-1]["category"] = "html_injection"
        else:
            merged.append({"start": d["start"], "end": d["end"], "category": d["category"]})
    for d in reversed(merged):
        replacement = _SCHEME_NEUTRALIZE.sub("blocked:", content[d["start"] : d["end"]])
        if d["category"] == "html_injection":
            replacement = html.escape(replacement)
        content = content[: d["start"]] + replacement + content[d["end"] :]
    return content


class InsecureOutputGuardrail(BaseGuardrail):
    """Detect XSS/HTML, dangerous markdown URIs, SQLi, and exec primitives in output.

    Fast tier — compiled regex only, no LLM call. Detection spans are reported
    with offsets; ``sanitize: true`` additionally returns a rendered-safe copy.
    """

    name = "insecure_output"
    tier = "fast"
    stage = "output"

    async def check(
        self, content: str, context: Optional[dict] = None
    ) -> GuardrailResult:
        start = time.perf_counter()
        settings = self.settings
        categories: list[str] = settings.get("detect_categories", _DEFAULT_CATEGORIES)
        sanitize: bool = settings.get("sanitize", False)
        ignore_fenced_code: bool = settings.get("ignore_fenced_code", True)

        scan_target = _mask_fenced_code(content) if ignore_fenced_code else content

        detections = []
        for category in categories:
            for pattern_name, pattern in _CATEGORY_PATTERNS.get(category, []):
                for m in pattern.finditer(scan_target):
                    detections.append(
                        {
                            "category": category,
                            "pattern": pattern_name,
                            "match": content[m.start() : m.end()][:200],
                            "start": m.start(),
                            "end": m.end(),
                        }
                    )

        elapsed = (time.perf_counter() - start) * 1000

        if detections:
            found = sorted(set(d["category"] for d in detections))
            details = {
                "detections": detections,
                "categories_checked": categories,
                "ignore_fenced_code": ignore_fenced_code,
            }
            if sanitize:
                details["sanitized_output"] = _sanitize(content, detections)
            return GuardrailResult(
                passed=False,
                action=self.configured_action,
                guardrail_name=self.name,
                message=(
                    f"Insecure output detected: {', '.join(found)} "
                    f"({len(detections)} instance(s))"
                ),
                details=details,
                latency_ms=round(elapsed, 2),
            )

        return GuardrailResult(
            passed=True,
            action="pass",
            guardrail_name=self.name,
            message="No insecure output patterns detected",
            latency_ms=round(elapsed, 2),
        )
