"""Offline, model-free heuristics for auditing MCP metadata.

These are *fresh* patterns owned by this package (per the spec: no import of the
server-side `guardrails` stack, which is model-backed and can't run on a laptop).
Connected mode (Task 3) adds the strong model verdict on top of these.

Every detector is a pure function: (text/item) -> list[Finding]. No I/O.
"""

from __future__ import annotations

import base64
import codecs
import re
from typing import Iterable

from shield_mcp.report import Finding

MAX_TEXT_BYTES = 20_000  # size cap before we scan/decode (mirror shield_guard caps)

# ── tool-poisoning: instructions aimed at the model that reads the metadata ──
_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|preceding)\s+instructions",
    r"disregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|preceding)",
    r"forget\s+(?:all\s+|everything|the\s+above|previous)",
    r"do\s+not\s+(?:tell|inform|mention|reveal|notify|alert)\s+(?:the\s+)?(?:user|human|operator)",
    r"without\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?(?:user|human)",
    r"you\s+(?:must|should|shall|will)\s+(?:always|now|instead|secretly)",
    r"</?\s*(?:important|system|secret|instruction|admin)\s*>",  # hidden-instruction tags
    r"\bsystem\s+prompt\b",
    r"pretend\s+to\s+be|act\s+as\s+(?:if|though|a)",
    r"\bexfiltrat",
    r"send\s+(?:it|them|the\s+\w+|all\s+\w+)\s+to\b",
    r"read\s+(?:the\s+)?(?:\.env\b|~/?\.ssh|/etc/passwd|environment\s+variables?|secret[s]?|credential[s]?)",
    r"\bprint\s+(?:the\s+)?(?:api[_\s-]?key|token|password|secret)",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

# ── over-broad permission: dangerous capability by tool name or description ──
_DANGEROUS_NAME_TOKENS = {
    "exec", "eval", "shell", "subprocess", "run_command", "runcommand", "command",
    "system", "spawn", "delete", "destroy", "drop", "rm", "remove_all", "wipe",
    "format", "sudo", "chmod", "chown", "wire_transfer", "transfer_funds",
    "send_money", "withdraw", "write_file", "writefile", "put_object", "deploy",
    "kill", "shutdown",
}
_DANGEROUS_DESC_PATTERNS = [
    r"\barbitrary\s+(?:code|command[s]?|shell|sql)\b",
    r"\bexecut(?:e|es|ing)\b[^.]{0,40}\b(?:command|shell|code|script|sql)\b",
    r"\brm\s+-rf\b",
    r"delete[s]?\s+(?:all|any|everything|arbitrary)",
    r"\bfull\s+(?:filesystem|disk|system)\s+access\b",
    r"\bunrestricted\b",
]
_DANGEROUS_DESC_RE = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_DESC_PATTERNS]

# ── suspicious metadata ──
# Zero-width + bidi control characters used to hide text from human reviewers.
_HIDDEN_CHARS = "".join([
    "​", "‌", "‍", "⁠", "﻿",   # zero-width
    "‪", "‫", "‬", "‭", "‮",   # bidi embedding/override
    "⁦", "⁧", "⁨", "⁩",             # bidi isolates
])
_HIDDEN_RE = re.compile("[" + re.escape(_HIDDEN_CHARS) + "]")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_LONG_DESC = 2000

# ── encoded content ──
_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


def _cap(text: str) -> str:
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    if len(text.encode("utf-8", "ignore")) > MAX_TEXT_BYTES:
        return text.encode("utf-8", "ignore")[:MAX_TEXT_BYTES].decode("utf-8", "ignore")
    return text


def _matches_injection(text: str):
    for rx in _INJECTION_RE:
        m = rx.search(text)
        if m:
            return m.group(0)
    return None


def _looks_like_attack(decoded: str) -> str:
    """Return an evidence snippet if decoded text carries an injection/danger."""
    hit = _matches_injection(decoded)
    if hit:
        return hit
    low = decoded.lower()
    for tok in ("ignore previous", "system prompt", "exfiltrat", "api key",
                "password", "/etc/passwd", ".ssh"):
        if tok in low:
            return tok
    return ""


def _decode_hidden_injection(text: str):
    """Try common encodings; yield (scheme, decoded_snippet) that reveal an attack."""
    hits = []
    # base64
    for tok in _B64_RE.findall(text)[:50]:
        pad = tok + "=" * (-len(tok) % 4)
        try:
            raw = base64.b64decode(pad, validate=True)
            decoded = raw.decode("utf-8", "strict")
        except Exception:
            continue
        if not decoded.isprintable() and "\n" not in decoded:
            continue
        ev = _looks_like_attack(decoded)
        if ev:
            hits.append(("base64", decoded.strip()[:200]))
    # hex
    for tok in _HEX_RE.findall(text)[:50]:
        try:
            raw = bytes.fromhex(tok)
            decoded = raw.decode("utf-8", "strict")
        except Exception:
            continue
        if _looks_like_attack(decoded):
            hits.append(("hex", decoded.strip()[:200]))
    # rot13 (whole text) — only meaningful if the rotated form reveals an attack
    try:
        rot = codecs.decode(text, "rot_13")
        if _looks_like_attack(rot):
            hits.append(("rot13", rot.strip()[:200]))
    except Exception:
        pass
    return hits


def audit_text(text: str, *, kind: str, name: str, scan_permissions_name: str = "") -> list:
    """Run text-based detectors on one description/metadata blob.

    scan_permissions_name: when set (tools), also run the over-broad-permission
    name-token check against it.
    """
    findings = []
    text = _cap(text)

    # tool-poisoning (plain text)
    hit = _matches_injection(text)
    if hit:
        findings.append(Finding(
            severity="critical", category="tool-poisoning",
            subject_kind=kind, subject_name=name,
            detail="Description contains text that instructs the model reading it "
                   "(prompt-injection / tool poisoning).",
            evidence=hit,
        ))

    # encoded-content (hidden injection under base64/hex/rot13)
    for scheme, snippet in _decode_hidden_injection(text):
        findings.append(Finding(
            severity="critical", category="encoded-content",
            subject_kind=kind, subject_name=name,
            detail=f"Description hides instructions inside {scheme}-encoded content.",
            evidence=snippet,
        ))

    # over-broad-permission (description patterns)
    for rx in _DANGEROUS_DESC_RE:
        m = rx.search(text)
        if m:
            findings.append(Finding(
                severity="high", category="over-broad-permission",
                subject_kind=kind, subject_name=name,
                detail="Description implies a broad/dangerous capability.",
                evidence=m.group(0),
            ))
            break

    # over-broad-permission (tool name token)
    if scan_permissions_name:
        low = scan_permissions_name.lower()
        toks = set(re.split(r"[^a-z0-9]+", low)) | {low}
        dangerous = toks & _DANGEROUS_NAME_TOKENS
        if dangerous:
            findings.append(Finding(
                severity="high", category="over-broad-permission",
                subject_kind=kind, subject_name=name,
                detail="Tool name implies a dangerous capability "
                       f"({', '.join(sorted(dangerous))}).",
                evidence=scan_permissions_name,
            ))

    # suspicious-metadata
    if _HIDDEN_RE.search(text):
        findings.append(Finding(
            severity="medium", category="suspicious-metadata",
            subject_kind=kind, subject_name=name,
            detail="Description contains zero-width or bidirectional control "
                   "characters that hide text from human review.",
            evidence=repr(_HIDDEN_RE.search(text).group(0)),
        ))
    if _HTML_COMMENT_RE.search(text):
        findings.append(Finding(
            severity="medium", category="suspicious-metadata",
            subject_kind=kind, subject_name=name,
            detail="Description contains an HTML comment (can hide instructions).",
            evidence=_HTML_COMMENT_RE.search(text).group(0)[:120],
        ))
    if len(text) > _LONG_DESC:
        findings.append(Finding(
            severity="medium", category="suspicious-metadata",
            subject_kind=kind, subject_name=name,
            detail=f"Description is unusually long ({len(text)} chars); may bury "
                   "instructions in noise.",
            evidence=f"{len(text)} characters",
        ))

    return findings


def _tool_text(tool: dict) -> str:
    """Concatenate the auditable text of a tool: title + description + param docs."""
    parts = [tool.get("title") or "", tool.get("description") or ""]
    schema = tool.get("inputSchema") or {}
    props = (schema or {}).get("properties") or {}
    if isinstance(props, dict):
        for pname, pdef in props.items():
            if isinstance(pdef, dict) and pdef.get("description"):
                parts.append(f"{pname}: {pdef['description']}")
    return "\n".join(p for p in parts if p)


def audit_tool(tool: dict) -> list:
    name = tool.get("name") or "<unnamed>"
    text = _tool_text(tool)
    findings = audit_text(text, kind="tool", name=name, scan_permissions_name=name)
    if not (tool.get("description") or "").strip():
        findings.append(Finding(
            severity="info", category="shadow-capability",
            subject_kind="tool", subject_name=name,
            detail="Tool has no description; its behavior can't be audited from "
                   "metadata (a blind spot for the model and for reviewers).",
        ))
    return findings


def audit_resource(resource: dict) -> list:
    name = resource.get("name") or resource.get("uri") or "<unnamed>"
    return audit_text(_resource_text(resource), kind="resource", name=name)


def _prompt_text(prompt: dict) -> str:
    parts = [prompt.get("title") or "", prompt.get("description") or ""]
    for arg in prompt.get("arguments") or []:
        if isinstance(arg, dict) and arg.get("description"):
            parts.append(f"{arg.get('name', 'arg')}: {arg['description']}")
    return "\n".join(p for p in parts if p)


def _resource_text(resource: dict) -> str:
    return "\n".join(
        p for p in (resource.get("title") or "", resource.get("description") or "") if p
    )


def audit_prompt(prompt: dict) -> list:
    name = prompt.get("name") or "<unnamed>"
    return audit_text(_prompt_text(prompt), kind="prompt", name=name)


def subject_texts(catalog) -> list:
    """Yield (kind, name, text) for every auditable description in a catalog.

    Shared by offline audit and connected mode so both scan exactly the same text.
    """
    out = []
    for t in catalog.tools:
        out.append(("tool", t.get("name") or "<unnamed>", _tool_text(t)))
    for r in catalog.resources:
        out.append(("resource", r.get("name") or r.get("uri") or "<unnamed>", _resource_text(r)))
    for p in catalog.prompts:
        out.append(("prompt", p.get("name") or "<unnamed>", _prompt_text(p)))
    return out
