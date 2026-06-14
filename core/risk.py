"""Zero-config risk classifier for agent tool calls.

Scores a tool call as low / medium / high with **no policy configured** — the
"dangerous call" signal that powers observe-mode discovery, the OpenAPI tool
generator's safe defaults, and the MCP proxy's annotations.

Pure, CPU-only, no I/O — runs anywhere (data plane, in-VPC). Heuristics only;
it never *blocks* (that's RBAC/guardrails) — it ranks attention.

Signals, strongest wins:
  1. Tool-name verb/noun taxonomy (transfer, delete, exec, send, ...).
  2. HTTP method, when the tool came from an OpenAPI operation.
  3. Argument sniffing (money amounts, SSN / card / email, file paths).
"""

from __future__ import annotations

import re
from typing import Optional

_TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokenize(name: str) -> list[str]:
    """Split a tool name into lowercase word tokens (snake, kebab, camelCase)."""
    parts: list[str] = []
    for chunk in _TOKEN_SPLIT_RE.split(name or ""):
        if not chunk:
            continue
        parts.extend(_CAMEL_RE.split(chunk))
    return [p.lower() for p in parts if p]

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

# ── Name taxonomy (whole-token match, not substring) ─────────────────
_HIGH_TOKENS = {
    "transfer", "payment", "pay", "wire", "refund", "payout",
    "delete", "drop", "destroy", "remove", "purge", "truncate", "wipe",
    "exec", "shell", "command", "sudo", "deploy", "terminate", "shutdown",
    "grant", "revoke", "privilege", "privileges", "password", "passwords",
    "secret", "secrets", "credential", "credentials", "key", "keys",
}
_MEDIUM_TOKENS = {
    "send", "email", "mail", "post", "publish", "message", "notify", "sms",
    "create", "update", "modify", "edit", "write", "upload", "insert", "set",
    "charge", "invoice", "order", "orders", "subscribe", "share",
    "export", "download",
}
_LOW_VERBS = {
    "get", "list", "read", "lookup", "search", "find", "fetch", "view",
    "show", "describe", "status", "health", "query",
}

# ── Argument sniffing ────────────────────────────────────────────────
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_MONEY_KEYS = ("amount", "total", "price", "balance", "sum", "value", "cost")
_PATH_RE = re.compile(r"/[\w.-]+/[\w./-]+|[A-Za-z]:\\")

_METHOD_RISK = {
    "GET": LOW, "HEAD": LOW, "OPTIONS": LOW,
    "POST": MEDIUM, "PUT": MEDIUM, "PATCH": MEDIUM,
    "DELETE": HIGH,
}


def _name_risk(tool_name: str) -> tuple[str, Optional[str]]:
    tokens = _tokenize(tool_name)
    if not tokens:
        return LOW, None
    # A high-risk token (delete, transfer, secret, ...) dominates intent —
    # even "get_secret" is sensitive.
    for tok in tokens:
        if tok in _HIGH_TOKENS:
            return HIGH, f"name verb '{tok}'"
    # A leading read verb (list_orders, get_balance) means a read — the noun
    # after it doesn't escalate.
    if tokens[0] in _LOW_VERBS:
        return LOW, "read-style verb"
    for tok in tokens:
        if tok in _MEDIUM_TOKENS:
            return MEDIUM, f"name verb '{tok}'"
    for tok in tokens:
        if tok in _LOW_VERBS:
            return LOW, "read-style verb"
    return LOW, None


def _arg_risk(arguments: Optional[dict]) -> tuple[str, Optional[str]]:
    if not arguments:
        return LOW, None
    try:
        blob = " ".join(f"{k}={v}" for k, v in arguments.items())
    except Exception:
        return LOW, None
    if _SSN_RE.search(blob):
        return HIGH, "ssn in arguments"
    if _CARD_RE.search(blob):
        return HIGH, "card number in arguments"
    for k, v in arguments.items():
        if k.lower() in _MONEY_KEYS and _looks_numeric(v):
            return MEDIUM, f"money field '{k}' in arguments"
    if _EMAIL_RE.search(blob):
        return MEDIUM, "email address in arguments"
    if _PATH_RE.search(blob):
        return MEDIUM, "filesystem path in arguments"
    return LOW, None


def _looks_numeric(v) -> bool:
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        try:
            float(v.replace(",", "").replace("$", "").strip())
            return True
        except ValueError:
            return False
    return False


def score_tool(
    tool_name: str,
    *,
    method: Optional[str] = None,
    arguments: Optional[dict] = None,
) -> dict:
    """Score a tool / tool call. Returns {risk, reason, signals}.

    ``method`` is the HTTP verb when the tool came from an OpenAPI operation.
    ``arguments`` is the call payload (omit when scoring a tool definition).
    The highest individual signal wins; ``reason`` explains that signal.
    """
    signals: list[tuple[str, str]] = []

    nr, nreason = _name_risk(tool_name)
    if nreason:
        signals.append((nr, nreason))

    if method:
        mr = _METHOD_RISK.get(method.upper(), MEDIUM)
        signals.append((mr, f"http {method.upper()}"))

    ar, areason = _arg_risk(arguments)
    if areason:
        signals.append((ar, areason))

    if not signals:
        return {"risk": LOW, "reason": "no risk signals", "signals": []}

    top = max(signals, key=lambda s: _ORDER[s[0]])
    return {
        "risk": top[0],
        "reason": top[1],
        "signals": [{"risk": r, "reason": why} for r, why in signals],
    }


def is_dangerous(tool_name: str, *, method: Optional[str] = None,
                 arguments: Optional[dict] = None) -> bool:
    """Convenience: True when the call scores high."""
    return score_tool(tool_name, method=method, arguments=arguments)["risk"] == HIGH
