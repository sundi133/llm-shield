"""The declarative gateway policy language: parse, validate, compile, evaluate.

A policy document says which roles may call which tools, with an explicit default:

    default: deny
    rules:
      - id: allow-reads
        effect: allow
        roles: [analyst, admin]
        tools: [balance_get, statement_generate]
      - id: deny-writes
        effect: deny
        roles: ["*"]
        tools: ["*"]

It compiles — once, in the admin plane, at publish time — to an immutable
snapshot with a precompiled ``tool -> rule indices`` index, so the guard path
decides a call with a dict lookup and a short role check, never a scan and never
a YAML parse. ``evaluate`` is the single source of the allow/deny logic: the
admin ``simulate`` endpoint and the guard path both run it, so what an operator
previews is exactly what enforces.

Validation is Pydantic (no new dependency; mirrors ProfileRequest's extra=forbid).
Documents may be authored as YAML or JSON. M2 Task 1. Spec:
docs/specs/spec-mcp-gateway-m2-policy-engine.md.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

SCHEMA = 1                      # the language schema version, stamped on snapshots
_MAX_RULES = 1000
_WILDCARD = "*"


class PolicyError(ValueError):
    """A document that cannot be parsed or validated. Message is operator-facing."""


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(..., min_length=1, max_length=128)
    effect: str = Field(..., pattern="^(allow|deny)$")
    roles: list[str] = Field(default_factory=lambda: [_WILDCARD], max_length=200)
    tools: list[str] = Field(default_factory=lambda: [_WILDCARD], max_length=500)

    @field_validator("roles", "tools")
    @classmethod
    def _non_empty_strings(cls, v: list[str]) -> list[str]:
        out = []
        for item in v:
            s = str(item).strip()
            if not s:
                raise ValueError("entries must be non-empty")
            if s not in out:
                out.append(s)
        if not out:
            # An empty list would silently match nothing; a rule that matches
            # nothing is a mistake, not a policy. Default to wildcard explicitly.
            return [_WILDCARD]
        return out


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default: str = Field("deny", pattern="^(allow|deny)$")
    rules: list[PolicyRule] = Field(default_factory=list, max_length=_MAX_RULES)

    @field_validator("rules")
    @classmethod
    def _unique_ids(cls, rules: list[PolicyRule]) -> list[PolicyRule]:
        seen = set()
        for r in rules:
            if r.id in seen:
                raise ValueError(f"duplicate rule id: {r.id!r}")
            seen.add(r.id)
        return rules


def _as_mapping(raw: Union[str, dict, None]) -> dict:
    """Accept a YAML string, a JSON string, or a dict. Empty = an empty policy."""
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        import yaml  # pyyaml is already a dependency
        try:
            loaded = yaml.safe_load(raw)
        except Exception as e:                      # noqa: BLE001
            raise PolicyError(f"not valid YAML/JSON: {e}")
        if loaded is None:
            return {}
        if not isinstance(loaded, dict):
            raise PolicyError("a policy document must be a mapping "
                              "(default: ..., rules: [...])")
        return loaded
    raise PolicyError("a policy document must be text or an object")


def parse_document(raw: Union[str, dict, None]) -> PolicyDocument:
    """Parse + validate a document, or raise PolicyError with a legible message."""
    mapping = _as_mapping(raw)
    try:
        return PolicyDocument.model_validate(mapping)
    except ValidationError as e:
        raise PolicyError("; ".join(_fmt_errors(e)))


def validate_document(raw: Union[str, dict, None]) -> tuple[bool, list[str]]:
    """(ok, errors). Never raises — for the validate endpoint."""
    try:
        parse_document(raw)
        return True, []
    except PolicyError as e:
        return False, str(e).split("; ")


def _fmt_errors(e: ValidationError) -> list[str]:
    out = []
    for err in e.errors():
        loc = ".".join(str(p) for p in err.get("loc", ()))
        out.append(f"{loc or 'document'}: {err.get('msg', 'invalid')}")
    return out


def document_sha(raw: Union[str, dict, None]) -> str:
    """A stable hash of a document's meaning (normalized, not its formatting)."""
    doc = parse_document(raw)
    blob = json.dumps(doc.model_dump(), sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def compile_document(doc: PolicyDocument, *, source_sha: str = "") -> dict:
    """Compile a validated document to an immutable snapshot body.

    Rules keep document order (lower index = higher precedence: first match
    wins). ``index`` maps an explicit tool to the rule indices that mention it;
    ``any_tool`` holds the indices of rules whose tools are ["*"]. Evaluation
    merges the two in order — no scan over all rules.
    """
    rules: list[dict] = []
    index: dict[str, list[int]] = {}
    any_tool: list[int] = []
    for i, rule in enumerate(doc.rules):
        rules.append({"id": rule.id, "effect": rule.effect,
                      "roles": list(rule.roles), "tools": list(rule.tools)})
        if _WILDCARD in rule.tools:
            any_tool.append(i)
        else:
            for t in rule.tools:
                index.setdefault(t, []).append(i)
    return {
        "schema": SCHEMA,
        "default": doc.default,
        "rules": rules,
        "index": index,
        "any_tool": any_tool,
        "source_sha": source_sha,
        "compiled_at": int(time.time()),
    }


def compile_source(raw: Union[str, dict, None]) -> dict:
    """parse + compile in one step (admin side)."""
    doc = parse_document(raw)
    return compile_document(doc, source_sha=document_sha(raw))


def _role_match(rule: dict, role: str) -> bool:
    roles = rule.get("roles") or []
    return _WILDCARD in roles or (role or "") in roles


def evaluate(snapshot: dict, role: str, tool: str) -> dict:
    """Decide one (role, tool) against a compiled snapshot.

    Returns {effect, rule_id, default_used}. The ONE source of allow/deny logic —
    reused by the admin simulate endpoint and the guard path, so a preview and an
    enforcement can never disagree.
    """
    if not isinstance(snapshot, dict):
        return {"effect": "deny", "rule_id": None, "default_used": True}
    rules = snapshot.get("rules") or []
    index = snapshot.get("index") or {}
    any_tool = snapshot.get("any_tool") or []
    candidates = sorted(set(index.get(tool, [])) | set(any_tool))
    for i in candidates:
        if 0 <= i < len(rules) and _role_match(rules[i], role):
            return {"effect": rules[i].get("effect", "deny"),
                    "rule_id": rules[i].get("id"), "default_used": False}
    return {"effect": snapshot.get("default", "deny"),
            "rule_id": None, "default_used": True}


def starter_document() -> dict:
    """The explicit allow-all a new (declarative) tenant starts with, visible for
    an operator to narrow — not a hidden default. (Used by M2 Task 2.)"""
    return {"default": "allow", "rules": []}
