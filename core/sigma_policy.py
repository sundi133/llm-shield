"""Convert between Shield custom policies and Sigma rules (import / export).

Pure and deterministic. The one non-deterministic step, translating a
natural-language policy into a Sigma detection, lives in core/sigma_translate.py
and hands its output to `nl_policy_to_rule` here.

Every exported rule carries a `votal:` block (Sigma permits custom attributes)
with the Shield-side settings: stage, action, priority, and for natural-language
policies the original prompt. Re-importing an exported rule is therefore
lossless inside Shield, while other SIEMs just see a normal Sigma rule.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from core.sigma import load_rule, validate_rule

LOGSOURCE_PRODUCT = "votal"
LOGSOURCE_SERVICE = "shield"
STAGE_CATEGORY = {"input": "llm_input", "output": "llm_output"}

#: Sigma level -> custom-policy action when an imported rule does not say.
#: informational rules are detect-only (a recorded violation that passes).
LEVEL_TO_ACTION = {
    "informational": "pass",
    "low": "warn",
    "medium": "warn",
    "high": "block",
    "critical": "block",
}

ACTION_TO_LEVEL = {"pass": "informational", "warn": "medium",
                   "redact": "medium", "block": "high"}

VALID_ACTIONS = ("pass", "warn", "redact", "block")


class SigmaImportError(ValueError):
    """An otherwise valid rule cannot become a policy (e.g. no stage)."""


def logsource(stage: str) -> dict:
    return {"product": LOGSOURCE_PRODUCT, "service": LOGSOURCE_SERVICE,
            "category": STAGE_CATEGORY[stage]}


def _stage_from_rule(rule: dict) -> Optional[str]:
    votal = rule.get("votal") if isinstance(rule.get("votal"), dict) else {}
    if votal.get("stage") in STAGE_CATEGORY:
        return votal["stage"]
    category = str((rule.get("logsource") or {}).get("category") or "").lower()
    if category in ("llm_input", "input", "prompt"):
        return "input"
    if category in ("llm_output", "output", "response", "completion"):
        return "output"
    return None


def _date(policy: dict) -> str:
    raw = policy.get("created_at") or ""
    try:
        return datetime.fromisoformat(str(raw)).strftime("%Y-%m-%d")
    except ValueError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _rule_id(policy: dict) -> str:
    pid = str(policy.get("policy_id") or "")
    try:
        return str(uuid.UUID(pid))
    except ValueError:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"votal-policy:{pid}"))


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

def rule_to_policy_data(rule: dict, stage: Optional[str] = None,
                        action: Optional[str] = None) -> tuple[dict, str]:
    """Turn a validated Sigma rule into (policy_data, stage) for save_custom_policy.

    Precedence for stage/action: explicit argument, then the rule's `votal:`
    block, then logsource.category / level. A rule exported from a
    natural-language policy (votal.source_format = natural_language) is restored
    as that natural-language policy, so a round trip is lossless.
    """
    validate_rule(rule)
    votal = rule.get("votal") if isinstance(rule.get("votal"), dict) else {}

    resolved_stage = stage or _stage_from_rule(rule)
    if resolved_stage not in STAGE_CATEGORY:
        raise SigmaImportError(
            "cannot tell whether this rule is an input or output policy: pass "
            "stage, or set logsource.category to llm_input / llm_output")

    resolved_action = action or votal.get("action") or LEVEL_TO_ACTION.get(
        str(rule.get("level") or "medium").lower(), "warn")
    if resolved_action not in VALID_ACTIONS:
        raise SigmaImportError(f"invalid action '{resolved_action}'")

    title = str(rule["title"]).strip()
    description = str(rule.get("description") or title).strip()
    data: dict[str, Any] = {
        "name": title[:100],
        "description": description[:500],
        "action": resolved_action,
        "stage": resolved_stage,
        "enabled": bool(votal.get("enabled", True)),
        "priority": int(votal.get("priority", 100)),
    }
    if votal.get("confidence_threshold") is not None:
        data["confidence_threshold"] = float(votal["confidence_threshold"])

    if votal.get("source_format") == "natural_language" and votal.get("prompt"):
        data["format"] = "natural_language"
        data["prompt"] = str(votal["prompt"])
        data["multi_turn"] = bool(votal.get("multi_turn", False))
    else:
        stored = {k: v for k, v in rule.items() if k != "votal"}
        data["format"] = "sigma"
        data["sigma_rule"] = stored
    return data, resolved_stage


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _votal_block(policy: dict, source_format: str) -> dict:
    block = {
        "source_format": source_format,
        "stage": policy.get("stage", "input"),
        "action": policy.get("action", "warn"),
        "priority": policy.get("priority", 100),
        "enabled": policy.get("enabled", True),
        "policy_id": policy.get("policy_id"),
    }
    if source_format == "natural_language":
        block["prompt"] = policy.get("prompt", "")
        block["confidence_threshold"] = policy.get("confidence_threshold", 0.8)
        block["multi_turn"] = policy.get("multi_turn", False)
    return block


def sigma_policy_to_rule(policy: dict) -> dict:
    """Export a Sigma-format policy: its stored rule plus the votal: block."""
    rule = dict(policy.get("sigma_rule") or {})
    rule.setdefault("id", _rule_id(policy))
    rule.setdefault("logsource", logsource(policy.get("stage", "input")))
    rule["votal"] = _votal_block(policy, "sigma")
    validate_rule(rule)
    return rule


def nl_policy_to_rule(policy: dict, keywords: list[str], patterns: list[str]) -> dict:
    """Build a Sigma rule for a natural-language policy from translated terms.

    `keywords` become a keyword search on the message; `patterns` become
    `message|re` alternatives. The detection approximates the policy (an LLM
    judged it; Sigma cannot), so the rule is marked experimental, and the
    original prompt rides in the votal: block so Shield can restore it exactly.
    """
    keywords = [k.strip() for k in keywords if isinstance(k, str) and k.strip()]
    patterns = [p.strip() for p in patterns if isinstance(p, str) and p.strip()]
    if not keywords and not patterns:
        raise SigmaImportError(
            "translation produced no keywords or patterns for this policy")

    detection: dict[str, Any] = {}
    names = []
    if keywords:
        detection["keywords"] = keywords
        names.append("keywords")
    if patterns:
        detection["patterns"] = {"message|re|i": patterns}
        names.append("patterns")
    detection["condition"] = " or ".join(names)

    stage = policy.get("stage", "input")
    rule = {
        "title": policy.get("name", "Votal policy"),
        "id": _rule_id(policy),
        "status": "experimental",
        "description": (policy.get("description") or "").strip()
        or policy.get("name", ""),
        "author": "Votal Shield (translated from a natural-language policy)",
        "date": _date(policy),
        "logsource": logsource(stage),
        "detection": detection,
        "level": ACTION_TO_LEVEL.get(policy.get("action", "warn"), "medium"),
        "tags": ["votal.custom_policy", f"votal.stage.{stage}"],
        "votal": _votal_block(policy, "natural_language"),
    }
    # Regexes from a model may not compile; validate drops the rule loudly.
    load_rule(rule)
    return rule
