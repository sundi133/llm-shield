"""Sigma import / export / validate for custom policies, shared by both APIs.

Used by the data-plane router (api/routes_custom_policies.py) and the portal
router (api/routes_tenant_self.py) so the two surfaces behave identically.
Exporting a natural-language policy needs the guardrail LLM; where none is
reachable that policy is reported in `errors` and the rest still export.
"""
from __future__ import annotations

from typing import Any, Optional, Union

from core.sigma import SigmaRuleError, dump_rule, dump_rules, parse_documents, validate_rule
from core.sigma_policy import rule_to_policy_data, sigma_policy_to_rule
from storage.custom_policies import save_custom_policy

Source = Union[str, dict, list]


def validate_sigma(source: Source) -> dict:
    """Validate rule text without storing it. Never raises for a bad rule."""
    try:
        docs = parse_documents(source)
    except SigmaRuleError as e:
        return {"valid": False, "rules": [], "errors": [{"index": 0, "error": str(e)}]}
    rules, errors = [], []
    for index, doc in enumerate(docs):
        title = doc.get("title") if isinstance(doc, dict) else None
        try:
            if not isinstance(doc, dict):
                raise SigmaRuleError("each Sigma document must be a mapping")
            validate_rule(doc)
            rules.append({"index": index, "title": title,
                          "level": doc.get("level"),
                          "category": (doc.get("logsource") or {}).get("category")})
        except SigmaRuleError as e:
            errors.append({"index": index, "title": title, "error": str(e)})
    return {"valid": not errors and bool(rules), "rules": rules, "errors": errors}


def import_sigma(tenant_id: str, source: Source, *, stage: Optional[str] = None,
                 action: Optional[str] = None, dry_run: bool = False,
                 created_by: str = "system") -> dict:
    """Create one policy per rule. Rules are independent: a bad one is reported
    in `errors` and the others still import. Raises SigmaRuleError only when the
    input cannot be read at all."""
    docs = parse_documents(source)
    created, planned, errors = [], [], []
    for index, doc in enumerate(docs):
        title = doc.get("title") if isinstance(doc, dict) else None
        try:
            if not isinstance(doc, dict):
                raise ValueError("each Sigma document must be a mapping")
            policy_data, resolved_stage = rule_to_policy_data(doc, stage, action)
            if dry_run:
                planned.append(policy_data)
                continue
            created.append(save_custom_policy(tenant_id=tenant_id, policy_data=policy_data,
                                              created_by=created_by, stage=resolved_stage))
        except ValueError as e:
            errors.append({"index": index, "title": title, "error": str(e)})
    return {"dry_run": dry_run, "created": created, "would_create": planned, "errors": errors}


async def policy_to_rule(policy: dict, translate: bool = True) -> dict:
    """Export one policy as a Sigma rule. Raises ValueError with a reason."""
    if policy.get("format") == "sigma":
        return sigma_policy_to_rule(policy)
    if not translate:
        raise ValueError("natural-language policy: pass translate=true to convert it")
    from core.sigma_translate import translate_nl_policy  # needs the guardrail LLM
    try:
        return await translate_nl_policy(policy)
    except ValueError:
        raise
    except Exception as e:  # LLM unreachable, timeout, bad response
        raise ValueError(f"translation failed: {e}") from e


async def export_sigma(policies: list[dict], translate: bool = True) -> dict:
    """Export policies as Sigma. One policy failing does not stop the rest."""
    rules: list[Any] = []
    errors = []
    for policy in policies:
        try:
            rules.append(await policy_to_rule(policy, translate))
        except Exception as e:
            errors.append({"policy_id": policy.get("policy_id"),
                           "policy_name": policy.get("name"), "error": str(e)})
    return {"count": len(rules), "yaml": dump_rules(rules) if rules else "",
            "rules": rules, "errors": errors}


async def export_one(policy: dict, translate: bool = True) -> dict:
    rule = await policy_to_rule(policy, translate)
    return {"rule": rule, "yaml": dump_rule(rule)}
