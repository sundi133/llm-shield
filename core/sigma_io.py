"""Sigma import / export / validate for custom policies, shared by both APIs.

Used by the data-plane router (api/routes_custom_policies.py) and the portal
router (api/routes_tenant_self.py) so the two surfaces behave identically.
Exporting a natural-language policy needs the guardrail LLM; where none is
reachable that policy is reported in `errors` and the rest still export.
"""
from __future__ import annotations

from typing import Any, Optional, Union

from core.sigma import (
    SigmaRuleError,
    check_fields,
    dump_rule,
    dump_rules,
    evaluate_rules,
    parse_documents,
    policy_event,
    translate_fields,
    validate_rule,
)
from core.sigma_policy import rule_to_policy_data, sigma_policy_to_rule
from storage.custom_policies import save_custom_policy

Source = Union[str, dict, list]

#: Bounds on sample testing (it runs on the request that asks for it).
MAX_SAMPLES = 20
MAX_SAMPLE_CHARS = 20_000
_SAMPLE_CONTEXT_KEYS = ("user_role", "session_id", "agent_id", "tool_name", "tool_input")


def prepare_rule(doc: Any, field_map: Optional[dict] = None) -> dict:
    """Validate a rule, translate its field names, and require Shield fields.
    The single definition of "this rule can work in Shield"."""
    if not isinstance(doc, dict):
        raise SigmaRuleError("each Sigma document must be a mapping")
    validate_rule(doc)
    rule = translate_fields(doc, field_map)
    check_fields(rule)
    return rule


def _sample_event(sample: Any) -> tuple[Optional[dict], Optional[str]]:
    if isinstance(sample, str):
        text, ctx, stage = sample, {}, "input"
    elif isinstance(sample, dict):
        text = str(sample.get("message") or "")
        ctx = {k: sample.get(k) for k in _SAMPLE_CONTEXT_KEYS if sample.get(k) is not None}
        stage = sample.get("stage") if sample.get("stage") in ("input", "output") else "input"
    else:
        return None, "a sample must be text or an object with a message"
    if len(text) > MAX_SAMPLE_CHARS:
        return None, f"sample exceeds {MAX_SAMPLE_CHARS} characters"
    return policy_event(text, ctx, stage), None


def validate_sigma(source: Source, samples: Optional[list] = None,
                   field_map: Optional[dict] = None) -> dict:
    """Validate rule text without storing it. Never raises for a bad rule.

    With `samples`, each valid rule is run against each sample through the same
    engine as live traffic (normalization included) and `sample_results` lists
    which matched, so an author can prove a rule fires before saving it.
    """
    try:
        docs = parse_documents(source)
    except SigmaRuleError as e:
        return {"valid": False, "rules": [], "errors": [{"index": 0, "error": str(e)}]}
    rules, errors, prepared = [], [], []
    for index, doc in enumerate(docs):
        title = doc.get("title") if isinstance(doc, dict) else None
        try:
            rule = prepare_rule(doc, field_map)
            prepared.append((index, rule))
            rules.append({"index": index, "title": title,
                          "level": doc.get("level"),
                          "category": (doc.get("logsource") or {}).get("category")})
        except SigmaRuleError as e:
            errors.append({"index": index, "title": title, "error": str(e)})
    result = {"valid": not errors and bool(rules), "rules": rules, "errors": errors}

    if samples:
        sample_results = []
        for s_index, sample in enumerate(list(samples)[:MAX_SAMPLES]):
            event, problem = _sample_event(sample)
            if problem:
                sample_results.append({"sample_index": s_index, "error": problem})
                continue
            outcomes = evaluate_rules([rule for _, rule in prepared], event)
            for (r_index, rule), outcome in zip(prepared, outcomes):
                sample_results.append({
                    "sample_index": s_index, "rule_index": r_index,
                    "title": rule.get("title"), "matched": outcome.matched,
                    "selections": outcome.selections, "error": outcome.error,
                })
        result["sample_results"] = sample_results
    return result


def import_sigma(tenant_id: str, source: Source, *, stage: Optional[str] = None,
                 action: Optional[str] = None, dry_run: bool = False,
                 created_by: str = "system", field_map: Optional[dict] = None) -> dict:
    """Create one policy per rule. Rules are independent: a bad one is reported
    in `errors` and the others still import. Field names are translated
    (built-in aliases, then `field_map`) and a rule that still reads a field
    Shield never provides is an error, also in a dry run. Raises SigmaRuleError
    only when the input cannot be read at all."""
    docs = parse_documents(source)
    created, planned, errors = [], [], []
    for index, doc in enumerate(docs):
        title = doc.get("title") if isinstance(doc, dict) else None
        try:
            rule = prepare_rule(doc, field_map)
            policy_data, resolved_stage = rule_to_policy_data(rule, stage, action)
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
