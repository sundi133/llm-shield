"""Which targets a call may use, and in what order.

Spec: docs/specs/gateway-routing-failover.md, sections 3.2 and 4.1. A route's
`targets` is the most a call can reach; rules and budgets only narrow it, and
failover (dispatch.py) never leaves the eligible list this returns.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from core.llm_gateway import config, health


@dataclass
class CallContext:
    tenant_id: str
    agent: str = ""
    role: str = ""
    data_class: str = ""
    flagged: tuple = ()                 # guardrails that did not pass on an allowed input
    prompt_chars: int = 0


@dataclass
class Plan:
    route: dict
    targets: list                       # target dicts, in the order to try
    rule: str = ""                      # which rule decided, for x_shield and audit
    budget: str = "ok"                  # ok | warn | fallback
    skipped: list = field(default_factory=list)   # [{target, reason}]
    prompt_chars: int = 0               # for a token estimate when a stream reports no usage
    spend: float = 0.0


@dataclass
class Refusal:
    route: str
    reason: str
    code: str                           # deny | budget | no_target


def match_route(snapshot: Optional[config.Snapshot], model: str) -> Optional[dict]:
    if snapshot is None or not model or not config.enabled():
        return None
    r = snapshot.routes.get(model)
    return r if isinstance(r, dict) and r.get("enabled", True) else None


def plan(snapshot: config.Snapshot, route: dict, ctx: CallContext, *, rng=random.random):
    """A Plan, or a Refusal when nothing may serve this call."""
    eligible = list(route.get("targets") or [])
    rule_note = ""
    for i, rule in enumerate(route.get("rules") or []):
        if not rule or not matches(rule.get("when") or {}, ctx):
            continue
        rule_note = f"rules[{i}]" + (f": {rule['note']}" if rule.get("note") else "")
        if "deny" in rule:
            return Refusal(route["name"], rule["deny"], "deny")
        # `use` narrows: only targets the route already lists, in the rule's order.
        eligible = [t for t in rule.get("use") or [] if t in eligible]
        loc = (rule.get("when") or {}).get("location_required")
        if loc:
            eligible = [t for t in eligible if (snapshot.targets.get(t) or {}).get("location") == loc]
        break
    budget_state, spend = "ok", 0.0
    budget = route.get("budget") or {}
    if budget.get("monthly"):
        from core.llm_gateway import usage
        spend = float(snapshot.spend.get(route["name"], 0.0)) + usage.local_spend(ctx.tenant_id, route["name"])
        if spend >= float(budget["monthly"]):
            usage.maybe_alert_budget(ctx.tenant_id, route["name"], spend, budget)
            at = budget.get("at_limit", "warn")
            if at == "block":
                return Refusal(route["name"], f"the monthly budget for route '{route['name']}' is spent "
                                              f"({spend:.2f} of {float(budget['monthly']):.2f} "
                                              f"{budget.get('currency', 'USD')})", "budget")
            budget_state = at
            if at == "fallback":
                eligible = [t for t in eligible if t in (budget.get("fallback_targets") or [])]
    order, skipped = [], []
    for tid in eligible:
        t = snapshot.targets.get(tid)
        if not isinstance(t, dict):
            skipped.append({"target": tid, "reason": "missing"})
        elif not t.get("enabled", True):
            skipped.append({"target": tid, "reason": "disabled"})
        elif not health.available(ctx.tenant_id, tid):
            skipped.append({"target": tid, "reason": "circuit_open"})
        else:
            order.append(t)
    if not order:
        why = f" under {rule_note.split(':')[0]}" if rule_note else ""
        return Refusal(route["name"], f"no available target for route '{route['name']}'{why}", "no_target")
    return Plan(route=route, targets=_order(route, order, ctx, rng), rule=rule_note, skipped=skipped,
                budget=budget_state, prompt_chars=ctx.prompt_chars, spend=spend)


def matches(when: dict, ctx: CallContext) -> bool:
    """Every condition present must hold. `location_required` is not a test:
    it narrows the targets of a rule that matched."""
    tests = 0
    if "flagged" in when:
        tests += 1
        if not set(when["flagged"]) & set(ctx.flagged):
            return False
    if "data_class" in when:
        tests += 1
        if ctx.data_class not in {v.lower() for v in when["data_class"]}:
            return False
    if "agent" in when:
        tests += 1
        if not ctx.agent or ctx.agent not in when["agent"]:
            return False
    if "role" in when:
        tests += 1
        if not ctx.role or ctx.role not in when["role"]:
            return False
    if "prompt_tokens_over" in when:
        tests += 1
        if ctx.prompt_chars // 4 <= int(when["prompt_tokens_over"]):
            return False
    return tests > 0 or "location_required" in when


def _order(route: dict, targets: list, ctx: CallContext, rng) -> list:
    """The strategy's order. Priority keeps the route's order; the others
    reorder the same eligible targets and never add one."""
    strategy = route.get("strategy", "priority")
    if strategy == "lowest_latency":
        # Unmeasured targets first, so a new or recovered target gets measured.
        def key(t):
            ms = health.latency(ctx.tenant_id, t["id"])
            return (ms is not None, ms or 0.0)
        return sorted(targets, key=key)
    if strategy == "lowest_cost":
        def cost(t):
            p = t.get("price")
            if not p:
                return (1, 0.0)
            return (0, float(p.get("input_per_mtok") or 0) + float(p.get("output_per_mtok") or 0))
        return sorted(targets, key=cost)
    if strategy == "weighted":
        # A weighted shuffle (Efraimidis-Spirakis): the higher the weight, the
        # likelier first; zero-weight targets stay as fallbacks, in route order.
        weights = route.get("weights") or {}
        weighted = [t for t in targets if weights.get(t["id"], 0) > 0]
        rest = [t for t in targets if weights.get(t["id"], 0) <= 0]
        weighted.sort(key=lambda t: -(max(rng(), 1e-12) ** (1.0 / weights[t["id"]])))
        return weighted + rest
    return targets
