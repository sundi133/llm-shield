"""Which targets a call may use, and in what order.

Spec: docs/specs/gateway-routing-failover.md, sections 3.2 and 4.1. A route's
`targets` is the most a call can reach; rules and budgets only narrow it, and
failover (dispatch.py) never leaves the eligible list this returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.llm_gateway import config


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


def plan(snapshot: config.Snapshot, route: dict, ctx: CallContext):
    """A Plan, or a Refusal when nothing may serve this call."""
    eligible = list(route.get("targets") or [])
    rule_note = ""
    order, skipped = [], []
    for tid in eligible:
        t = snapshot.targets.get(tid)
        if not isinstance(t, dict):
            skipped.append({"target": tid, "reason": "missing"})
        elif not t.get("enabled", True):
            skipped.append({"target": tid, "reason": "disabled"})
        else:
            order.append(t)
    if not order:
        return Refusal(route["name"], f"no available target for route '{route['name']}'", "no_target")
    return Plan(route=route, targets=order, rule=rule_note, skipped=skipped)
