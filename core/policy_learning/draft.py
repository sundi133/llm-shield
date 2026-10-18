"""A least-privilege draft policy for one agent, from what it was seen doing.

Spec: docs/specs/policy-from-purpose.md, section 4.2. Deterministic, and never
more than the evidence: the model step (core/policy_learning/purpose.py) may
add lines it marks as implied by the purpose, but nothing here grants a tool,
a resource or a role the agent was not seen using, and nothing changes the
agent until a person applies the lines they accept (section 4.3).

  policydraft:{tenant}:{agent}   JSON draft, TTL 30 days
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from typing import Any, Optional

from core.policy_learning import observe

KINDS = ("tool", "resource", "approval", "identity")
STATUSES = ("pending", "accepted", "rejected", "stale")
RISKS = ("low", "medium", "high")
CANDIDATES_MAX = 200
RESOURCE_ITEMS_MAX = 10

#: Verbs that move money, delete, send outside, change access or run code.
HIGH_VERBS = frozenset("""transfer pay payment payout refund charge wire withdraw delete del drop
remove purge destroy truncate wipe send post email mail sms share publish upload export grant
revoke invite exec execute run shell command deploy write""".split())
MONEY_VERBS = frozenset("transfer pay payment payout refund charge wire withdraw".split())
MEDIUM_VERBS = frozenset("create update set put patch add insert modify edit save rename move "
                         "assign approve close open start stop".split())


class DraftError(ValueError):
    """A draft cannot be built; carries the HTTP status the route should use."""

    def __init__(self, message: str, status: int = 409, code: str = "cannot_draft"):
        super().__init__(message)
        self.status, self.code = status, code


def _words(tool: str) -> list[str]:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", tool or "")
    return [w for w in re.split(r"[^a-z0-9]+", snake.lower()) if w]


def risk(tool: str, *, approval_tools: set, sanitized_tools: set) -> tuple[str, str]:
    """(risk, why) for a tool, from its name and the tenant's existing rules."""
    words = set(_words(tool))
    if tool in approval_tools:
        return "high", "already needs an approval"
    if tool in sanitized_tools:
        return "high", "has a data-sanitization policy"
    hit = sorted(words & HIGH_VERBS)
    if hit:
        return "high", f"its name says it can {hit[0]}"
    hit = sorted(words & MEDIUM_VERBS)
    if hit:
        return "medium", f"its name says it can {hit[0]}"
    return "low", "reads"


def is_money(tool: str) -> bool:
    return bool(set(_words(tool)) & MONEY_VERBS)


def _draft_key(tenant_id: str, agent: str) -> str:
    return f"policydraft:{tenant_id}:{agent}"


def load(tenant_id: str, agent: str) -> Optional[dict]:
    from storage.tenant_store import kv_get
    d = kv_get(_draft_key(tenant_id, agent))
    return d if isinstance(d, dict) else None


def save(tenant_id: str, agent: str, draft: dict) -> None:
    from storage.tenant_store import kv_set
    kv_set(_draft_key(tenant_id, agent), draft, ttl=observe.ttl_seconds())


def agent_record(tenant_id: str, agent: str) -> Optional[dict]:
    from storage.tenant_store import kv_get
    agents = kv_get(f"agents:{tenant_id}") or {}
    rec = agents.get(agent) if isinstance(agents, dict) else None
    return rec if isinstance(rec, dict) else None


def tenant_context(tenant_id: str, agent: str) -> dict:
    """The tenant rules a draft must respect: tools under an approval rule for
    this agent, tools with a sanitization policy, and the tenant's tools."""
    approval_tools, sanitized, tools = set(), set(), set()
    try:
        from storage.agentic_control_plane import get_control_plane_config
        for rule in ((get_control_plane_config(tenant_id).get("approvals") or {}).get("rules") or []):
            agents = rule.get("agent_keys") or []
            if not agents or agent in agents:
                approval_tools.update(rule.get("tool_names") or [])
    except Exception:
        pass
    try:
        from storage import tool_catalog
        _, rows, _, _ = tool_catalog.catalog(tenant_id)
        for row in rows:
            tools.add(row["tool"])
            if row.get("sanitization_count") or row.get("audit_required"):
                sanitized.add(row["tool"])
    except Exception:
        pass
    return {"approval_tools": approval_tools, "sanitized_tools": sanitized, "tools": tools}


def _qid(*parts: str) -> str:
    return ":".join(parts)


def _digest(obs: list[dict], description: str) -> str:
    raw = json.dumps([description, [(e["tool"], e["role"], e.get("count")) for e in obs]], sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build(tenant_id: str, agent: str, *, window_days: int = 14, created_by: str = "",
          model: Optional[dict] = None, answers: Optional[dict] = None,
          previous: Optional[dict] = None) -> dict:
    """The draft for one agent. `model`: the purpose step's validated output
    (core/policy_learning/purpose.py) or None. `answers`: question id -> option.
    Statuses and answers from `previous` carry over to lines with the same id."""
    rec = agent_record(tenant_id, agent)
    obs = observe.read(tenant_id, agent, window_days)
    if rec is None:
        if obs:
            raise DraftError(f"agent '{agent}' is not registered; register it first, then draft "
                             f"its policy from what it was seen doing", 409, "unregistered_agent")
        raise DraftError(f"no agent '{agent}'", 404, "no_agent")
    description = (rec.get("description") or "").strip()
    if not obs and not description and not model:
        raise DraftError("nothing to learn from yet: describe the agent in the registry, or let "
                         "it run through Shield for a while", 409, "nothing_to_learn")

    ctx = tenant_context(tenant_id, agent)
    prev_items = {i["id"]: i for i in (previous or {}).get("items") or []}
    answers = {**((previous or {}).get("answers") or {}), **(answers or {})}

    items: dict[str, dict] = {}
    questions: list[dict] = []

    def add(item: dict) -> dict:
        old = prev_items.get(item["id"])
        if old and old.get("status") in ("accepted", "rejected"):
            item["status"] = old["status"]
        items[item["id"]] = item
        return item

    def ask(qid: str, text: str, about: list[str], options: list[str]) -> None:
        questions.append({"id": qid, "text": text, "about": about, "options": options,
                          "answer": answers.get(qid)})

    # ── tools the agent was seen calling ──────────────────────────────
    per_tool: dict[str, dict] = {}
    for e in obs:
        t = per_tool.setdefault(e["tool"], {"count": 0, "allowed": 0, "held": 0, "blocked": 0,
                                            "roles": {}, "resources": set(), "identity": set()})
        out = e.get("outcomes") or {}
        t["count"] += int(e.get("count") or 0)
        for k in ("allowed", "held", "blocked"):
            t[k] += int(out.get(k) or 0)
        if int(out.get("allowed") or 0) + int(out.get("held") or 0):
            t["roles"][e["role"]] = t["roles"].get(e["role"], 0) + int(e.get("count") or 0)
            t["resources"].update(e.get("resources") or [])
        t["identity"].update(e.get("identity") or [])

    for tool, t in sorted(per_tool.items()):
        r, why = risk(tool, approval_tools=ctx["approval_tools"], sanitized_tools=ctx["sanitized_tools"])
        if t["allowed"] + t["held"] == 0:
            qid = _qid("blocked", tool)
            ask(qid, f"{tool} was blocked all {t['blocked']} times it was tried. Should this agent "
                     f"be allowed to call it?", [f"tool:{tool}"],
                ["allow", "allow with approval", "keep blocked"])
            if answers.get(qid) in ("allow", "allow with approval"):
                add({"id": f"tool:{tool}", "kind": "tool", "value": tool, "roles": [],
                     "risk": r, "status": "pending",
                     "evidence": {"observed": t["count"], "from_purpose": False,
                                  "reason": f"blocked {t['blocked']} times; you chose to allow it"}})
                if answers.get(qid) == "allow with approval":
                    add({"id": f"approval:{tool}", "kind": "approval",
                         "value": {"tool": tool, "min_approvals": 2 if is_money(tool) else 1},
                         "roles": [], "risk": r, "status": "pending",
                         "evidence": {"observed": t["count"], "from_purpose": False,
                                      "reason": "you chose to allow it with approval"}})
            continue
        roles = sorted(t["roles"])
        item = add({"id": f"tool:{tool}", "kind": "tool", "value": tool,
                    "roles": [x for x in roles if x], "risk": r, "status": "pending",
                    "evidence": {"observed": t["count"], "from_purpose": False,
                                 "reason": f"risk {r}: {why}"}})
        if r == "high" and t["count"] < 3:
            qid = _qid("rare_high", tool)
            ask(qid, f"{tool} is high risk ({why}) and was called only {t['count']} time(s). "
                     f"Keep it?", [item["id"]], ["keep", "remove"])
            if answers.get(qid) == "remove":
                item["status"] = "rejected"
        named = [x for x in roles if x]
        if len(named) > 1:
            for role in named:
                if t["roles"][role] == 1:
                    qid = _qid("one_role", tool, role)
                    ask(qid, f"{tool} was called once by role '{role}'. Keep that role?",
                        [item["id"]], ["keep", "remove this role"])
                    if answers.get(qid) == "remove this role":
                        item["roles"] = [x for x in item["roles"] if x != role]
        if r == "high" and tool not in ctx["approval_tools"]:
            add({"id": f"approval:{tool}", "kind": "approval",
                 "value": {"tool": tool, "min_approvals": 2 if is_money(tool) else 1},
                 "roles": [], "risk": r, "status": "pending",
                 "evidence": {"observed": t["count"], "from_purpose": False,
                              "reason": "high risk: a person approves each call"}})

    # ── tools the purpose implies (model step) ────────────────────────
    for m in (model or {}).get("tools") or []:
        tool = m["tool"]
        if m.get("needed") != "yes" or f"tool:{tool}" in items:
            if f"tool:{tool}" in items and m.get("reason"):
                items[f"tool:{tool}"]["evidence"]["from_purpose"] = m.get("needed") == "yes"
                items[f"tool:{tool}"]["evidence"]["purpose_reason"] = m["reason"]
            continue
        r, why = risk(tool, approval_tools=ctx["approval_tools"], sanitized_tools=ctx["sanitized_tools"])
        add({"id": f"tool:{tool}", "kind": "tool", "value": tool, "roles": [], "risk": r,
             "status": "pending",
             "evidence": {"observed": 0, "from_purpose": True,
                          "reason": f"risk {r}: {why}", "purpose_reason": m.get("reason", "")}})
        if r == "high" and tool not in ctx["approval_tools"]:
            add({"id": f"approval:{tool}", "kind": "approval",
                 "value": {"tool": tool, "min_approvals": 2 if is_money(tool) else 1},
                 "roles": [], "risk": r, "status": "pending",
                 "evidence": {"observed": 0, "from_purpose": True,
                              "reason": "high risk: a person approves each call"}})
    for q in (model or {}).get("questions") or []:
        ask(q["id"], q["text"], [f"tool:{t}" for t in q.get("tools") or []], q["options"])
        ans = answers.get(q["id"])
        for t in q.get("tools") or []:
            iid = f"tool:{t}"
            if ans == "do not allow" and iid in items:
                items[iid]["status"] = "rejected"
            elif ans == "allow with approval" and iid in items and f"approval:{t}" not in items:
                add({"id": f"approval:{t}", "kind": "approval",
                     "value": {"tool": t, "min_approvals": 2 if is_money(t) else 1},
                     "roles": [], "risk": items[iid]["risk"], "status": "pending",
                     "evidence": {"observed": items[iid]["evidence"]["observed"], "from_purpose": True,
                                  "reason": "you chose to allow it with approval"}})

    # ── resources ─────────────────────────────────────────────────────
    shapes: dict[str, int] = {}
    for tool, t in per_tool.items():
        for s in t["resources"]:
            shapes[s] = shapes.get(s, 0) + t["count"]
    skipped = []
    for shape, n in sorted(shapes.items(), key=lambda kv: (-kv[1], kv[0])):
        if shape.strip("/*") == "" or shape.count("*") > 1:
            skipped.append(shape)
            continue
        if sum(1 for i in items.values() if i["kind"] == "resource") >= RESOURCE_ITEMS_MAX:
            skipped.append(shape)
            continue
        add({"id": f"resource:{shape}", "kind": "resource", "value": shape, "roles": [],
             "risk": "low", "status": "pending",
             "evidence": {"observed": n, "from_purpose": False,
                          "reason": "the resources the agent acted on, with identifiers replaced by *"}})

    # ── identity ──────────────────────────────────────────────────────
    seen = set().union(*(t["identity"] for t in per_tool.values())) if per_tool else set()
    token, cert = {"agent_token", "agent_token_dpop"}, {"cert", "mtls"}
    require = ""
    if seen and seen <= token:
        require = "token"
    elif seen and seen <= cert:
        require = "cert"
    elif seen and seen <= token | cert:
        require = "cert_or_token"
    if require and ((rec.get("identity") or {}).get("require", "any")) != require:
        add({"id": "identity", "kind": "identity", "value": require, "roles": [], "risk": "low",
             "status": "pending",
             "evidence": {"observed": sum(t["count"] for t in per_tool.values()), "from_purpose": False,
                          "reason": f"every call carried a verified {require.replace('_', ' ')}"}})

    if not description:
        ask("no_description", "What does this agent do? Add a description in the Agent Registry, "
                              "then rebuild the draft: it is what the purpose step reads.",
            [], ["done"])

    # Lines carried over from an earlier draft that no longer have evidence.
    live_tools = set(per_tool) | ctx["tools"]
    for iid, old in prev_items.items():
        if iid in items:
            continue
        if old["kind"] == "tool" and old["value"] not in live_tools:
            items[iid] = {**old, "status": "stale",
                          "evidence": {**old.get("evidence", {}), "reason": "no longer a tenant tool"}}

    draft = {
        "id": (previous or {}).get("id") or "pd_" + uuid.uuid4().hex[:10],
        "agent_id": agent,
        "created_at": int(time.time()),
        "created_by": created_by,
        "window_days": window_days,
        "base_version": rec.get("updated_at"),
        "inputs_digest": _digest(obs, description),
        "description": description,
        "items": sorted(items.values(), key=lambda i: (KINDS.index(i["kind"]), str(i["value"]))),
        "questions": questions,
        "answers": answers,
        "skipped_resources": skipped,
        "model": (model or {}).get("meta") or {"used": False},
        # The model's validated output, so answering a question rebuilds the
        # draft without asking the model again.
        "model_output": ({"tools": model.get("tools") or [], "questions": model.get("questions") or [],
                          "meta": model.get("meta")} if model else None),
        "applied": (previous or {}).get("applied"),
    }
    return draft


def _covers(item: dict, role: str) -> bool:
    return not item.get("roles") or role in item["roles"] or not role


def simulate(draft: dict, obs: list[dict]) -> dict:
    """Replay observed calls against the draft. Two views: the lines accepted so
    far (what Apply would do now), and every line not rejected."""
    def view(statuses: tuple) -> dict:
        tools = {i["value"]: i for i in draft["items"] if i["kind"] == "tool" and i["status"] in statuses}
        approvals = {i["value"]["tool"] for i in draft["items"]
                     if i["kind"] == "approval" and i["status"] in statuses}
        rows, totals = [], {"allowed": 0, "held": 0, "blocked": 0}
        for e in obs:
            n = int(e.get("count") or 0)
            item = tools.get(e["tool"])
            if item is None or not _covers(item, e["role"]):
                verdict = "blocked"
            elif e["tool"] in approvals:
                verdict = "held"
            else:
                verdict = "allowed"
            totals[verdict] += n
            rows.append({"tool": e["tool"], "role": e["role"], "calls": n, "verdict": verdict})
        return {"totals": totals, "rows": rows}
    return {"accepted": view(("accepted",)), "proposed": view(("accepted", "pending"))}


# ── apply (task 3) ───────────────────────────────────────────────────


def accepted(draft: dict, kind: str) -> list[dict]:
    return [i for i in draft.get("items") or [] if i["kind"] == kind and i["status"] == "accepted"]


def applied_record(record: dict, draft: dict) -> dict:
    """The registry entry with the draft's accepted lines applied. Never adds a
    tool, role or resource that is not an accepted line, and never empties
    role_permissions (an empty map falls back to the global RBAC config,
    which would widen access rather than narrow it)."""
    new = dict(record)
    tools = accepted(draft, "tool")
    names = sorted({i["value"] for i in tools})
    new["tools"] = names
    by_role: dict[str, set] = {}
    for i in tools:
        for role in i.get("roles") or []:
            by_role.setdefault(role, set()).add(i["value"])
    if by_role:
        new["role_permissions"] = {r: sorted(t) for r, t in sorted(by_role.items())}
    else:
        allowed = set(names)
        new["role_permissions"] = {r: [t for t in (ts or []) if t in allowed]
                                   for r, ts in (record.get("role_permissions") or {}).items()}
    resources = [i["value"] for i in accepted(draft, "resource")]
    if resources:
        new["allowed_resources"] = sorted(set(resources))
        new["require_resource_scope"] = True
    ident = accepted(draft, "identity")
    if ident:
        new["identity"] = {**(record.get("identity") or {}), "require": ident[0]["value"]}
    return new


def approval_rules_to_add(tenant_id: str, agent: str, draft: dict) -> list[dict]:
    """Rules for accepted approval lines that no existing rule already covers.
    Appended, never replacing a rule."""
    ctx = tenant_context(tenant_id, agent)
    out = []
    for i in accepted(draft, "approval"):
        tool = i["value"]["tool"]
        if tool in ctx["approval_tools"]:
            continue
        out.append({"rule_id": f"pfp_{agent}_{tool}"[:120], "tool_names": [tool], "agent_keys": [agent],
                    "min_approvals": int(i["value"].get("min_approvals") or 1),
                    "source": "policy_from_purpose", "draft_id": draft["id"]})
    return out


def suggestions(draft: dict, obs: list[dict]) -> list[dict]:
    """After apply: calls seen since, outside what was applied."""
    applied = draft.get("applied") or {}
    if not applied:
        return []
    tools = set(applied.get("tools") or [])
    roles = {r: set(ts) for r, ts in (applied.get("role_permissions") or {}).items()}
    out = []
    for e in obs:
        if int(e.get("last_seen") or 0) <= int(applied.get("at") or 0):
            continue
        outside = e["tool"] not in tools or (roles and e["role"] and e["tool"] not in roles.get(e["role"], set()))
        if outside:
            out.append({"id": f"suggest:{e['tool']}|{e['role']}", "tool": e["tool"], "role": e["role"],
                        "calls": int(e.get("count") or 0), "outcomes": e.get("outcomes") or {},
                        "last_seen": e.get("last_seen")})
    return out
