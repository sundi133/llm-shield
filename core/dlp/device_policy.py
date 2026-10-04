"""The tenant's device DLP policy: model, strict validation, defaults.

Everything in the signed DLP bundle except `rules` and `blocklists`, which come
from the tenant's existing data policies (api/routes_edge._build_bundle), so
the device agent, the browser extension and ICAP enforce one rule set.
Spec: docs/specs/device-dlp-agent.md §3.2, §5.1.

The defaults are the ones task 1 measured (dlp-bench/reports/SUMMARY.md) for
Tev1 0.8B: the "contains actual data" questions, thresholds calibrated on the
calibration split, and per-category enforcement where source code, financial
data and exfiltration intent are monitor-only because the model misses them.

Validation is strict (unknown keys are errors) because this policy ends up on
laptops: a typo that silently falls back to a default is a DLP control that
quietly is not there.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

CATEGORIES = ("credentials", "personal_data", "customer_data", "source_code", "financial",
              "health")
MODES = ("monitor", "enforce")
ENFORCEMENT = ("justify", "monitor")
PINNED_ACTIONS = ("allow_and_log", "block")
FAIL_MODES = ("allow", "block")

MAX_HOSTS = 200
MAX_INSTRUCTIONS = 1000   # the model is tuned for about 2,000 tokens in all
MAX_CRITERION = 300
MAX_FLEETS = 100

# Copied, not imported: the server images do not ship icap/. A test holds this
# equal to icap.config.DEFAULT_AI_HOSTS so the two cannot drift.
DEFAULT_AI_HOSTS = (
    "chatgpt.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com",
    "perplexity.ai", "grok.com", "deepseek.com", "meta.ai", "poe.com",
    "openai.com", "anthropic.com", "generativelanguage.googleapis.com",
    "githubcopilot.com", "api.cohere.ai", "mistral.ai", "api.groq.com",
    "api.x.ai", "openrouter.ai",
)

# The benchmarked model: `ollama pull tev1:0.8b`, manifest digest as measured.
DEFAULT_MODEL = {
    "name": "tev1:0.8b",
    "digest": "sha256:d45e875d63fed9465390a4eb9e55f51f470390a446667b55d0a075a15e0336bf",
    "min_ollama": "0.35.0",
}

# dlp-bench/questions_v2.json, held equal to it by a test.
DEFAULT_QUESTIONS = {
    "category": {
        "type": "choice",
        "instructions": "Does the text itself include actual sensitive data taken from a real "
                        "system, company or person? General questions, explanations, templates, "
                        "placeholders, documentation examples, public information and fictional "
                        "content are not sensitive. If actual data is present, which kind is it?",
        "criteria": {
            "none": "No actual sensitive data in the text: a general question, template, "
                    "example, public or fictional content",
            "credentials": "The text contains a real password, key, token or secret value",
            "personal_data": "The text contains real personal details about an identifiable "
                             "individual",
            "customer_data": "The text contains real records about the company's customers or "
                             "clients",
            "source_code": "The text contains the company's own private source code",
            "financial": "The text contains the company's non-public financial figures or plans",
            "health": "The text contains health or medical details about a real, identifiable "
                      "person",
        },
    },
    "exfil_intent": {
        "type": "noul",
        "instructions": "Is the user asking for help to take company data, code or credentials "
                        "out of the company, to hide that they are doing it, or to get around "
                        "security controls?",
    },
}

# Calibrated on the calibration split for tev1:0.8b with DEFAULT_QUESTIONS
# (dlp-bench/reports/tev1-0.8b-apple_silicon-q2-actual-data.json).
DEFAULT_THRESHOLDS = {
    "block_categories": ["credentials", "customer_data"],
    "block_p": 0.471,
    "justify_p": 0.3,
    "exfil_intent": 0.25,
    "min_confidence": 0.0,
}

DEFAULT_ENFORCEMENT = {
    "credentials": "justify", "personal_data": "justify", "customer_data": "justify",
    "health": "justify", "source_code": "monitor", "financial": "monitor",
    "exfil_intent": "monitor",
}

DEFAULT_POLICY = {
    "mode": "monitor",
    "fleet_modes": {},
    "ai_hosts": list(DEFAULT_AI_HOSTS),
    "pinned_host_action": {"default": "allow_and_log", "hosts": {}},
    "model": DEFAULT_MODEL,
    "questions": DEFAULT_QUESTIONS,
    "thresholds": DEFAULT_THRESHOLDS,
    "enforcement": DEFAULT_ENFORCEMENT,
    "fail_mode": "allow",
    "model_timeout_ms": 1500,
    "privacy": {"capture_excerpt": False, "server_screen": False},
    "grace_s": 604800,
}

_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_FLEET = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MODEL_NAME = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,99}(:[a-z0-9._-]{1,64})?$")


class PolicyError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def default_policy() -> dict:
    return copy.deepcopy(DEFAULT_POLICY)


def valid_fleet(fleet: str) -> bool:
    return isinstance(fleet, str) and bool(_FLEET.match(fleet))


def policy_hash(policy: dict) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":"))
                          .encode()).hexdigest()


def _unknown(obj: dict, allowed, where: str, errors: list[str]) -> None:
    for k in obj:
        if k not in allowed:
            errors.append(f"{where}{k}: unknown field")


def _prob(v: Any, where: str, errors: list[str]) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0.0 <= v <= 1.0:
        errors.append(f"{where}: a number from 0 to 1")
        return 0.0
    return float(v)


def _int(v: Any, lo: int, hi: int, where: str, errors: list[str]) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        errors.append(f"{where}: an integer from {lo} to {hi}")
        return lo
    return v


def _one_of(v: Any, allowed, where: str, errors: list[str]) -> str:
    if v not in allowed:
        errors.append(f"{where}: one of {', '.join(allowed)}")
    return v


def _text(v: Any, n: int, where: str, errors: list[str]) -> str:
    if not isinstance(v, str) or not v.strip():
        errors.append(f"{where}: non-empty text")
        return ""
    if len(v) > n:
        errors.append(f"{where}: at most {n} characters")
    return v.strip()


def _host(v: Any, where: str, errors: list[str]) -> str:
    h = v.strip().lower().rstrip(".") if isinstance(v, str) else ""
    if not _HOST.match(h):
        errors.append(f"{where}: not a hostname: {str(v)[:80]!r}")
    return h


def _questions(q: Any, errors: list[str]) -> dict:
    if not isinstance(q, dict):
        errors.append("questions: an object")
        return {}
    _unknown(q, ("category", "exfil_intent"), "questions.", errors)
    out: dict = {}
    cat = q.get("category")
    if not isinstance(cat, dict):
        errors.append("questions.category: required object")
    else:
        _unknown(cat, ("type", "instructions", "criteria"), "questions.category.", errors)
        if cat.get("type") != "choice":
            errors.append("questions.category.type: must be choice")
        crit = cat.get("criteria")
        crit_out: dict = {}
        if not isinstance(crit, dict):
            errors.append("questions.category.criteria: required object")
        else:
            if "none" not in crit:
                errors.append("questions.category.criteria.none: required (the signal is "
                              "1 - P(none))")
            for k, v in crit.items():
                if k != "none" and k not in CATEGORIES:
                    errors.append(f"questions.category.criteria.{k}: unknown category "
                                  f"(one of none, {', '.join(CATEGORIES)})")
                crit_out[k] = _text(v, MAX_CRITERION, f"questions.category.criteria.{k}", errors)
            if len(crit_out) < 2:
                errors.append("questions.category.criteria: none and at least one category")
        out["category"] = {"type": "choice",
                           "instructions": _text(cat.get("instructions"), MAX_INSTRUCTIONS,
                                                 "questions.category.instructions", errors),
                           "criteria": crit_out}
    ex = q.get("exfil_intent")
    if ex is not None:
        if not isinstance(ex, dict):
            errors.append("questions.exfil_intent: an object")
        else:
            _unknown(ex, ("type", "instructions"), "questions.exfil_intent.", errors)
            if ex.get("type") != "noul":
                errors.append("questions.exfil_intent.type: must be noul")
            out["exfil_intent"] = {"type": "noul",
                                   "instructions": _text(ex.get("instructions"), MAX_INSTRUCTIONS,
                                                         "questions.exfil_intent.instructions",
                                                         errors)}
    return out


def validate_policy(raw: Any) -> dict:
    """The normalized policy, with every omitted field at its default. Raises
    PolicyError listing every problem, not just the first."""
    if not isinstance(raw, dict):
        raise PolicyError(["policy: an object"])
    errors: list[str] = []
    # agent_hooks is optional and stored only when set (core/dlp/agent_hooks.py),
    # so tenants that never use it keep their policy hash and bundles.
    _unknown(raw, {*DEFAULT_POLICY, "agent_hooks", "agent_os_events"}, "", errors)
    p = {**default_policy(), **copy.deepcopy(raw)}
    if "agent_hooks" in p:
        from core.dlp import agent_hooks
        p["agent_hooks"] = agent_hooks.validate(p["agent_hooks"], errors,
                                                valid_fleet=valid_fleet, max_fleets=MAX_FLEETS)
    if "agent_os_events" in p:
        # Optional too, stored only when set (core/dlp/agent_os_events.py).
        from core.dlp import agent_os_events
        p["agent_os_events"] = agent_os_events.validate(
            p["agent_os_events"], errors, valid_fleet=valid_fleet, max_fleets=MAX_FLEETS)

    _one_of(p["mode"], MODES, "mode", errors)

    fm = p["fleet_modes"]
    if not isinstance(fm, dict) or len(fm) > MAX_FLEETS:
        errors.append(f"fleet_modes: an object of at most {MAX_FLEETS} fleets")
        fm = {}
    for fleet, mode in fm.items():
        if not valid_fleet(fleet):
            errors.append(f"fleet_modes.{fleet}: fleet id is lowercase letters, digits, . _ -")
        _one_of(mode, MODES, f"fleet_modes.{fleet}", errors)
    p["fleet_modes"] = dict(sorted(fm.items()))

    hosts = p["ai_hosts"]
    if not isinstance(hosts, list) or not hosts or len(hosts) > MAX_HOSTS:
        errors.append(f"ai_hosts: a list of 1 to {MAX_HOSTS} hostnames")
        hosts = []
    p["ai_hosts"] = sorted({_host(h, f"ai_hosts[{i}]", errors) for i, h in enumerate(hosts)})

    pin = p["pinned_host_action"]
    if not isinstance(pin, dict):
        errors.append("pinned_host_action: an object")
        pin = {}
    _unknown(pin, ("default", "hosts"), "pinned_host_action.", errors)
    pin_hosts = pin.get("hosts") or {}
    if not isinstance(pin_hosts, dict):
        errors.append("pinned_host_action.hosts: an object of host -> action")
        pin_hosts = {}
    p["pinned_host_action"] = {
        "default": _one_of(pin.get("default", "allow_and_log"), PINNED_ACTIONS,
                           "pinned_host_action.default", errors),
        "hosts": {_host(h, f"pinned_host_action.hosts.{h}", errors):
                  _one_of(a, PINNED_ACTIONS, f"pinned_host_action.hosts.{h}", errors)
                  for h, a in sorted(pin_hosts.items())},
    }

    m = p["model"]
    if not isinstance(m, dict):
        errors.append("model: an object")
        m = {}
    _unknown(m, ("name", "digest", "min_ollama"), "model.", errors)
    name = m.get("name")
    if not isinstance(name, str) or not _MODEL_NAME.match(name):
        errors.append("model.name: an Ollama model name such as tev1:0.8b")
    digest = m.get("digest") or ""
    if digest and not _DIGEST.match(digest):
        errors.append("model.digest: sha256:<64 hex> or empty")
    min_ollama = m.get("min_ollama") or DEFAULT_MODEL["min_ollama"]
    if not isinstance(min_ollama, str) or not _VERSION.match(min_ollama):
        errors.append("model.min_ollama: a version such as 0.35.0")
    p["model"] = {"name": name, "digest": digest, "min_ollama": min_ollama}

    p["questions"] = _questions(p["questions"], errors)
    asked = set((p["questions"].get("category") or {}).get("criteria", {})) - {"none"}

    t = p["thresholds"]
    if not isinstance(t, dict):
        errors.append("thresholds: an object")
        t = {}
    _unknown(t, DEFAULT_THRESHOLDS, "thresholds.", errors)
    t = {**DEFAULT_THRESHOLDS, **t}
    bc = t["block_categories"]
    if not isinstance(bc, list):
        errors.append("thresholds.block_categories: a list")
        bc = []
    for c in bc:
        if c not in asked:
            errors.append(f"thresholds.block_categories: {c!r} is not a category the "
                          f"questions ask about")
    p["thresholds"] = {
        "block_categories": sorted(set(c for c in bc if isinstance(c, str))),
        "block_p": _prob(t["block_p"], "thresholds.block_p", errors),
        "justify_p": _prob(t["justify_p"], "thresholds.justify_p", errors),
        "exfil_intent": _prob(t["exfil_intent"], "thresholds.exfil_intent", errors),
        "min_confidence": _prob(t["min_confidence"], "thresholds.min_confidence", errors),
    }
    if p["thresholds"]["justify_p"] > p["thresholds"]["block_p"]:
        errors.append("thresholds.justify_p: must not be above block_p")

    enf = p["enforcement"]
    if not isinstance(enf, dict):
        errors.append("enforcement: an object of category -> justify or monitor")
        enf = {}
    _unknown(enf, DEFAULT_ENFORCEMENT, "enforcement.", errors)
    enf = {**DEFAULT_ENFORCEMENT, **enf}
    for k, v in enf.items():
        _one_of(v, ENFORCEMENT, f"enforcement.{k}", errors)
    for c in p["thresholds"]["block_categories"]:
        if enf.get(c) == "monitor":
            errors.append(f"thresholds.block_categories: {c!r} is monitor-only in enforcement; "
                          f"a monitor-only category cannot block")
    p["enforcement"] = dict(sorted(enf.items()))

    _one_of(p["fail_mode"], FAIL_MODES, "fail_mode", errors)
    p["model_timeout_ms"] = _int(p["model_timeout_ms"], 100, 10000, "model_timeout_ms", errors)
    p["grace_s"] = _int(p["grace_s"], 0, 30 * 86400, "grace_s", errors)

    priv = p["privacy"]
    if not isinstance(priv, dict):
        errors.append("privacy: an object")
        priv = {}
    _unknown(priv, ("capture_excerpt", "server_screen"), "privacy.", errors)
    priv = {"capture_excerpt": False, "server_screen": False, **priv}
    for k, v in priv.items():
        if not isinstance(v, bool):
            errors.append(f"privacy.{k}: true or false")
    p["privacy"] = priv

    if errors:
        raise PolicyError(errors)
    return p


def for_fleet(policy: dict, fleet: str) -> dict:
    """The policy as one fleet's devices enforce it: `mode` resolved from
    fleet_modes, the per-fleet maps themselves left out (a device needs only
    its own). agent_hooks, when set, becomes this fleet's
    {"agents", "mode", "on_unreachable"}."""
    from core.dlp import agent_hooks, agent_os_events
    out = {k: v for k, v in policy.items()
           if k not in ("fleet_modes", "agent_hooks", "agent_os_events")}
    out["mode"] = policy.get("fleet_modes", {}).get(fleet, policy["mode"])
    resolved = agent_hooks.resolve(policy, fleet)
    if resolved is not None:
        out["agent_hooks"] = resolved
    resolved = agent_os_events.resolve(policy, fleet)
    if resolved is not None:
        out["agent_os_events"] = resolved
    return out
