"""Policy scopes: one tenant, a global I/O policy, and local policies per team.

A tenant names one or more request headers (``X-Org-Id``, ``X-Team-Id``). The
value on the first one present selects a rule; the rule's local guardrails are
merged on top of the tenant's global ``input_guardrails`` / ``output_guardrails``.
Spec: docs/specs/policy-scopes.md.

The merge only ever tightens. A header is whatever the caller says it is, so the
guarantee that matters is that no value, real or spoofed, gets below the global
policy. Every rule below exists to keep that true:

- a guardrail the global policy enables stays enabled, at an action no weaker;
- denylist settings (``keywords``) are unioned, allowlist settings
  (``allowed_languages``) are intersected, every other setting stays global
  unless the global guardrail is marked ``delegable``;
- a local policy cannot disable anything, and cannot touch ``tool_allowlist``;
- a local stage is ignored when the global policy has no such stage, because a
  tenant stage *replaces* the server defaults on ``/guardrails/*`` and a one
  guardrail local stage would quietly drop the rest.

This module is pure: no Redis, no request objects. The guard path calls
:func:`resolve` with the tenant config the middleware already cached and a
header accessor. Selection and merge are memoized per cached config object, so
a request on a known value costs a couple of dict lookups (spec section 2 has
the measurements). Validation for the write routes is :func:`validate_scopes`;
the merge enforces the same rules at read time regardless, so a config that
reached the store some other way still cannot weaken the global policy.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

logger = logging.getLogger("votal.policy_scopes")

DISABLE_ENV = "SHIELD_DISABLE_POLICY_SCOPES"

# Reserved normalized values. Parentheses can't survive normalization, so a
# caller can't send one of these and have it read as anything but itself.
MISSING = "(missing)"
INVALID = "(invalid)"

RULE_GLOBAL = "global"
RULE_UNMATCHED = "unmatched"

APPLIED = "applied"
REJECT_MISSING = "reject_missing"
REJECT_BINDING = "reject_binding"

# Marker on a scoped copy of the tenant config. The storage layer refuses to
# save a dict carrying it, so a merged view can never be written back as the
# global policy (spec section 5, write safety).
SCOPE_MARKER = "_policy_scope"

STAGE_KEYS = ("input_guardrails", "output_guardrails")

MAX_VALUE_LEN = 64
MAX_RULES = 200
MAX_EXACT_PER_RULE = 20
MAX_GLOBS_TOTAL = 100
MAX_SELECTORS = 5
MAX_KEY_BINDINGS = 1000
MAX_CONFIG_BYTES = 256 * 1024
MAX_MEMO_VALUES = 5000
_MAX_COMPILED = 2048

_VALUE_RE = re.compile(r"^[a-z0-9._:@/-]{1,64}$")
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_GLOB_CHARS = ("*", "?", "[")

# Selecting on one of these would copy a credential into the discovery store
# and the audit log.
_FORBIDDEN_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-tenant-key", "x-admin-key", "x-agent-token",
    "x-client-cert", "x-forwarded-client-cert",
})

# Higher is stricter. "mask" is the custom-policy spelling of redact.
_STRICTNESS = {"pass": 0, "log": 1, "warn": 2, "redact": 3, "mask": 3, "block": 4}

# List settings where more entries means stricter: union them.
DENYLIST_KEYS = frozenset({
    "keywords", "patterns", "extra_patterns", "blocked_topics",
    "competitors", "pii_patterns",
})
# List settings where more entries means looser: intersect them. An empty
# allowlist means "no restriction", so empty on either side yields the other.
ALLOWLIST_KEYS = frozenset({"allowed_languages", "allowed_topics", "trusted_domains"})

_CUSTOM_POLICY_GUARDRAILS = frozenset({"custom_policy_input", "custom_policy_output"})
_LOCAL_FORBIDDEN_GUARDRAILS = frozenset({"tool_allowlist"})


def scopes_disabled() -> bool:
    """Kill switch: every tenant gets its global policy only.

    Read live, like ``SHIELD_DISABLE_TENANT_POLICY_ON_PROXY``, so it can be
    flipped without a restart.
    """
    return os.environ.get(DISABLE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Decision:
    """Which scope a request landed in, and whether it may proceed."""
    rule: str                       # rule id, RULE_GLOBAL or RULE_UNMATCHED
    value: str                      # normalized value, MISSING or INVALID
    header: Optional[str]           # the selector header it came from
    outcome: str = APPLIED          # APPLIED, REJECT_MISSING or REJECT_BINDING
    degraded: bool = False          # selection failed; global applied instead

    def as_dict(self) -> dict:
        return {"rule": self.rule, "value": self.value, "header": self.header}


@dataclass(frozen=True)
class Resolution:
    """What the guard path needs: the config to run, and the decision.

    ``decision`` is None when the tenant has no policy scopes (or they are off),
    and ``config`` is then the tenant config itself, untouched.
    """
    config: Optional[dict]
    decision: Optional[Decision]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_value(raw: Optional[str]) -> str:
    """Normalize one header value: strip, lowercase, at most 64 safe chars."""
    if raw is None:
        return MISSING
    v = str(raw).strip().lower()
    if not v:
        return MISSING
    return v if _VALUE_RE.match(v) else INVALID


def normalize_header_values(values: Sequence[str]) -> str:
    """Normalize every occurrence of one header in a request.

    Two different values for the same header (sent twice, or comma-joined by a
    proxy) is ambiguous, and ambiguity must not let a caller choose, so it reads
    as INVALID. Repeats of the same value are fine.
    """
    seen = {normalize_value(v) for v in values or ()} - {MISSING}
    if not seen:
        return MISSING
    if len(seen) > 1:
        return INVALID
    return seen.pop()


def _is_glob(pattern: str) -> bool:
    return any(c in pattern for c in _GLOB_CHARS)


def _selector_headers(scopes: dict) -> list[str]:
    out = []
    for sel in scopes.get("selectors") or ():
        name = (sel or {}).get("header") if isinstance(sel, dict) else None
        if isinstance(name, str) and _HEADER_RE.match(name) \
                and name.lower() not in _FORBIDDEN_HEADERS:
            out.append(name)
    return out[:MAX_SELECTORS]


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def _strictness(action) -> int:
    return _STRICTNESS.get(action, -1)


def _item_key(item) -> str:
    if isinstance(item, (dict, list)):
        return json.dumps(item, sort_keys=True, default=str)
    return str(item)


def _union(global_list: list, local_list: list) -> list:
    out, seen = [], set()
    for item in list(global_list) + list(local_list):
        k = _item_key(item)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


def _intersect(global_list: list, local_list: list) -> list:
    if not global_list:
        return list(local_list)
    if not local_list:
        return list(global_list)
    local_keys = {_item_key(i) for i in local_list}
    narrowed = [i for i in global_list if _item_key(i) in local_keys]
    # Nothing in common would mean "no restriction" to the guardrail, which is
    # looser than either side. Keep global; validation rejects this on save.
    return narrowed or list(global_list)


def _merge_settings(gs: dict, ls: dict, delegable: bool) -> dict:
    if delegable:
        return {**gs, **ls}
    merged = dict(gs)
    for key, lv in ls.items():
        gv = gs.get(key)
        if key in DENYLIST_KEYS and isinstance(lv, list):
            merged[key] = _union(gv if isinstance(gv, list) else [], lv)
        elif key in ALLOWLIST_KEYS and isinstance(lv, list):
            merged[key] = _intersect(gv if isinstance(gv, list) else [], lv)
        # Anything else is locked to global.
    return merged


def _custom_policy_caps() -> tuple[int, int]:
    try:
        from storage.custom_policies import MAX_POLICIES_PER_STAGE, sigma_max_policies_per_stage
        return MAX_POLICIES_PER_STAGE, sigma_max_policies_per_stage()
    except Exception:
        return 10, 100


def _is_sigma(policy: dict) -> bool:
    return policy.get("format") == "sigma"


def _merge_custom_policies(global_list: list, local_list: list) -> list:
    """Union by ``policy_id``; a shared id keeps the stricter action.

    Global policies come first and are never dropped. Local policies past the
    per-stage caps (NL and Sigma counted separately, as on the write path) are.
    """
    nl_cap, sigma_cap = _custom_policy_caps()
    out, index = [], {}
    for p in global_list or ():
        if isinstance(p, dict):
            index[p.get("policy_id")] = len(out)
            out.append(dict(p))
    nl = sum(1 for p in out if not _is_sigma(p))
    sg = len(out) - nl
    for p in local_list or ():
        if not isinstance(p, dict) or not p.get("policy_id"):
            continue
        pid = p["policy_id"]
        if pid in index:
            g = out[index[pid]]
            if _strictness(p.get("action")) > _strictness(g.get("action")):
                g["action"] = p["action"]
            continue
        if not p.get("enabled", True):
            continue
        if _is_sigma(p):
            if sg >= sigma_cap:
                logger.warning("policy scope: local sigma policy %s over the cap, dropped", pid)
                continue
            sg += 1
        else:
            if nl >= nl_cap:
                logger.warning("policy scope: local policy %s over the cap, dropped", pid)
                continue
            nl += 1
        index[pid] = len(out)
        out.append(dict(p))
    return out


def _merge_guardrail(name: str, g: dict, l: dict) -> dict:
    if not g.get("enabled", True):
        # Global has it off: the team may turn it on, on its own terms.
        return dict(l)
    merged = dict(g)
    merged["enabled"] = True
    if _strictness(l.get("action")) > _strictness(g.get("action")):
        merged["action"] = l["action"]
    gs = g.get("settings") or {}
    ls = l.get("settings") or {}
    if name in _CUSTOM_POLICY_GUARDRAILS:
        settings = dict(gs)
        settings["policies"] = _merge_custom_policies(gs.get("policies") or [], ls.get("policies") or [])
        merged["settings"] = settings
    else:
        merged["settings"] = _merge_settings(gs, ls, bool(g.get("delegable")))
    return merged


def merge_stage(global_stage: Optional[dict], local_stage: Optional[dict]) -> Optional[dict]:
    """Merge one stage (``input_guardrails`` or ``output_guardrails``).

    Returns the global stage unchanged when it is absent: see the module
    docstring for why a local stage can't stand in for a missing global one.
    """
    if global_stage is None or not local_stage:
        return global_stage
    out = dict(global_stage)
    for name, l in local_stage.items():
        if name in _LOCAL_FORBIDDEN_GUARDRAILS or not isinstance(l, dict):
            continue
        if not l.get("enabled", True):
            continue
        g = global_stage.get(name)
        if isinstance(g, dict):
            out[name] = _merge_guardrail(name, g, l)
        elif name in _CUSTOM_POLICY_GUARDRAILS:
            # Team-only custom policies still answer to the per-stage caps.
            merged = dict(l)
            settings = dict(l.get("settings") or {})
            settings["policies"] = _merge_custom_policies([], settings.get("policies") or [])
            merged["settings"] = settings
            out[name] = merged
        else:
            out[name] = dict(l)
    return out


def merge_config(tenant_config: dict, local: Optional[dict], decision: Decision) -> dict:
    """A scoped copy of the tenant config. The cached original is never mutated."""
    scoped = dict(tenant_config)
    for stage in STAGE_KEYS:
        merged = merge_stage(tenant_config.get(stage), (local or {}).get(stage))
        if merged is not None:
            scoped[stage] = merged
    scoped[SCOPE_MARKER] = decision.as_dict()
    return scoped


# ---------------------------------------------------------------------------
# Selection (compiled and memoized per cached tenant config object)
# ---------------------------------------------------------------------------

class _Compiled:
    __slots__ = ("config", "headers", "missing", "exact", "globs", "rules",
                 "unmatched", "bindings", "value_memo", "effective")

    def __init__(self, tenant_config: dict, scopes: dict):
        self.config = tenant_config          # strong ref: pins id() for the memo key
        self.headers = _selector_headers(scopes)
        self.missing = scopes.get("missing", "global")
        self.rules: dict[str, dict] = {}
        self.exact: dict[str, str] = {}
        self.globs: list[tuple[re.Pattern, str]] = []
        for rule in (scopes.get("rules") or ())[:MAX_RULES]:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                continue
            rid = rule["id"]
            self.rules[rid] = rule
            match = rule.get("match") or {}
            for v in (match.get("exact") or ())[:MAX_EXACT_PER_RULE]:
                nv = normalize_value(v)
                if nv not in (MISSING, INVALID):
                    self.exact.setdefault(nv, rid)
            for pat in match.get("glob") or ():
                if len(self.globs) >= MAX_GLOBS_TOTAL:
                    break
                if isinstance(pat, str) and 0 < len(pat) <= MAX_VALUE_LEN:
                    self.globs.append((re.compile(fnmatch.translate(pat.strip().lower())), rid))
        self.unmatched = scopes.get("unmatched") if isinstance(scopes.get("unmatched"), dict) else None
        self.bindings = {}
        for prefix, allowed in (scopes.get("key_bindings") or {}).items():
            if isinstance(allowed, list):
                self.bindings[str(prefix)] = [str(a).strip().lower() for a in allowed if a]
        self.value_memo: dict[str, str] = {}
        self.effective: dict[str, dict] = {}

    def rule_for(self, value: str) -> str:
        hit = self.value_memo.get(value)
        if hit is not None:
            return hit
        rid = self._match(value)
        if len(self.value_memo) < MAX_MEMO_VALUES:
            self.value_memo[value] = rid
        return rid

    def _match(self, value: str) -> str:
        if value == MISSING:
            return RULE_GLOBAL
        if value != INVALID:
            rid = self.exact.get(value)
            if rid:
                return rid
            for rx, rid in self.globs:
                if rx.match(value):
                    return rid
        return RULE_UNMATCHED if self.unmatched is not None else RULE_GLOBAL

    def local_for(self, rid: str) -> Optional[dict]:
        if rid == RULE_UNMATCHED:
            return self.unmatched
        return self.rules.get(rid)


# tenant id -> the few most recent compiled configs, newest last. The
# middleware caches one config object per API key and reloads it every 60 s,
# so a tenant has about as many live objects as it has active keys. Keeping a
# handful per tenant (not one entry per object ever seen) bounds what stale
# configs this pins in memory.
_PER_TENANT = 4
_compiled: dict[str, list[_Compiled]] = {}


def _compile(tenant_config: dict, scopes: dict, memo: bool) -> _Compiled:
    if not memo:
        return _Compiled(tenant_config, scopes)
    tid = str(tenant_config.get("tenant_id") or id(tenant_config))
    bucket = _compiled.get(tid)
    if bucket:
        for c in bucket:
            if c.config is tenant_config:
                return c
    else:
        if len(_compiled) >= _MAX_COMPILED:
            _compiled.clear()
        bucket = _compiled[tid] = []
    c = _Compiled(tenant_config, scopes)
    bucket.append(c)
    if len(bucket) > _PER_TENANT:
        del bucket[0]
    return c


def _binding_allows(allowed: list[str], value: str) -> bool:
    for pat in allowed:
        if (fnmatch.fnmatchcase(value, pat) if _is_glob(pat) else value == pat):
            return True
    return False


def _select(c: _Compiled, header_values: Callable[[str], Sequence[str]],
            key_prefix: Optional[str]) -> Decision:
    value, header = MISSING, None
    for name in c.headers:
        v = normalize_header_values(header_values(name) or ())
        if v != MISSING:
            value, header = v, name
            break

    allowed = c.bindings.get(key_prefix) if key_prefix else None
    if allowed is not None:
        if value == MISSING:
            exact = [a for a in allowed if not _is_glob(a)]
            if len(exact) == 1 and len(allowed) == 1:
                value = exact[0]
        if value != MISSING and (value in (INVALID,) or not _binding_allows(allowed, value)):
            return Decision(RULE_GLOBAL, value, header, REJECT_BINDING)

    if value == MISSING and c.missing == "reject":
        return Decision(RULE_GLOBAL, value, header, REJECT_MISSING)
    return Decision(c.rule_for(value), value, header)


def resolve(tenant_config: Optional[dict],
            header_values: Callable[[str], Sequence[str]],
            key_prefix: Optional[str] = None,
            memo: bool = True) -> Resolution:
    """Pick the scope for a request and return the config to run.

    ``header_values(name)`` returns every value of a header in the request
    (Starlette's ``request.headers.getlist``). ``key_prefix`` is the calling
    key's 12-char prefix, for key bindings. ``memo=False`` is for the preview
    route, which reads a fresh config from the store on each call.

    Fails to global: any error while selecting or merging returns the tenant's
    global policy, which is the floor, so a bug here can never weaken
    enforcement.
    """
    if not tenant_config:
        return Resolution(tenant_config, None)
    scopes = tenant_config.get("policy_scopes")
    if not isinstance(scopes, dict) or not scopes.get("enabled") or scopes_disabled():
        return Resolution(tenant_config, None)
    try:
        c = _compile(tenant_config, scopes, memo)
        decision = _select(c, header_values, key_prefix)
        if decision.outcome != APPLIED or decision.rule == RULE_GLOBAL:
            return Resolution(tenant_config, decision)
        effective = c.effective.get(decision.rule)
        if effective is None:
            effective = merge_config(tenant_config, c.local_for(decision.rule),
                                     Decision(decision.rule, "", None))
            c.effective[decision.rule] = effective
        # The memoized dict is shared by every request on this rule; the marker
        # must say which value and header *this* request used.
        scoped = dict(effective)
        scoped[SCOPE_MARKER] = decision.as_dict()
        return Resolution(scoped, decision)
    except Exception:
        logger.warning("policy scope selection failed; applying the global policy",
                       exc_info=True)
        return Resolution(tenant_config, Decision(RULE_GLOBAL, MISSING, None, degraded=True))


def is_scoped(config: Optional[dict]) -> bool:
    """True for a merged view. Storage refuses to save these."""
    return bool(config) and SCOPE_MARKER in config


# ---------------------------------------------------------------------------
# Validation (write routes)
# ---------------------------------------------------------------------------

def _validate_local_stage(stage: str, local: dict, global_stage: Optional[dict],
                          where: str) -> list[str]:
    errors = []
    if not isinstance(local, dict):
        return [f"{where}.{stage}: must be an object"]
    if local and global_stage is None:
        errors.append(f"{where}.{stage}: the global policy has no {stage}; "
                      f"set a global {stage} first")
        return errors
    for name, l in local.items():
        p = f"{where}.{stage}.{name}"
        if name in _LOCAL_FORBIDDEN_GUARDRAILS:
            errors.append(f"{p}: can only be set in the global policy")
            continue
        if not isinstance(l, dict):
            errors.append(f"{p}: must be an object")
            continue
        if not l.get("enabled", True):
            errors.append(f"{p}: a team policy can't disable a guardrail")
            continue
        action = l.get("action")
        if action is not None and action not in _STRICTNESS:
            errors.append(f"{p}: unknown action '{action}'")
            continue
        g = (global_stage or {}).get(name)
        if not isinstance(g, dict) or not g.get("enabled", True):
            # Team-only, or turning on something global has off. Custom
            # policies still count against the per-stage caps.
            if name in _CUSTOM_POLICY_GUARDRAILS:
                errors.extend(_validate_custom_policies(
                    p, [], (l.get("settings") or {}).get("policies") or []))
            continue
        if action is not None and _strictness(action) < _strictness(g.get("action")):
            errors.append(f"{p}: global action is {g.get('action')}, "
                          f"a team policy can't lower it to {action}")
        gs, ls = g.get("settings") or {}, l.get("settings") or {}
        if name in _CUSTOM_POLICY_GUARDRAILS:
            errors.extend(_validate_custom_policies(p, gs.get("policies") or [],
                                                    ls.get("policies") or []))
            continue
        if g.get("delegable"):
            continue
        for key, lv in ls.items():
            gv = gs.get(key)
            if key in DENYLIST_KEYS and isinstance(lv, list):
                continue
            if key in ALLOWLIST_KEYS and isinstance(lv, list):
                if gv and lv and not ({_item_key(i) for i in gv} & {_item_key(i) for i in lv}):
                    errors.append(f"{p}.settings.{key}: shares nothing with the global list")
                elif gv and any(_item_key(i) not in {_item_key(x) for x in gv} for i in lv):
                    errors.append(f"{p}.settings.{key}: a team policy can only narrow this list")
                continue
            if gv != lv:
                errors.append(f"{p}.settings.{key}: set by the global policy "
                              f"(mark the global guardrail delegable to allow this)")
    return errors


def _validate_custom_policies(where: str, global_list: list, local_list: list) -> list[str]:
    errors = []
    by_id = {p.get("policy_id"): p for p in global_list if isinstance(p, dict)}
    nl_cap, sigma_cap = _custom_policy_caps()
    nl = sum(1 for p in global_list if isinstance(p, dict) and not _is_sigma(p))
    sg = sum(1 for p in global_list if isinstance(p, dict) and _is_sigma(p))
    for p in local_list:
        if not isinstance(p, dict) or not p.get("policy_id"):
            errors.append(f"{where}: every custom policy needs a policy_id")
            continue
        g = by_id.get(p["policy_id"])
        if g is not None:
            if _strictness(p.get("action")) < _strictness(g.get("action")):
                errors.append(f"{where}: policy {p['policy_id']} is {g.get('action')} "
                              f"globally, a team policy can't lower it")
            continue
        if not p.get("enabled", True):
            continue
        if _is_sigma(p):
            sg += 1
        else:
            nl += 1
    if nl > nl_cap:
        errors.append(f"{where}: {nl} custom policies with the global ones, the limit is {nl_cap}")
    if sg > sigma_cap:
        errors.append(f"{where}: {sg} Sigma policies with the global ones, the limit is {sigma_cap}")
    return errors


def validate_rule(rule: dict, tenant_config: dict, check_stages: bool = True) -> list[str]:
    """Errors for one rule against the tenant's current global policy.

    ``check_stages=False`` checks only the rule's shape (id, match). The write
    routes use that for rules the write didn't touch: a rule that has gone
    stale because the *global* policy changed after it was saved must not
    block an unrelated save. The merge keeps such a rule safe regardless, and
    ``GET`` reports it as a warning.
    """
    errors = []
    rid = rule.get("id")
    where = f"rules.{rid}"
    if not isinstance(rid, str) or not _RULE_ID_RE.match(rid) \
            or rid in (RULE_GLOBAL, RULE_UNMATCHED):
        errors.append(f"rule id '{rid}' must match {_RULE_ID_RE.pattern} "
                      f"and not be '{RULE_GLOBAL}' or '{RULE_UNMATCHED}'")
    match = rule.get("match") or {}
    exact = match.get("exact") or []
    globs = match.get("glob") or []
    if not exact and not globs:
        errors.append(f"{where}.match: needs at least one exact value or glob")
    if len(exact) > MAX_EXACT_PER_RULE:
        errors.append(f"{where}.match.exact: at most {MAX_EXACT_PER_RULE} values")
    for v in exact:
        if normalize_value(v) in (MISSING, INVALID):
            errors.append(f"{where}.match.exact: '{v}' is not a valid value")
    for g in globs:
        if not isinstance(g, str) or not g.strip() or len(g) > MAX_VALUE_LEN:
            errors.append(f"{where}.match.glob: '{g}' must be 1 to {MAX_VALUE_LEN} chars")
    for stage in STAGE_KEYS:
        if check_stages and stage in rule:
            errors.extend(_validate_local_stage(stage, rule[stage], tenant_config.get(stage), where))
    return errors


def validate_scopes(scopes: dict, tenant_config: dict,
                    only_rules: Optional[set] = None,
                    check_unmatched: bool = True) -> list[str]:
    """Every error in a whole ``policy_scopes`` config. Empty means valid.

    ``only_rules`` limits the checks against the global policy to those rule
    ids (see :func:`validate_rule`); every structural limit is always checked.
    """
    errors = []
    if not isinstance(scopes, dict):
        return ["policy_scopes must be an object"]
    try:
        size = len(json.dumps(scopes, default=str))
    except (TypeError, ValueError):
        return ["policy_scopes must be JSON-serializable"]
    if size > MAX_CONFIG_BYTES:
        errors.append(f"policy_scopes is {size} bytes, the limit is {MAX_CONFIG_BYTES}")

    selectors = scopes.get("selectors") or []
    if scopes.get("enabled") and not selectors:
        errors.append("selectors: name at least one header")
    if len(selectors) > MAX_SELECTORS:
        errors.append(f"selectors: at most {MAX_SELECTORS}")
    for sel in selectors:
        name = sel.get("header") if isinstance(sel, dict) else None
        if not isinstance(name, str) or not _HEADER_RE.match(name):
            errors.append(f"selectors: '{name}' is not a valid header name")
        elif name.lower() in _FORBIDDEN_HEADERS:
            errors.append(f"selectors: '{name}' carries credentials and can't be used")
    if scopes.get("missing", "global") not in ("global", "reject"):
        errors.append("missing: must be 'global' or 'reject'")

    unmatched = scopes.get("unmatched")
    if unmatched is not None:
        if not isinstance(unmatched, dict):
            errors.append("unmatched: must be an object")
        elif check_unmatched:
            for stage in STAGE_KEYS:
                if stage in unmatched:
                    errors.extend(_validate_local_stage(
                        stage, unmatched[stage], tenant_config.get(stage), "unmatched"))

    rules = scopes.get("rules") or []
    if len(rules) > MAX_RULES:
        errors.append(f"rules: at most {MAX_RULES}")
    seen_ids, owner, globs_total = set(), {}, 0
    for rule in rules:
        if not isinstance(rule, dict):
            errors.append("rules: every rule must be an object")
            continue
        rid = rule.get("id")
        errors.extend(validate_rule(rule, tenant_config,
                                    check_stages=only_rules is None or rid in only_rules))
        if rid in seen_ids:
            errors.append(f"rules.{rid}: duplicate rule id")
        seen_ids.add(rid)
        match = rule.get("match") or {}
        globs_total += len(match.get("glob") or [])
        for v in match.get("exact") or []:
            nv = normalize_value(v)
            if nv in owner and owner[nv] != rid:
                errors.append(f"rules.{rid}.match.exact: '{nv}' already belongs to rule {owner[nv]}")
            owner.setdefault(nv, rid)
    if globs_total > MAX_GLOBS_TOTAL:
        errors.append(f"rules: {globs_total} glob patterns in total, the limit is {MAX_GLOBS_TOTAL}")

    bindings = scopes.get("key_bindings") or {}
    if not isinstance(bindings, dict):
        errors.append("key_bindings: must be an object")
    else:
        if len(bindings) > MAX_KEY_BINDINGS:
            errors.append(f"key_bindings: at most {MAX_KEY_BINDINGS}")
        for prefix, allowed in bindings.items():
            if not isinstance(allowed, list) or not allowed:
                errors.append(f"key_bindings.{prefix}: list at least one value or glob")
                continue
            for a in allowed:
                if not isinstance(a, str) or not a.strip() or len(a) > MAX_VALUE_LEN:
                    errors.append(f"key_bindings.{prefix}: '{a}' is not a valid value or glob")
                elif not _is_glob(a) and normalize_value(a) in (MISSING, INVALID):
                    errors.append(f"key_bindings.{prefix}: '{a}' is not a valid value")
    return errors
