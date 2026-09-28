"""Cross-app flow policy: validation, compilation and evaluation.

Pure: no I/O, no clock reads except where a caller passes one in. Everything
the guard path needs is precompiled here once per policy load, so evaluating a
call is glob and dict work only.

Vocabulary (docs/specs/cross-app-flow-control.md §3.1):

  app              a named application: the tools (globs) and MCP routes that
                   belong to it, the classification of data read from it, and
                   optionally a baseline exposure for data sent to it.
  classification   public < internal < confidential < restricted (the same
                   lattice as core/rbac.py clearances).
  exposure         internal < external < public: how far a call sends data.
  exposure rule    derives a call's exposure from its arguments
                   (github.create_repo private=false -> public).
  rule             source (apps / classification / tags) x destination
                   (apps / tools / exposure) -> block | require_approval | warn.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
CLASS_RANK = {c: i for i, c in enumerate(CLASSIFICATIONS)}
EXPOSURES = ("internal", "external", "public")
EXPO_RANK = {e: i for i, e in enumerate(EXPOSURES)}
ACTIONS = ("warn", "require_approval", "block")
ACTION_RANK = {"allow": 0, "warn": 1, "require_approval": 2, "block": 3}
MODES = ("enforce", "monitor")
PRINCIPAL_SCOPES = ("agent_user", "agent", "off")
EXPOSURE_OPS = ("equals", "not_equals", "in", "not_in", "matches",
                "domain_in", "domain_not_in", "missing")

DEFAULT_TAG_CLASSIFICATIONS = {
    # Mirrors guardrails/agentic/taint/taint_tracking._DEFAULT_TAINT_SENSITIVITY_MAP,
    # the tags tool_output_sanitization.taint_tags_for emits.
    "SSN": "restricted",
    "credit_card": "restricted",
    "secret": "confidential",
    "PII": "confidential",
    "internal_doc": "internal",
}

MAX_APPS = 200
MAX_RULES = 500
MAX_EXPOSURE_RULES = 200
MAX_LIST = 50
MAX_GLOB_LEN = 200
MAX_REGEX_LEN = 500
MAX_TEXT_LEN = 500
MAX_VALUE_CHARS = 4096       # argument values are truncated to this before matching
MAX_LEAVES = 200             # "*" walks at most this many argument leaves
MAX_TOOL_NAME = 256
MAX_SOURCES_IN_DETAILS = 10

_NAME_RE = re.compile(r"^[a-z0-9_.:-]{1,64}$")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")

_TOP_KEYS = {"enabled", "mode", "fail_closed", "session_ttl_seconds", "principal_scope",
             "principal_window_seconds", "default_exposure", "tag_classifications",
             "apps", "exposure_rules", "rules", "description"}
_APP_KEYS = {"tools", "routes", "classification", "source_tools", "exposure", "description"}
_EXPO_KEYS = {"tools", "apps", "param", "exposure", "description"} | set(EXPOSURE_OPS)
_RULE_KEYS = {"id", "description", "enabled", "source", "destination", "action",
              "message", "min_approvals", "approval_ttl_seconds"}
_SOURCE_KEYS = {"apps", "classifications", "min_classification", "tags"}
_DEST_KEYS = {"apps", "tools", "exposure"}


# ── validation ───────────────────────────────────────────────────────


class PolicyError(ValueError):
    """A policy failed validation. ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _unknown(obj: dict, allowed: set, where: str, errors: list[str]) -> None:
    for k in obj:
        if k not in allowed:
            errors.append(f"{where}: unknown field '{k}' (allowed: {', '.join(sorted(allowed))})")


def _bool(v: Any, default: bool, where: str, errors: list[str]) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    errors.append(f"{where}: must be true or false")
    return default


def _int(v: Any, default: int, lo: int, hi: int, where: str, errors: list[str]) -> int:
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        errors.append(f"{where}: must be an integer")
        return default
    if not lo <= v <= hi:
        errors.append(f"{where}: must be between {lo} and {hi}")
        return default
    return v


def _enum(v: Any, allowed: Iterable[str], default: Optional[str], where: str,
          errors: list[str]) -> Optional[str]:
    if v is None:
        return default
    if not isinstance(v, str) or v not in allowed:
        errors.append(f"{where}: must be one of {', '.join(allowed)}")
        return default
    return v


def _text(v: Any, where: str, errors: list[str]) -> str:
    if v is None:
        return ""
    if not isinstance(v, str):
        errors.append(f"{where}: must be a string")
        return ""
    if len(v) > MAX_TEXT_LEN:
        errors.append(f"{where}: longer than {MAX_TEXT_LEN} characters")
        return v[:MAX_TEXT_LEN]
    return v


def _str_list(v: Any, where: str, errors: list[str], *, max_len: int = MAX_GLOB_LEN,
              enum: Optional[Iterable[str]] = None) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        errors.append(f"{where}: must be a list of strings")
        return []
    if len(v) > MAX_LIST:
        errors.append(f"{where}: more than {MAX_LIST} entries")
        v = v[:MAX_LIST]
    out: list[str] = []
    allowed = tuple(enum) if enum is not None else None
    for i, item in enumerate(v):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{where}[{i}]: must be a non-empty string")
            continue
        item = item.strip()
        if len(item) > max_len:
            errors.append(f"{where}[{i}]: longer than {max_len} characters")
            continue
        if allowed is not None and item not in allowed:
            errors.append(f"{where}[{i}]: '{item}' must be one of {', '.join(allowed)}")
            continue
        if item not in out:
            out.append(item)
    return out


def _names(v: Any, where: str, errors: list[str], known: Optional[set] = None) -> list[str]:
    out = []
    for i, name in enumerate(_str_list(v, where, errors, max_len=64)):
        if not _NAME_RE.match(name):
            errors.append(f"{where}[{i}]: '{name}' must match {_NAME_RE.pattern}")
            continue
        if known is not None and name not in known:
            errors.append(f"{where}[{i}]: unknown app '{name}' (define it under apps)")
            continue
        out.append(name)
    return out


def _validate_app(name: str, raw: Any, errors: list[str]) -> Optional[dict]:
    where = f"apps.{name}"
    if not _NAME_RE.match(name):
        errors.append(f"apps: app name '{name}' must match {_NAME_RE.pattern}")
        return None
    if not isinstance(raw, dict):
        errors.append(f"{where}: must be an object")
        return None
    _unknown(raw, _APP_KEYS, where, errors)
    app = {
        "tools": _str_list(raw.get("tools"), f"{where}.tools", errors),
        "routes": _str_list(raw.get("routes"), f"{where}.routes", errors, max_len=128),
        "source_tools": _str_list(raw.get("source_tools"), f"{where}.source_tools", errors),
    }
    if not app["tools"] and not app["routes"]:
        errors.append(f"{where}: needs at least one of tools or routes")
    cls = _enum(raw.get("classification"), CLASSIFICATIONS, None, f"{where}.classification", errors)
    if cls:
        app["classification"] = cls
    expo = _enum(raw.get("exposure"), EXPOSURES, None, f"{where}.exposure", errors)
    if expo:
        app["exposure"] = expo
    desc = _text(raw.get("description"), f"{where}.description", errors)
    if desc:
        app["description"] = desc
    if app["source_tools"] and not cls:
        errors.append(f"{where}: source_tools has no effect without a classification")
    return app


def _validate_exposure_rule(i: int, raw: Any, apps: set, errors: list[str]) -> Optional[dict]:
    where = f"exposure_rules[{i}]"
    if not isinstance(raw, dict):
        errors.append(f"{where}: must be an object")
        return None
    _unknown(raw, _EXPO_KEYS, where, errors)
    rule: dict = {
        "tools": _str_list(raw.get("tools"), f"{where}.tools", errors),
        "apps": _names(raw.get("apps"), f"{where}.apps", errors, apps),
    }
    if not rule["tools"] and not rule["apps"]:
        errors.append(f"{where}: needs tools or apps (use tools: [\"*\"] to mean every call)")
    param = raw.get("param")
    if not isinstance(param, str) or not param.strip() or len(param) > 200:
        errors.append(f"{where}.param: required string (dotted path, '*' or '$resource')")
    else:
        rule["param"] = param.strip()
    expo = _enum(raw.get("exposure"), ("external", "public"), None, f"{where}.exposure", errors)
    if not expo:
        if raw.get("exposure") is None:
            errors.append(f"{where}.exposure: required (external or public)")
    else:
        rule["exposure"] = expo
    ops = [op for op in EXPOSURE_OPS if op in raw]
    if len(ops) != 1:
        errors.append(f"{where}: exactly one operator required, one of {', '.join(EXPOSURE_OPS)}")
        return None
    op = ops[0]
    val = raw[op]
    if op in ("equals", "not_equals"):
        if not isinstance(val, (str, int, float, bool)) or val is None:
            errors.append(f"{where}.{op}: must be a string, number or boolean")
            return None
    elif op in ("in", "not_in"):
        if not isinstance(val, list) or not val or len(val) > MAX_LIST or \
                not all(isinstance(x, (str, int, float, bool)) for x in val):
            errors.append(f"{where}.{op}: must be a non-empty list of up to {MAX_LIST} scalars")
            return None
    elif op == "matches":
        if not isinstance(val, str) or not val or len(val) > MAX_REGEX_LEN:
            errors.append(f"{where}.matches: must be a regex of 1..{MAX_REGEX_LEN} characters")
            return None
        try:
            re.compile(val)
        except re.error as e:
            errors.append(f"{where}.matches: invalid regex: {e}")
            return None
    elif op in ("domain_in", "domain_not_in"):
        doms = _str_list(val, f"{where}.{op}", errors, max_len=253)
        if not doms:
            errors.append(f"{where}.{op}: must be a non-empty list of domains")
            return None
        val = [d.lower().lstrip("@").lstrip(".") for d in doms]
    elif op == "missing":
        if not isinstance(val, bool):
            errors.append(f"{where}.missing: must be true or false")
            return None
    # Stored in the input shape ({op: value}) so a normalized policy validates
    # again unchanged when it is loaded back from the store.
    rule[op] = val
    desc = _text(raw.get("description"), f"{where}.description", errors)
    if desc:
        rule["description"] = desc
    return rule


def _validate_rule(i: int, raw: Any, apps: set, seen: set, errors: list[str]) -> Optional[dict]:
    where = f"rules[{i}]"
    if not isinstance(raw, dict):
        errors.append(f"{where}: must be an object")
        return None
    _unknown(raw, _RULE_KEYS, where, errors)
    rid = raw.get("id")
    if not isinstance(rid, str) or not _NAME_RE.match(rid):
        errors.append(f"{where}.id: required, must match {_NAME_RE.pattern}")
        rid = f"rule_{i}"
    elif rid in seen:
        errors.append(f"{where}.id: duplicate id '{rid}'")
    seen.add(rid)
    where = f"rules[{rid}]"

    src_raw = raw.get("source") or {}
    if not isinstance(src_raw, dict):
        errors.append(f"{where}.source: must be an object")
        src_raw = {}
    _unknown(src_raw, _SOURCE_KEYS, f"{where}.source", errors)
    source = {
        "apps": _names(src_raw.get("apps"), f"{where}.source.apps", errors, apps),
        "classifications": _str_list(src_raw.get("classifications"),
                                     f"{where}.source.classifications", errors,
                                     enum=CLASSIFICATIONS),
        "tags": _str_list(src_raw.get("tags"), f"{where}.source.tags", errors, max_len=64),
    }
    mc = _enum(src_raw.get("min_classification"), CLASSIFICATIONS, None,
               f"{where}.source.min_classification", errors)
    if mc:
        source["min_classification"] = mc
    if not (source["apps"] or source["classifications"] or source["tags"] or mc):
        errors.append(f"{where}.source: set at least one of apps, classifications, "
                      f"min_classification or tags (an empty source would match every read)")

    dst_raw = raw.get("destination") or {}
    if not isinstance(dst_raw, dict):
        errors.append(f"{where}.destination: must be an object")
        dst_raw = {}
    _unknown(dst_raw, _DEST_KEYS, f"{where}.destination", errors)
    dest = {
        "apps": _names(dst_raw.get("apps"), f"{where}.destination.apps", errors, apps),
        "tools": _str_list(dst_raw.get("tools"), f"{where}.destination.tools", errors),
        "exposure": _str_list(dst_raw.get("exposure"), f"{where}.destination.exposure",
                              errors, enum=EXPOSURES),
    }
    if not (dest["apps"] or dest["tools"] or dest["exposure"]):
        errors.append(f"{where}.destination: set at least one of apps, tools or exposure")

    action = _enum(raw.get("action"), ACTIONS, "block", f"{where}.action", errors)
    rule = {
        "id": rid,
        "enabled": _bool(raw.get("enabled"), True, f"{where}.enabled", errors),
        "source": source,
        "destination": dest,
        "action": action,
        "min_approvals": _int(raw.get("min_approvals"), 1, 1, 5, f"{where}.min_approvals", errors),
        "approval_ttl_seconds": _int(raw.get("approval_ttl_seconds"), 3600, 60, 86400,
                                     f"{where}.approval_ttl_seconds", errors),
    }
    for k in ("description", "message"):
        t = _text(raw.get(k), f"{where}.{k}", errors)
        if t:
            rule[k] = t
    return rule


def validate_policy(raw: Any) -> dict:
    """Validate and normalize a policy. Raises PolicyError listing every problem.

    Strict on unknown keys at every level: a misspelled field in a security
    policy that is silently ignored is a rule that silently never fires.
    """
    errors: list[str] = []
    if not isinstance(raw, dict):
        raise PolicyError(["policy: must be a JSON object"])
    _unknown(raw, _TOP_KEYS, "policy", errors)

    apps_raw = raw.get("apps") or {}
    if not isinstance(apps_raw, dict):
        errors.append("apps: must be an object keyed by app name")
        apps_raw = {}
    if len(apps_raw) > MAX_APPS:
        errors.append(f"apps: more than {MAX_APPS} apps")
    apps: dict[str, dict] = {}
    for name, app_raw in list(apps_raw.items())[:MAX_APPS]:
        app = _validate_app(str(name), app_raw, errors)
        if app is not None:
            apps[str(name)] = app
    app_names = set(apps_raw.keys())

    tagc_raw = raw.get("tag_classifications") or {}
    tag_classes = dict(DEFAULT_TAG_CLASSIFICATIONS)
    if not isinstance(tagc_raw, dict):
        errors.append("tag_classifications: must be an object {tag: classification}")
    else:
        for tag, cls in tagc_raw.items():
            if not isinstance(tag, str) or not tag or len(tag) > 64:
                errors.append(f"tag_classifications: bad tag {tag!r}")
            elif cls not in CLASSIFICATIONS:
                errors.append(f"tag_classifications.{tag}: must be one of {', '.join(CLASSIFICATIONS)}")
            else:
                tag_classes[tag] = cls

    expo_raw = raw.get("exposure_rules") or []
    if not isinstance(expo_raw, list):
        errors.append("exposure_rules: must be a list")
        expo_raw = []
    if len(expo_raw) > MAX_EXPOSURE_RULES:
        errors.append(f"exposure_rules: more than {MAX_EXPOSURE_RULES} rules")
    exposure_rules = [r for r in (_validate_exposure_rule(i, x, app_names, errors)
                                  for i, x in enumerate(expo_raw[:MAX_EXPOSURE_RULES]))
                      if r is not None]

    rules_raw = raw.get("rules") or []
    if not isinstance(rules_raw, list):
        errors.append("rules: must be a list")
        rules_raw = []
    if len(rules_raw) > MAX_RULES:
        errors.append(f"rules: more than {MAX_RULES} rules")
    seen: set = set()
    rules = [r for r in (_validate_rule(i, x, app_names, seen, errors)
                         for i, x in enumerate(rules_raw[:MAX_RULES]))
             if r is not None]

    policy = {
        "enabled": _bool(raw.get("enabled"), True, "enabled", errors),
        "mode": _enum(raw.get("mode"), MODES, "enforce", "mode", errors),
        "fail_closed": _bool(raw.get("fail_closed"), False, "fail_closed", errors),
        "session_ttl_seconds": _int(raw.get("session_ttl_seconds"), 3600, 60, 86400,
                                    "session_ttl_seconds", errors),
        "principal_scope": _enum(raw.get("principal_scope"), PRINCIPAL_SCOPES, "agent_user",
                                 "principal_scope", errors),
        "principal_window_seconds": _int(raw.get("principal_window_seconds"), 3600, 60, 86400,
                                         "principal_window_seconds", errors),
        "default_exposure": _enum(raw.get("default_exposure"), EXPOSURES, "internal",
                                  "default_exposure", errors),
        "tag_classifications": {k: v for k, v in tag_classes.items()
                                if DEFAULT_TAG_CLASSIFICATIONS.get(k) != v
                                or k not in DEFAULT_TAG_CLASSIFICATIONS},
        "apps": apps,
        "exposure_rules": exposure_rules,
        "rules": rules,
    }
    desc = _text(raw.get("description"), "description", errors)
    if desc:
        policy["description"] = desc
    if errors:
        raise PolicyError(errors)
    return policy


# ── compilation ──────────────────────────────────────────────────────


def _glob_re(globs: list[str]) -> Optional[re.Pattern]:
    if not globs:
        return None
    return re.compile("|".join(f"(?:{fnmatch.translate(g.lower())})" for g in globs))


@dataclass
class _App:
    name: str
    tools: Optional[re.Pattern]
    routes: frozenset
    classification: Optional[str]
    source_tools: Optional[re.Pattern]
    exposure: Optional[str]


@dataclass
class _ExpoRule:
    tools: Optional[re.Pattern]
    apps: frozenset
    param: str
    op: str
    value: Any
    regex: Optional[re.Pattern]
    exposure: str


@dataclass
class _Rule:
    id: str
    raw: dict
    src_apps: frozenset
    src_classes: frozenset
    src_min: Optional[int]
    src_tags: frozenset
    dst_apps: frozenset
    dst_tools: Optional[re.Pattern]
    dst_exposure: frozenset
    action: str


@dataclass
class CompiledPolicy:
    raw: dict
    enabled: bool
    mode: str
    fail_closed: bool
    session_ttl: int
    principal_scope: str
    principal_window: int
    default_exposure: str
    tag_classes: dict
    apps: list = field(default_factory=list)
    exposure_rules: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    has_sources: bool = False


def compile_policy(policy: dict) -> CompiledPolicy:
    """Compile a *validated* policy (the output of validate_policy)."""
    tag_classes = dict(DEFAULT_TAG_CLASSIFICATIONS)
    tag_classes.update(policy.get("tag_classifications") or {})
    cp = CompiledPolicy(
        raw=policy,
        enabled=bool(policy.get("enabled", True)),
        mode=policy.get("mode", "enforce"),
        fail_closed=bool(policy.get("fail_closed", False)),
        session_ttl=int(policy.get("session_ttl_seconds", 3600)),
        principal_scope=policy.get("principal_scope", "agent_user"),
        principal_window=int(policy.get("principal_window_seconds", 3600)),
        default_exposure=policy.get("default_exposure", "internal"),
        tag_classes=tag_classes,
    )
    for name, app in (policy.get("apps") or {}).items():
        cp.apps.append(_App(
            name=name,
            tools=_glob_re(app.get("tools") or []),
            routes=frozenset(r.lower() for r in app.get("routes") or []),
            classification=app.get("classification"),
            source_tools=_glob_re(app.get("source_tools") or []),
            exposure=app.get("exposure"),
        ))
    cp.has_sources = any(a.classification for a in cp.apps)
    for r in policy.get("exposure_rules") or []:
        op = next(o for o in EXPOSURE_OPS if o in r)
        cp.exposure_rules.append(_ExpoRule(
            tools=_glob_re(r.get("tools") or []),
            apps=frozenset(r.get("apps") or []),
            param=r["param"],
            op=op,
            value=r[op],
            regex=re.compile(r[op]) if op == "matches" else None,
            exposure=r["exposure"],
        ))
    for r in policy.get("rules") or []:
        if not r.get("enabled", True):
            continue
        src, dst = r["source"], r["destination"]
        cp.rules.append(_Rule(
            id=r["id"],
            raw=r,
            src_apps=frozenset(src.get("apps") or []),
            src_classes=frozenset(src.get("classifications") or []),
            src_min=CLASS_RANK[src["min_classification"]] if src.get("min_classification") else None,
            src_tags=frozenset(src.get("tags") or []),
            dst_apps=frozenset(dst.get("apps") or []),
            dst_tools=_glob_re(dst.get("tools") or []),
            dst_exposure=frozenset(dst.get("exposure") or []),
            action=r.get("action", "block"),
        ))
    return cp


# ── classification of a call ─────────────────────────────────────────


def _norm_tool(tool_name: str) -> str:
    return (tool_name or "")[:MAX_TOOL_NAME].lower()


def apps_for(cp: CompiledPolicy, tool_name: str, route: Optional[str] = None) -> list[str]:
    """Every app the call belongs to: tool-glob matches UNION route matches.

    A union, so a caller-asserted route can add an app but never remove one
    the tool name already matched.
    """
    tool = _norm_tool(tool_name)
    rt = (route or "").lower()
    out = []
    for app in cp.apps:
        if (app.tools is not None and app.tools.fullmatch(tool)) or (rt and rt in app.routes):
            out.append(app.name)
    return out


def source_classification(cp: CompiledPolicy, tool_name: str,
                          apps: list[str]) -> Optional[str]:
    """Classification of data this call reads, or None if it is not a source.

    The max over the call's apps that carry a classification and whose
    source_tools (default: all of the app's tools) match this tool.
    """
    tool = _norm_tool(tool_name)
    best: Optional[str] = None
    by_name = {a.name: a for a in cp.apps}
    for name in apps:
        app = by_name.get(name)
        if app is None or not app.classification:
            continue
        if app.source_tools is not None and not app.source_tools.fullmatch(tool):
            continue
        if best is None or CLASS_RANK[app.classification] > CLASS_RANK[best]:
            best = app.classification
    return best


def effective_classification(cp: CompiledPolicy, record: dict) -> Optional[str]:
    """A record's classification lifted by its detected tags."""
    best = record.get("classification") if record.get("classification") in CLASS_RANK else None
    for tag in record.get("tags") or []:
        c = cp.tag_classes.get(tag)
        if c and (best is None or CLASS_RANK[c] > CLASS_RANK[best]):
            best = c
    return best


# ── exposure ─────────────────────────────────────────────────────────

_MISSING = object()


def _walk_leaves(value: Any, out: list, depth: int = 0) -> None:
    if len(out) >= MAX_LEAVES or depth > 8:
        return
    if isinstance(value, dict):
        for v in value.values():
            _walk_leaves(v, out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _walk_leaves(v, out, depth + 1)
    elif value is not None:
        out.append(value)


def _resolve_param(params: dict, path: str, resource: Optional[str]) -> Any:
    """The argument at ``path``: a dotted path, '*' (every leaf) or '$resource'."""
    if path == "$resource":
        return resource if resource else _MISSING
    if path == "*":
        leaves: list = []
        _walk_leaves(params, leaves)
        return leaves if leaves else _MISSING
    cur: Any = params
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return _MISSING if cur is None else cur


def _candidates(value: Any) -> list:
    """Scalars to test: a list argument matches when any element does."""
    if isinstance(value, (dict, list, tuple)):
        leaves: list = []
        _walk_leaves(value, leaves)
        return leaves
    return [value]


def _loose_eq(value: Any, target: Any) -> bool:
    if isinstance(target, bool):
        if isinstance(value, bool):
            return value is target
        if isinstance(value, str):
            return value.strip().lower() == ("true" if target else "false")
        if isinstance(value, (int, float)):
            return value in (0, 1) and bool(value) is target
        return False
    if isinstance(target, (int, float)):
        if isinstance(value, bool):
            return False
        try:
            return float(value) == float(target)
        except (TypeError, ValueError):
            return False
    return str(value).strip().lower() == str(target).strip().lower()


def _domains(values: list) -> list[str]:
    out = []
    for v in values:
        if not isinstance(v, str):
            continue
        for m in _EMAIL_RE.finditer(v[:MAX_VALUE_CHARS]):
            out.append(m.group(1).lower())
    return out


def _domain_allowed(domain: str, allowed: list[str]) -> bool:
    return any(domain == a or domain.endswith("." + a) for a in allowed)


def _expo_rule_hits(rule: _ExpoRule, params: dict, resource: Optional[str]) -> bool:
    value = _resolve_param(params, rule.param, resource)
    if rule.op == "missing":
        return (value is _MISSING) is rule.value
    if value is _MISSING:
        return False
    cands = _candidates(value)
    if rule.op == "equals":
        return any(_loose_eq(c, rule.value) for c in cands)
    if rule.op == "not_equals":
        return any(not _loose_eq(c, rule.value) for c in cands)
    if rule.op == "in":
        return any(any(_loose_eq(c, t) for t in rule.value) for c in cands)
    if rule.op == "not_in":
        return any(not any(_loose_eq(c, t) for t in rule.value) for c in cands)
    if rule.op == "matches":
        return any(rule.regex.search(str(c)[:MAX_VALUE_CHARS]) for c in cands)
    if rule.op == "domain_not_in":
        return any(not _domain_allowed(d, rule.value) for d in _domains(cands))
    if rule.op == "domain_in":
        return any(_domain_allowed(d, rule.value) for d in _domains(cands))
    return False


def exposure_for(cp: CompiledPolicy, tool_name: str, apps: list[str],
                 params: Optional[dict], resource: Optional[str] = None) -> str:
    """How far this call sends data. Only ever escalates from the baseline."""
    tool = _norm_tool(tool_name)
    params = params if isinstance(params, dict) else {}
    best = cp.default_exposure
    app_set = set(apps)
    for app in cp.apps:
        if app.name in app_set and app.exposure and EXPO_RANK[app.exposure] > EXPO_RANK[best]:
            best = app.exposure
    for rule in cp.exposure_rules:
        if EXPO_RANK[rule.exposure] <= EXPO_RANK[best]:
            continue
        in_scope = (rule.tools is not None and rule.tools.fullmatch(tool)) or \
            bool(rule.apps & app_set)
        if in_scope and _expo_rule_hits(rule, params, resource):
            best = rule.exposure
    return best


# ── evaluation ───────────────────────────────────────────────────────


def destination_rules(cp: CompiledPolicy, tool_name: str, apps: list[str],
                      exposure: str) -> list[_Rule]:
    """Rules whose destination matches this call (every field a rule sets)."""
    tool = _norm_tool(tool_name)
    app_set = set(apps)
    out = []
    for rule in cp.rules:
        if rule.dst_apps and not (rule.dst_apps & app_set):
            continue
        if rule.dst_tools is not None and not rule.dst_tools.fullmatch(tool):
            continue
        if rule.dst_exposure and exposure not in rule.dst_exposure:
            continue
        out.append(rule)
    return out


def source_matches(cp: CompiledPolicy, rule: _Rule, record: dict) -> bool:
    if rule.src_apps and not (rule.src_apps & set(record.get("apps") or [])):
        return False
    if not (rule.src_classes or rule.src_min is not None or rule.src_tags):
        return True
    eff = effective_classification(cp, record)
    if eff is not None:
        if eff in rule.src_classes:
            return True
        if rule.src_min is not None and CLASS_RANK[eff] >= rule.src_min:
            return True
    return bool(rule.src_tags & set(record.get("tags") or []))


def _describe_source(cp: CompiledPolicy, rec: dict) -> dict:
    return {
        "apps": list(rec.get("apps") or []),
        "tool": rec.get("tool", ""),
        "route": rec.get("route", ""),
        "classification": effective_classification(cp, rec),
        "tags": list(rec.get("tags") or []),
        "evidence": rec.get("evidence", ""),
        "tool_call_id": rec.get("tool_call_id", ""),
        "path": rec.get("path", ""),
        "scope": rec.get("scope", ""),
        "at": rec.get("at"),
    }


def _source_label(src: dict) -> str:
    app = ", ".join(src["apps"]) or "unclassified tool"
    cls = src["classification"] or "tagged"
    tags = f" [{', '.join(src['tags'])}]" if src["tags"] else ""
    return f"{cls}{tags} data from {app} ({src['tool']})"


def _dest_label(dest: dict) -> str:
    app = ", ".join(dest["apps"]) if dest["apps"] else "an unclassified tool"
    return f"{app} ({dest['tool']}, {dest['exposure']} destination)"


def evaluate(cp: CompiledPolicy, *, tool_name: str, apps: list[str], exposure: str,
             records: list[dict], rules: Optional[list[_Rule]] = None) -> dict:
    """Judge one outgoing call against the session's recorded sources.

    Returns {action, violations, destination, message, lineage}. ``action`` is
    the strongest over every violated rule: block > require_approval > warn,
    or "allow". Mode (monitor) is applied by the caller, not here.
    """
    dest = {"tool": tool_name, "apps": list(apps), "exposure": exposure}
    rules = destination_rules(cp, tool_name, apps, exposure) if rules is None else rules
    violations = []
    for rule in rules:
        hits = [r for r in records if source_matches(cp, rule, r)]
        if not hits:
            continue
        hits.sort(key=lambda r: r.get("at") or 0, reverse=True)
        violations.append({
            "rule_id": rule.id,
            "action": rule.action,
            "description": rule.raw.get("description", ""),
            "rule_message": rule.raw.get("message", ""),
            "min_approvals": rule.raw.get("min_approvals", 1),
            "approval_ttl_seconds": rule.raw.get("approval_ttl_seconds", 3600),
            "sources": [_describe_source(cp, r) for r in hits[:MAX_SOURCES_IN_DETAILS]],
            "source_count": len(hits),
            "destination": dest,
        })
    if not violations:
        return {"action": "allow", "violations": [], "destination": dest,
                "message": "", "lineage": []}
    violations.sort(key=lambda v: ACTION_RANK[v["action"]], reverse=True)
    top = violations[0]
    lineage = [f"{_source_label(s)} -> {_dest_label(dest)}"
               for v in violations for s in v["sources"][:3]]
    verb = {"block": "blocked", "require_approval": "requires approval",
            "warn": "flagged"}[top["action"]]
    message = top["rule_message"] or (
        f"Cross-app flow {verb} by rule '{top['rule_id']}': "
        f"{_source_label(top['sources'][0])} may not be sent to {_dest_label(dest)}"
    )
    return {"action": top["action"], "violations": violations, "destination": dest,
            "message": message, "lineage": lineage}


# ── source records ───────────────────────────────────────────────────


def fingerprint(record: dict) -> str:
    """Stable field name for a source record: repeated reads overwrite one field."""
    key = "|".join([
        record.get("tool", ""), record.get("route", ""),
        record.get("classification") or "", ",".join(sorted(record.get("tags") or [])),
    ])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def make_record(*, tool_name: str, route: Optional[str], apps: list[str],
                classification: Optional[str], tags: Optional[list[str]],
                evidence: str, path: str, at: float,
                tool_call_id: Optional[str] = None,
                input_sources: Optional[list[str]] = None) -> dict:
    return {
        "apps": list(apps),
        "tool": (tool_name or "")[:MAX_TOOL_NAME],
        "route": (route or "")[:128],
        "classification": classification,
        "tags": sorted({str(t)[:64] for t in (tags or []) if t})[:20],
        "evidence": evidence,
        "path": path,
        "tool_call_id": (tool_call_id or "")[:128],
        "input_sources": [str(s)[:128] for s in (input_sources or [])][:20],
        "at": at,
    }


# ── starter policy ───────────────────────────────────────────────────


def starter_policy() -> dict:
    """The template the portal and GET /template offer. Validates as-is.

    Tool globs cover both naming styles: the agent registry only accepts
    [A-Za-z0-9_-] (drive_read_file), MCP servers often use dots (drive.read_file).
    """
    return {
        "enabled": True,
        "mode": "monitor",
        "fail_closed": False,
        "session_ttl_seconds": 3600,
        "principal_scope": "agent_user",
        "principal_window_seconds": 3600,
        "default_exposure": "internal",
        "apps": {
            "google_drive": {"tools": ["drive_*", "drive.*", "gdrive_*", "google_drive*"],
                             "classification": "confidential",
                             "description": "Documents; treat everything read as confidential"},
            "salesforce": {"tools": ["salesforce_*", "salesforce.*", "sfdc_*"],
                           "classification": "confidential",
                           "source_tools": ["salesforce_get*", "salesforce_search*",
                                            "salesforce_query*", "salesforce.get*",
                                            "salesforce.search*", "salesforce.query*",
                                            "sfdc_get*", "sfdc_query*"],
                           "description": "Customer records"},
            "github": {"tools": ["github_*", "github.*"], "classification": "internal"},
            "jira": {"tools": ["jira_*", "jira.*"], "classification": "internal"},
            "gmail": {"tools": ["gmail_*", "gmail.*", "email_*", "email.*", "send_email*"]},
            "slack": {"tools": ["slack_*", "slack.*"], "classification": "internal"},
            "public_web": {"tools": ["web_post*", "web.post*", "pastebin_*", "pastebin.*",
                                     "http_post*", "http.post*"],
                           "exposure": "public",
                           "description": "Anything that publishes to the open internet"},
        },
        "exposure_rules": [
            {"tools": ["github_create_repo*", "github.create_repo*",
                       "github_update_repo*", "github.update_repo*"],
             "param": "private", "equals": False, "exposure": "public",
             "description": "A repository created or switched to public"},
            {"tools": ["github_create_repo*", "github.create_repo*"],
             "param": "private", "missing": True, "exposure": "public",
             "description": "GitHub creates public repositories unless private is set"},
            {"apps": ["github"], "param": "visibility", "in": ["public"], "exposure": "public"},
            {"tools": ["drive_share*", "drive.share*", "gdrive_share*"], "param": "type",
             "in": ["anyone"], "exposure": "public",
             "description": "Anyone-with-the-link sharing"},
            {"apps": ["gmail"], "param": "*", "domain_not_in": ["example.com"],
             "exposure": "external",
             "description": "Mail to any address outside your domains (edit the list)"},
            {"apps": ["slack"], "param": "channel", "matches": "^(ext-|shared-)",
             "exposure": "external", "description": "Slack Connect / shared channels"},
        ],
        "rules": [
            {"id": "confidential-to-public",
             "description": "Confidential or restricted data may never be published",
             "source": {"min_classification": "confidential"},
             "destination": {"exposure": ["public"]},
             "action": "block"},
            {"id": "customer-data-external",
             "description": "Customer data leaving the company needs a human",
             "source": {"apps": ["salesforce"]},
             "destination": {"exposure": ["external"]},
             "action": "require_approval"},
            {"id": "regulated-pii-anywhere-out",
             "description": "SSNs and card numbers never leave, even by approval",
             "source": {"tags": ["SSN", "credit_card"]},
             "destination": {"exposure": ["external", "public"]},
             "action": "block"},
            {"id": "confidential-to-chat",
             "description": "Flag confidential documents posted to chat",
             "source": {"apps": ["google_drive"]},
             "destination": {"apps": ["slack"]},
             "action": "warn"},
        ],
    }
