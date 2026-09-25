"""Sigma rules as a Shield policy format: parse, validate, match, dump.

Sigma (https://sigmahq.io) is the YAML detection-rule format security teams use
across Sentinel, Splunk, Elastic and QRadar. Shield lets a custom input/output
policy be written as a Sigma rule instead of natural language. Such a policy is
enforced by the existing custom-policy guardrails; this module only decides
whether a rule matches.

Matching is **deterministic**: no LLM, no network. A policy event is a flat dict:

    message      the text being screened (prompt on input, model output on output)
    stage        "input" | "output"
    user_role, session_id, agent_id, tool_name, tool_input

Supported Sigma subset (anything else is rejected at validation time, so a rule
never silently matches nothing):

  * detection identifiers holding a field map (AND of fields), a list of field
    maps (OR), or a keyword list / single keyword (searched in `message`);
  * values: case-insensitive equality with `*` / `?` wildcards; a list is OR;
    `null` means the field is absent or empty;
  * modifiers: contains, startswith, endswith, all, cased, exists, re (with the
    re sub-flags i, m, s);
  * condition: identifiers, and / or / not, parentheses, `1 of x*`,
    `all of x*`, `1 of them`, `all of them`; a list of conditions is OR.

Not supported (rejected): correlation/aggregation (`| count()`, `timeframe`),
and modifiers such as base64, windash, cidr, lt/gt.

Safety: YAML is loaded with a SafeLoader that refuses anchors and aliases (no
billion-laughs expansion), rule text is size-capped, and every regex runs under a
per-evaluation deadline using the `regex` module, which (unlike stdlib `re`) can
be interrupted.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Union

import regex
import yaml

#: Largest rule text accepted, in bytes.
MAX_RULE_BYTES = 64 * 1024

#: Fields a Sigma policy may match on. Anything else is allowed (Sigma rules are
#: often written against other schemas) but can only match if the event has it.
POLICY_FIELDS = ("message", "stage", "user_role", "session_id",
                 "agent_id", "tool_name", "tool_input")

SUPPORTED_MODIFIERS = frozenset({
    "contains", "startswith", "endswith", "all", "cased", "exists", "re",
    # sub-flags of `re`
    "i", "m", "s",
})

LEVELS = ("informational", "low", "medium", "high", "critical")

_KEYWORDS = frozenset({"and", "or", "not", "of", "them", "1", "all", "any"})


class SigmaRuleError(ValueError):
    """The rule is malformed or uses an unsupported Sigma feature."""


class SigmaEvalTimeout(RuntimeError):
    """Evaluation exceeded its time budget (a pattern that cannot finish)."""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that refuses YAML anchors and aliases.

    safe_load does not bound alias expansion, so a small document can expand
    into gigabytes. Sigma rules never need anchors, so refuse them outright.
    """

    def fetch_alias(self):
        raise SigmaRuleError("YAML aliases are not allowed in Sigma rules")

    def fetch_anchor(self):
        raise SigmaRuleError("YAML anchors are not allowed in Sigma rules")


def _load_yaml_docs(text: str) -> list:
    if len(text.encode("utf-8", "ignore")) > MAX_RULE_BYTES:
        raise SigmaRuleError(f"rule text exceeds {MAX_RULE_BYTES} bytes")
    try:
        return [d for d in yaml.load_all(text, Loader=_NoAliasLoader) if d is not None]
    except SigmaRuleError:
        raise
    except yaml.YAMLError as e:
        raise SigmaRuleError(f"invalid YAML: {e}") from e


def parse_documents(source: Union[str, dict, list]) -> list:
    """Load rule documents WITHOUT validating them (so callers can report per rule).

    Accepts YAML text (one or many `---` documents), a rule object, or a list of
    rule objects. Raises SigmaRuleError only when the input cannot be read at all.
    """
    if isinstance(source, (dict, list)):
        # Objects (JSON request bodies) get the same size cap as YAML text.
        import json
        try:
            size = len(json.dumps(source, default=str))
        except (TypeError, ValueError) as e:
            raise SigmaRuleError(f"rule is not serializable: {e}") from e
        if size > MAX_RULE_BYTES:
            raise SigmaRuleError(f"rule exceeds {MAX_RULE_BYTES} bytes")
        docs = [source] if isinstance(source, dict) else source
    elif isinstance(source, str):
        docs = _load_yaml_docs(source)
    else:
        raise SigmaRuleError("a Sigma rule must be YAML text or an object")
    if not docs:
        raise SigmaRuleError("no Sigma rule found")
    return docs


def load_rules(source: Union[str, dict, list]) -> list[dict]:
    """Load and validate one or more rules; raises on the first invalid one."""
    rules = []
    for d in parse_documents(source):
        if not isinstance(d, dict):
            raise SigmaRuleError("each Sigma document must be a mapping")
        validate_rule(d)
        rules.append(d)
    return rules


def load_rule(source: Union[str, dict]) -> dict:
    """Load exactly one rule."""
    rules = load_rules(source)
    if len(rules) != 1:
        raise SigmaRuleError(f"expected one Sigma rule, got {len(rules)}")
    return rules[0]


def dump_rule(rule: dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True)


def dump_rules(rules: Iterable[dict]) -> str:
    return yaml.safe_dump_all(list(rules), sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _split_key(key: str) -> tuple[str, list[str]]:
    parts = str(key).split("|")
    return parts[0], [p.strip().lower() for p in parts[1:]]


def _validate_modifiers(key: str, mods: list[str], value: Any) -> None:
    for m in mods:
        if m not in SUPPORTED_MODIFIERS:
            raise SigmaRuleError(f"unsupported Sigma modifier '{m}' in '{key}'")
    if any(m in ("i", "m", "s") for m in mods) and "re" not in mods:
        raise SigmaRuleError(f"'{key}': i/m/s are only valid after the re modifier")
    if "re" in mods:
        for v in (value if isinstance(value, list) else [value]):
            try:
                regex.compile(str(v))
            except regex.error as e:
                raise SigmaRuleError(f"'{key}': invalid regex {v!r}: {e}") from e
    if "exists" in mods and not isinstance(value, bool):
        raise SigmaRuleError(f"'{key}': the exists modifier takes true or false")


def _validate_search(name: str, value: Any) -> None:
    if isinstance(value, dict):
        if not value:
            raise SigmaRuleError(f"detection '{name}' is empty")
        for key, v in value.items():
            fld, mods = _split_key(key)
            if not fld:
                raise SigmaRuleError(f"detection '{name}' has an empty field name")
            if isinstance(v, dict):
                raise SigmaRuleError(f"'{name}.{key}': nested maps are not valid Sigma")
            _validate_modifiers(key, mods, v)
    elif isinstance(value, list):
        if not value:
            raise SigmaRuleError(f"detection '{name}' is an empty list")
        if all(isinstance(v, dict) for v in value):
            for v in value:
                _validate_search(name, v)
        elif any(isinstance(v, (dict, list)) for v in value):
            raise SigmaRuleError(
                f"detection '{name}' mixes field maps and keywords")
    elif not isinstance(value, (str, int, float)):
        raise SigmaRuleError(f"detection '{name}' has an unsupported value type")


def validate_rule(rule: dict) -> None:
    """Raise SigmaRuleError if the rule is malformed or uses unsupported features."""
    if not isinstance(rule, dict):
        raise SigmaRuleError("a Sigma rule must be a mapping")
    title = rule.get("title")
    if not isinstance(title, str) or not title.strip():
        raise SigmaRuleError("Sigma rule needs a non-empty 'title'")
    level = rule.get("level")
    if level is not None and str(level).lower() not in LEVELS:
        raise SigmaRuleError(f"unknown level '{level}'; allowed: {list(LEVELS)}")
    logsource = rule.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        raise SigmaRuleError("'logsource' must be a mapping")

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaRuleError("Sigma rule needs a 'detection' mapping")
    if "timeframe" in detection:
        raise SigmaRuleError("'timeframe' (correlation) is not supported")
    condition = detection.get("condition")
    conditions = condition if isinstance(condition, list) else [condition]
    if not conditions or not all(isinstance(c, str) and c.strip() for c in conditions):
        raise SigmaRuleError("detection needs a non-empty 'condition'")

    searches = {k: v for k, v in detection.items() if k != "condition"}
    if not searches:
        raise SigmaRuleError("detection has a condition but no search identifiers")
    for name, value in searches.items():
        _validate_search(name, value)

    for c in conditions:
        if "|" in c:
            raise SigmaRuleError("aggregation in the condition ('| count()') is not supported")
        # Parse to catch syntax errors and unknown identifiers now, not at runtime.
        _Parser(_tokenize(c), set(searches)).parse()


# ---------------------------------------------------------------------------
# Condition parsing
# ---------------------------------------------------------------------------

_TOKEN = regex.compile(r"\s*(\(|\)|[^\s()]+)")


def _tokenize(expr: str) -> list[str]:
    tokens, pos = [], 0
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            raise SigmaRuleError(f"cannot parse condition near: {expr[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def _pattern_matches(pattern: str, names: Iterable[str]) -> list[str]:
    if pattern == "them":
        return sorted(names)
    rx = regex.compile("^" + regex.escape(pattern).replace(r"\*", ".*") + "$")
    return sorted(n for n in names if rx.match(n))


class _Parser:
    """Recursive-descent parser: or < and < not < atom."""

    def __init__(self, tokens: list[str], names: set[str]):
        self.toks, self.i, self.names = tokens, 0, names

    def _peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _take(self) -> str:
        tok = self._peek()
        if tok is None:
            raise SigmaRuleError("condition ended unexpectedly")
        self.i += 1
        return tok

    def parse(self):
        node = self._or()
        if self._peek() is not None:
            raise SigmaRuleError(f"unexpected token '{self._peek()}' in condition")
        return node

    def _or(self):
        node = self._and()
        while (self._peek() or "").lower() == "or":
            self._take()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while (self._peek() or "").lower() == "and":
            self._take()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if (self._peek() or "").lower() == "not":
            self._take()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        tok = self._take()
        low = tok.lower()
        if tok == "(":
            node = self._or()
            if self._take() != ")":
                raise SigmaRuleError("missing ')' in condition")
            return node
        if low in ("1", "any", "all") and (self._peek() or "").lower() == "of":
            self._take()
            target = self._take()
            names = _pattern_matches(target, self.names)
            if not names:
                raise SigmaRuleError(f"'{tok} of {target}' matches no search identifier")
            return ("all" if low == "all" else "any", names)
        if low in _KEYWORDS or tok == ")":
            raise SigmaRuleError(f"unexpected '{tok}' in condition")
        if tok not in self.names:
            raise SigmaRuleError(f"condition references unknown identifier '{tok}'")
        return ("id", tok)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _eval_timeout_s() -> float:
    try:
        return max(1, int(os.environ.get("SHIELD_SIGMA_EVAL_TIMEOUT_MS", "250"))) / 1000.0
    except (TypeError, ValueError):
        return 0.25


class _Deadline:
    def __init__(self, budget_s: float):
        self.end = time.monotonic() + budget_s

    def remaining(self) -> float:
        left = self.end - time.monotonic()
        if left <= 0:
            raise SigmaEvalTimeout("Sigma rule evaluation exceeded its time budget")
        return left


def _wildcard_regex(value: str) -> str:
    """Sigma wildcard string -> anchored regex. `\\*` and `\\?` are literals."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(regex.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(regex.escape(ch))
        i += 1
    return "^" + "".join(out) + "$"


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _match_value(actual: Any, expected: Any, mods: list[str], dl: _Deadline) -> bool:
    """One event value against one rule value, honoring modifiers."""
    if expected is None:
        return actual in (None, "", [])
    text = actual if isinstance(actual, str) else str(actual)
    exp = str(expected)
    if "re" in mods:
        flags = 0
        if "i" in mods:
            flags |= regex.IGNORECASE
        if "m" in mods:
            flags |= regex.MULTILINE
        if "s" in mods:
            flags |= regex.DOTALL
        try:
            return regex.search(exp, text, flags=flags, timeout=dl.remaining()) is not None
        except TimeoutError as e:
            raise SigmaEvalTimeout(str(e)) from e

    cased = "cased" in mods
    if "contains" in mods:
        exp = f"*{exp}*"
    elif "startswith" in mods:
        exp = f"{exp}*"
    elif "endswith" in mods:
        exp = f"*{exp}"

    # Fast path: a plain substring / prefix / suffix / equality needs no regex.
    core = exp.strip("*")
    lead, trail = exp.startswith("*"), exp.endswith("*")
    if not _has_wildcard(core) and "\\" not in core:
        a, c = (text, core) if cased else (text.casefold(), core.casefold())
        if lead and trail:
            return c in a
        if lead:
            return a.endswith(c)
        if trail:
            return a.startswith(c)
        return a == c

    flags = regex.DOTALL | (0 if cased else regex.IGNORECASE)
    try:
        return regex.match(_wildcard_regex(exp), text, flags=flags,
                           timeout=dl.remaining()) is not None
    except TimeoutError as e:
        raise SigmaEvalTimeout(str(e)) from e


def _match_field(event: dict, key: str, expected: Any, dl: _Deadline) -> bool:
    dl.remaining()  # budget covers the non-regex fast paths too
    fld, mods = _split_key(key)
    present = fld in event and event[fld] not in (None, "", [])
    if "exists" in mods:
        return present is bool(expected)
    actual = event.get(fld)
    values = expected if isinstance(expected, list) else [expected]
    actuals = actual if isinstance(actual, list) else [actual]
    if not present and not any(v is None for v in values):
        return False

    def one(v: Any) -> bool:
        return any(_match_value(a, v, mods, dl) for a in actuals)

    if "all" in mods:
        return all(one(v) for v in values)
    return any(one(v) for v in values)


def _match_search(event: dict, value: Any, dl: _Deadline) -> bool:
    if isinstance(value, dict):
        return all(_match_field(event, k, v, dl) for k, v in value.items())
    if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
        return any(_match_search(event, v, dl) for v in value)
    # Keywords: free-text search in the message.
    dl.remaining()
    keywords = value if isinstance(value, list) else [value]
    message = event.get("message") or ""
    return any(_match_value(message, kw, ["contains"], dl) for kw in keywords)


def _eval_node(node, results: dict) -> bool:
    kind = node[0]
    if kind == "id":
        return results[node[1]]
    if kind == "not":
        return not _eval_node(node[1], results)
    if kind == "and":
        return _eval_node(node[1], results) and _eval_node(node[2], results)
    if kind == "or":
        return _eval_node(node[1], results) or _eval_node(node[2], results)
    if kind == "any":
        return any(results[n] for n in node[1])
    if kind == "all":
        return all(results[n] for n in node[1])
    raise SigmaRuleError(f"unknown condition node {kind}")


@dataclass
class SigmaMatch:
    matched: bool
    selections: list[str] = field(default_factory=list)


def match_rule(rule: dict, event: dict, timeout_s: float | None = None) -> SigmaMatch:
    """Return whether `rule` matches `event`, and which search identifiers hit.

    Raises SigmaRuleError for a malformed rule and SigmaEvalTimeout if the
    evaluation exceeds its budget; callers treat both as an evaluation error.
    """
    detection = rule.get("detection") or {}
    searches = {k: v for k, v in detection.items() if k != "condition"}
    dl = _Deadline(timeout_s if timeout_s is not None else _eval_timeout_s())
    results = {name: _match_search(event, value, dl) for name, value in searches.items()}
    condition = detection.get("condition")
    conditions = condition if isinstance(condition, list) else [condition]
    matched = any(
        _eval_node(_Parser(_tokenize(c), set(searches)).parse(), results)
        for c in conditions
    )
    return SigmaMatch(matched=matched,
                      selections=sorted(n for n, hit in results.items() if hit) if matched else [])


def policy_event(text: str, context: dict | None, stage: str) -> dict:
    """Build the flat event a Sigma policy matches against."""
    context = context or {}
    tool_input = context.get("tool_input")
    if tool_input is not None and not isinstance(tool_input, str):
        try:
            import json
            tool_input = json.dumps(tool_input, default=str)
        except Exception:
            tool_input = str(tool_input)
    return {
        "message": text or "",
        "stage": stage,
        "user_role": context.get("user_role"),
        "session_id": context.get("session_id"),
        "agent_id": context.get("agent_id") or context.get("agent_key"),
        "tool_name": context.get("tool_name"),
        "tool_input": tool_input,
    }
