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

import hashlib
import json
import os
import threading
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Union

import regex
import yaml

#: Largest rule text accepted, in bytes.
MAX_RULE_BYTES = 64 * 1024

#: The fields a Shield policy event carries. A rule may only use these (after
#: alias translation); anything else could never match, so writes reject it.
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
# Field compatibility and translation
# ---------------------------------------------------------------------------

#: Field names common in other schemas -> the Shield field they mean.
#: Matched case-insensitively. An explicit field_map on import wins over these.
FIELD_ALIASES = {
    **{k: "message" for k in ("prompt", "input", "user_input", "text", "content", "query",
                              "output", "response", "completion", "message.content")},
    **{k: "user_role" for k in ("role", "user.role")},
    **{k: "agent_id" for k in ("agent", "agent_name", "agent.id", "agent.name", "agent_key")},
    **{k: "tool_name" for k in ("tool", "tool.name", "tool_call.name", "function", "function_name")},
    **{k: "tool_input" for k in ("tool_args", "tool_arguments", "arguments", "tool.input",
                                 "tool_call.arguments", "params", "parameters")},
    **{k: "session_id" for k in ("session", "session.id", "conversation_id")},
}


def _field_maps(value: Any) -> Iterable[dict]:
    if isinstance(value, dict):
        yield value
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, dict):
                yield v


def referenced_fields(rule: dict) -> set[str]:
    """Every field a rule's detection reads (keyword searches read `message`)."""
    out: set[str] = set()
    for name, value in (rule.get("detection") or {}).items():
        if name == "condition":
            continue
        for m in _field_maps(value):
            out.update(_split_key(key)[0] for key in m)
    return out


def unknown_fields(rule: dict) -> list[str]:
    return sorted(f for f in referenced_fields(rule) if f not in POLICY_FIELDS)


def check_fields(rule: dict) -> None:
    """Reject a rule that reads fields Shield never provides: it could never match."""
    unknown = unknown_fields(rule)
    if unknown:
        raise SigmaRuleError(
            f"rule uses fields Shield does not provide: {unknown}. "
            f"Shield fields: {list(POLICY_FIELDS)}. Map them with field_map on "
            "import, or rewrite the rule (a rule for another log source, e.g. "
            "Windows process logs, belongs in your SIEM)."
        )


def translate_fields(rule: dict, field_map: Optional[dict] = None) -> dict:
    """Return a copy of `rule` with field names translated to Shield's.

    `field_map` (external name -> Shield field) wins over FIELD_ALIASES. Two
    fields in one selection that land on the same Shield field and modifiers
    are an error rather than one silently overwriting the other.
    """
    import copy

    explicit: dict[str, str] = {}
    for k, v in (field_map or {}).items():
        if v not in POLICY_FIELDS:
            raise SigmaRuleError(
                f"field_map target '{v}' is not a Shield field; use one of {list(POLICY_FIELDS)}")
        explicit[str(k)] = v

    def target(fld: str) -> str:
        if fld in explicit:
            return explicit[fld]
        if fld in POLICY_FIELDS:
            return fld
        return FIELD_ALIASES.get(fld.lower(), fld)

    def translate_map(m: dict, name: str) -> dict:
        out: dict = {}
        for key, val in m.items():
            parts = str(key).split("|")
            new_key = "|".join([target(parts[0])] + parts[1:])
            if new_key in out:
                raise SigmaRuleError(
                    f"detection '{name}': two fields map to '{new_key}'; put them in "
                    "separate selections")
            out[new_key] = val
        return out

    new = copy.deepcopy(rule)
    detection = new.get("detection")
    if isinstance(detection, dict):
        for name, value in list(detection.items()):
            if name == "condition":
                continue
            if isinstance(value, dict):
                detection[name] = translate_map(value, name)
            elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
                detection[name] = [translate_map(v, name) for v in value]
    return new


# ---------------------------------------------------------------------------
# Normalization (evasion resistance)
# ---------------------------------------------------------------------------

_FORMAT_CHARS = regex.compile(r"\p{Cf}+")


def normalization_enabled() -> bool:
    """SHIELD_SIGMA_NORMALIZE=0 restores raw-text matching (escape hatch)."""
    return os.environ.get("SHIELD_SIGMA_NORMALIZE", "1").strip().lower() not in ("0", "false", "off", "no")


def normalize_text(text: str) -> str:
    """NFKC (fullwidth/compatibility forms -> plain) and drop invisible format
    characters (zero-width space/joiners, word joiner, BOM, soft hyphen).
    Cross-script look-alikes (Cyrillic vs Latin) are NOT mapped by NFKC."""
    return _FORMAT_CHARS.sub("", unicodedata.normalize("NFKC", text))


# ---------------------------------------------------------------------------
# Compiled matching
# ---------------------------------------------------------------------------

def _eval_timeout_s() -> float:
    try:
        return max(1, int(os.environ.get("SHIELD_SIGMA_EVAL_TIMEOUT_MS", "250"))) / 1000.0
    except (TypeError, ValueError):
        return 0.25


def _stage_budget_s() -> float:
    try:
        return max(1, int(os.environ.get("SHIELD_SIGMA_STAGE_BUDGET_MS", "500"))) / 1000.0
    except (TypeError, ValueError):
        return 0.5


def prefilter_enabled() -> bool:
    return os.environ.get("SHIELD_SIGMA_PREFILTER", "1").strip().lower() not in ("0", "false", "off", "no")


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


def _literal_pieces(value: str) -> list[str]:
    """The wildcard-free runs of a Sigma wildcard string (escapes honoured)."""
    pieces, cur, i = [], [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            cur.append(value[i + 1])
            i += 2
            continue
        if ch in "*?":
            if cur:
                pieces.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        pieces.append("".join(cur))
    return pieces


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _folded(text: str, cache: dict) -> str:
    f = cache.get(text)
    if f is None:
        f = cache[text] = text.casefold()
    return f


class _ValueMatcher:
    """One rule value, compiled. `necessary` is a casefolded substring the
    (casefolded) text must contain for a match, or None when unknown."""

    __slots__ = ("kind", "pattern", "literal", "mode", "cased", "necessary")

    def __init__(self, kind, pattern=None, literal=None, mode=None, cased=False, necessary=None):
        self.kind, self.pattern, self.literal = kind, pattern, literal
        self.mode, self.cased, self.necessary = mode, cased, necessary

    def match(self, actual: Any, dl: _Deadline, cache: dict) -> bool:
        text = actual if isinstance(actual, str) else str(actual)
        if self.kind == "literal":
            a = text if self.cased else _folded(text, cache)
            c = self.literal
            if self.mode == "contains":
                return c in a
            if self.mode == "endswith":
                return a.endswith(c)
            if self.mode == "startswith":
                return a.startswith(c)
            return a == c
        try:
            if self.kind == "re":
                return self.pattern.search(text, timeout=dl.remaining()) is not None
            return self.pattern.match(text, timeout=dl.remaining()) is not None
        except TimeoutError as e:
            raise SigmaEvalTimeout(str(e)) from e


def _compile_value(expected: Any, mods: list[str]) -> Optional[_ValueMatcher]:
    if expected is None:
        return None  # the Sigma `null` value: handled at field level
    exp = str(expected)
    if "re" in mods:
        flags = 0
        if "i" in mods:
            flags |= regex.IGNORECASE
        if "m" in mods:
            flags |= regex.MULTILINE
        if "s" in mods:
            flags |= regex.DOTALL
        return _ValueMatcher("re", pattern=regex.compile(exp, flags))

    cased = "cased" in mods
    if "contains" in mods:
        exp = f"*{exp}*"
    elif "startswith" in mods:
        exp = f"{exp}*"
    elif "endswith" in mods:
        exp = f"*{exp}"

    core = exp.strip("*")
    lead, trail = exp.startswith("*"), exp.endswith("*")
    if not _has_wildcard(core) and "\\" not in core:
        mode = ("contains" if lead and trail else "endswith" if lead
                else "startswith" if trail else "equals")
        return _ValueMatcher("literal", literal=core if cased else core.casefold(), mode=mode,
                             cased=cased, necessary=core.casefold() or None)

    flags = regex.DOTALL | (0 if cased else regex.IGNORECASE)
    pieces = _literal_pieces(exp)
    longest = max(pieces, key=len).casefold() if pieces else None
    return _ValueMatcher("wild", pattern=regex.compile(_wildcard_regex(exp), flags),
                         necessary=longest or None)


class _FieldMatcher:
    __slots__ = ("fld", "exists", "all_mode", "values", "has_null", "necessary")

    def __init__(self, key: str, expected: Any):
        self.fld, mods = _split_key(key)
        self.exists = bool(expected) if "exists" in mods else None
        self.all_mode = "all" in mods
        raw = expected if isinstance(expected, list) else [expected]
        self.values = [] if self.exists is not None else [_compile_value(v, mods) for v in raw]
        self.has_null = any(v is None for v in self.values)
        self.necessary = self._necessary()

    def _necessary(self) -> Optional[frozenset]:
        # Only `message` is scanned by the prefilter, and only literal-bearing values count.
        if self.fld != "message" or self.exists is not None or self.has_null or not self.values:
            return None
        lits = [v.necessary for v in self.values]
        if any(lit is None for lit in lits):
            return None
        if self.all_mode:  # every value must match, so any one value's literal is necessary
            return frozenset([max(lits, key=len)])
        return frozenset(lits)

    def matches(self, event: dict, dl: _Deadline, cache: dict) -> bool:
        dl.remaining()  # the budget covers the non-regex fast paths too
        actual = event.get(self.fld)
        present = self.fld in event and actual not in (None, "", [])
        if self.exists is not None:
            return present is self.exists
        if not present and not self.has_null:
            return False
        actuals = actual if isinstance(actual, list) else [actual]

        def one(vm: Optional[_ValueMatcher]) -> bool:
            if vm is None:
                return any(a in (None, "", []) for a in actuals)
            return any(vm.match(a, dl, cache) for a in actuals)

        if self.all_mode:
            return all(one(v) for v in self.values)
        return any(one(v) for v in self.values)


class _SearchMatcher:
    __slots__ = ("maps", "keywords", "necessary")

    def __init__(self, value: Any):
        self.maps: Optional[list[list[_FieldMatcher]]] = None
        self.keywords: Optional[list[_ValueMatcher]] = None
        if isinstance(value, dict):
            self.maps = [[_FieldMatcher(k, v) for k, v in value.items()]]
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            self.maps = [[_FieldMatcher(k, v) for k, v in m.items()] for m in value]
        else:
            kws = value if isinstance(value, list) else [value]
            self.keywords = [_compile_value(kw, ["contains"]) for kw in kws]
        self.necessary = self._necessary()

    def _necessary(self) -> Optional[frozenset]:
        if self.keywords is not None:
            lits = [kw.necessary if kw is not None else None for kw in self.keywords]
            return None if any(lit is None for lit in lits) else frozenset(lits)
        union: set = set()
        for fields in self.maps:
            # A map is an AND: any one message field's literal set is necessary.
            found = next((f.necessary for f in fields if f.necessary is not None), None)
            if found is None:
                return None  # this alternative can match without a known literal
            union |= found
        return frozenset(union)

    def matches(self, event: dict, dl: _Deadline, cache: dict) -> bool:
        if self.keywords is not None:
            dl.remaining()
            message = event.get("message") or ""
            return any(kw is not None and kw.match(message, dl, cache) for kw in self.keywords)
        return any(all(f.matches(event, dl, cache) for f in fields) for fields in self.maps)


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


def _possible(node, possible: dict) -> bool:
    """Over-approximation of _eval_node: False only if the rule cannot match."""
    kind = node[0]
    if kind == "id":
        return possible[node[1]]
    if kind == "not":
        return True  # `not x` can be true whether or not x's literals are present
    if kind == "and":
        return _possible(node[1], possible) and _possible(node[2], possible)
    if kind == "or":
        return _possible(node[1], possible) or _possible(node[2], possible)
    if kind == "any":
        return any(possible[n] for n in node[1])
    if kind == "all":
        return all(possible[n] for n in node[1])
    return True


@dataclass
class SigmaMatch:
    matched: bool
    selections: list[str] = field(default_factory=list)


class CompiledRule:
    """A rule parsed once: condition ASTs, compiled values, prefilter literals."""

    __slots__ = ("searches", "conditions", "literals")

    def __init__(self, rule: dict):
        detection = rule.get("detection") or {}
        self.searches = {k: _SearchMatcher(v) for k, v in detection.items() if k != "condition"}
        condition = detection.get("condition")
        conditions = condition if isinstance(condition, list) else [condition]
        names = set(self.searches)
        self.conditions = tuple(_Parser(_tokenize(c), names).parse() for c in conditions)
        lits: set = set()
        for s in self.searches.values():
            if s.necessary:
                lits |= s.necessary
        self.literals = frozenset(lits)

    def could_match(self, present: Optional[set]) -> bool:
        if present is None:
            return True
        poss = {name: s.necessary is None or bool(s.necessary & present)
                for name, s in self.searches.items()}
        return any(_possible(c, poss) for c in self.conditions)

    def evaluate(self, event: dict, dl: _Deadline, cache: dict) -> SigmaMatch:
        results = {name: s.matches(event, dl, cache) for name, s in self.searches.items()}
        matched = any(_eval_node(c, results) for c in self.conditions)
        return SigmaMatch(matched=matched,
                          selections=sorted(n for n, hit in results.items() if hit) if matched else [])


_CACHE_MAX = 4096
_compiled: "OrderedDict[str, CompiledRule]" = OrderedDict()
_automata: "OrderedDict[frozenset, Any]" = OrderedDict()
_cache_lock = threading.Lock()


def rule_digest(rule: dict) -> str:
    """Content address of a rule, so an edit (even one that does not bump the
    policy version, e.g. via the raw JSON editor) never serves a stale compile."""
    blob = json.dumps(rule, sort_keys=True, default=str).encode()
    return hashlib.blake2b(blob, digest_size=16).hexdigest()


def compile_rule(rule: dict) -> CompiledRule:
    key = rule_digest(rule)
    with _cache_lock:
        cr = _compiled.get(key)
        if cr is not None:
            _compiled.move_to_end(key)
            return cr
    cr = CompiledRule(rule)
    with _cache_lock:
        _compiled[key] = cr
        while len(_compiled) > _CACHE_MAX:
            _compiled.popitem(last=False)
    return cr


def _present_literals(literals: frozenset, folded_message: str) -> Optional[set]:
    """One Aho-Corasick pass: which prefilter literals occur in the message.
    Returns None (no prefilter, evaluate everything) if pyahocorasick is absent."""
    if not literals:
        return set()
    try:
        import ahocorasick
    except ImportError:
        return None
    with _cache_lock:
        automaton = _automata.get(literals)
        if automaton is not None:
            _automata.move_to_end(literals)
    if automaton is None:
        automaton = ahocorasick.Automaton()
        for lit in literals:
            automaton.add_word(lit, lit)
        automaton.make_automaton()
        with _cache_lock:
            _automata[literals] = automaton
            while len(_automata) > 256:
                _automata.popitem(last=False)
    return {lit for _, lit in automaton.iter(folded_message)}


def match_rule(rule: dict, event: dict, timeout_s: float | None = None) -> SigmaMatch:
    """Return whether `rule` matches `event`, and which search identifiers hit.

    Raises SigmaRuleError for a malformed rule and SigmaEvalTimeout if the
    evaluation exceeds its budget; callers treat both as an evaluation error.
    """
    dl = _Deadline(timeout_s if timeout_s is not None else _eval_timeout_s())
    return compile_rule(rule).evaluate(event, dl, {})


@dataclass
class RuleOutcome:
    matched: bool = False
    selections: list[str] = field(default_factory=list)
    skipped: bool = False          # the prefilter proved the rule cannot match
    error: Optional[str] = None


def evaluate_rules(rules: list[dict], event: dict, *, rule_timeout_s: float | None = None,
                   stage_budget_s: float | None = None,
                   use_prefilter: bool | None = None) -> list[RuleOutcome]:
    """Evaluate many rules against one event in a single pass.

    Rules are compiled once (cached by content), the message is scanned once
    for every rule's literals, and only rules that could still match are fully
    evaluated. Each rule keeps its own time limit, and the whole pass has a
    budget; a rule that errors, times out or is not reached in budget gets an
    `error` (never a silent pass), which callers treat like any evaluation error.
    """
    per_rule = rule_timeout_s if rule_timeout_s is not None else _eval_timeout_s()
    stage_end = time.monotonic() + (stage_budget_s if stage_budget_s is not None else _stage_budget_s())
    compiled: list[Optional[CompiledRule]] = []
    outcomes: list[RuleOutcome] = []
    for rule in rules:
        try:
            compiled.append(compile_rule(rule))
            outcomes.append(RuleOutcome())
        except Exception as e:
            compiled.append(None)
            outcomes.append(RuleOutcome(error=f"invalid rule: {e}"))

    present: Optional[set] = None
    if (use_prefilter if use_prefilter is not None else prefilter_enabled()):
        message = event.get("message")
        if isinstance(message, str):
            literals = frozenset().union(*(c.literals for c in compiled if c is not None))
            present = _present_literals(literals, message.casefold())

    cache: dict = {}
    for i, cr in enumerate(compiled):
        if cr is None:
            continue
        if not cr.could_match(present):
            outcomes[i].skipped = True
            continue
        remaining = stage_end - time.monotonic()
        if remaining <= 0:
            outcomes[i].error = "Sigma stage time budget exhausted before this rule was evaluated"
            continue
        try:
            m = cr.evaluate(event, _Deadline(min(per_rule, remaining)), cache)
            outcomes[i].matched, outcomes[i].selections = m.matched, m.selections
        except Exception as e:
            outcomes[i].error = str(e)
    return outcomes


def policy_event(text: str, context: dict | None, stage: str, normalize: bool | None = None) -> dict:
    """Build the flat event a Sigma policy matches against.

    Free-text fields are normalized (NFKC, invisible format characters removed)
    unless SHIELD_SIGMA_NORMALIZE=0, so evasions like zero-width spaces or
    fullwidth digits do not slip past a rule.
    """
    context = context or {}
    tool_input = context.get("tool_input")
    if tool_input is not None and not isinstance(tool_input, str):
        try:
            # ensure_ascii=False: the default escapes every non-ASCII character
            # to a literal \uXXXX, which no rule (and no normalization) can see.
            tool_input = json.dumps(tool_input, default=str, ensure_ascii=False)
        except Exception:
            tool_input = str(tool_input)
    message = text or ""
    if normalize if normalize is not None else normalization_enabled():
        message = normalize_text(message)
        if isinstance(tool_input, str):
            tool_input = normalize_text(tool_input)
    return {
        "message": message,
        "stage": stage,
        "user_role": context.get("user_role"),
        "session_id": context.get("session_id"),
        "agent_id": context.get("agent_id") or context.get("agent_key"),
        "tool_name": context.get("tool_name"),
        "tool_input": tool_input,
    }
