"""On-device deterministic policy evaluation, for when the link is gone.

A drone loses connectivity as a matter of course: BVLOS, urban canyon, a hill
between it and the ground station. An enforcement point that needs a network
round trip per command is not one an aircraft can rely on, so the rules that
must always hold are the ones expressible without a model:

    set membership      geofence, approved sinks, allowed roles
    comparison          altitude ceiling, speed, battery floor, time window
    presence            required and forbidden fields
    shape               anchored regex, string length

This module runs exactly those, from a policy bundle produced by Shield, cached
on the companion computer. It is NOT a second policy language: it is a faithful
local execution of `storage.agentic_control_plane.evaluate_parameter_policy`'s
deterministic half, and `tests/test_edge_policy_parity.py` fails if the two
disagree. That test is the point of the module. A local evaluator that drifts
from the server is worse than none, because both sides believe they agree.

What this deliberately CANNOT do, and must not pretend to:

    Judged rules stay on the server (or on a local model). Prompt injection in
    an OCR'd placard, mission-scope judgement, incoherent sensor narratives:
    none of these are set membership, and an offline aircraft cannot evaluate
    them. The honest posture is to refuse the actions that depend on judgement
    when judgement is unavailable, not to approximate it with keywords.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    rule: str = ""       # which family refused: allowed_values, max, regex...
    field: str = ""
    reason: str = ""


ALLOW = Verdict(True)


def _nested_get(params: dict[str, Any], path: str) -> Any:
    """Dotted-path lookup, matching the server's _nested_get."""
    cur: Any = params
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


class EdgePolicy:
    """A cached policy bundle, evaluated locally in microseconds.

    Lookup is by tool name, so the number of policies in the bundle does not
    affect the cost of a decision: only the called tool's rules are examined.
    A bundle with ten thousand entries decides as fast as one with ten.
    """

    def __init__(self, bundle: dict[str, Any]):
        self.parameter_policies: dict[str, Any] = bundle.get("parameter_policies", {})
        self.held_tools: set[str] = {
            t for rule in (bundle.get("approvals", {}) or {}).get("rules", [])
            for t in (rule.get("tool_names") or [])
        }
        # Compile once at load, not per call. An uncompiled regex in a hot loop
        # is the difference between microseconds and milliseconds.
        self._regex_cache: dict[str, re.Pattern] = {}
        for pol in self.parameter_policies.values():
            for pattern in (pol.get("regex_rules") or {}).values():
                if pattern not in self._regex_cache:
                    try:
                        self._regex_cache[pattern] = re.compile(pattern)
                    except re.error:
                        pass  # an invalid pattern refuses at evaluation time

    @classmethod
    def from_file(cls, path: str | Path) -> "EdgePolicy":
        return cls(json.loads(Path(path).read_text()))

    def __len__(self) -> int:
        return len(self.parameter_policies)

    def requires_human(self, tool: str) -> bool:
        """Held actions need an approver, who is unreachable with no link.

        Offline this is a refusal, not a queue. An aircraft that cannot ask
        does not get to assume the answer would have been yes.
        """
        return tool in self.held_tools

    def check(self, tool: str, params: dict[str, Any]) -> Verdict:
        policy = self.parameter_policies.get(tool)
        if policy is None:
            # No policy for this tool. Fail closed: an unknown command on an
            # aircraft is not an implicitly permitted one.
            return Verdict(False, "unknown_tool", "", f"no policy for '{tool}'")

        for field in policy.get("required_fields") or []:
            if _nested_get(params, field) in (None, "", []):
                return Verdict(False, "required", field, f"missing '{field}'")

        for field in policy.get("forbidden_fields") or []:
            if _nested_get(params, field) not in (None, "", []):
                return Verdict(False, "forbidden", field, f"'{field}' is forbidden")

        for field, values in (policy.get("allowed_values") or {}).items():
            value = _nested_get(params, field)
            if value is not None and value not in values:
                return Verdict(False, "allowed_values", field,
                               f"'{field}'={value!r} not permitted")

        for field, limits in (policy.get("numeric_limits") or {}).items():
            value = _nested_get(params, field)
            if value is None:
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return Verdict(False, "numeric", field, f"'{field}' must be numeric")
            lo, hi = limits.get("min"), limits.get("max")
            if lo is not None and numeric < float(lo):
                return Verdict(False, "min", field, f"{field}={numeric:g} below {lo}")
            if hi is not None and numeric > float(hi):
                return Verdict(False, "max", field, f"{field}={numeric:g} exceeds {hi}")

        for field, pattern in (policy.get("regex_rules") or {}).items():
            value = _nested_get(params, field)
            if value is None:
                continue
            rx = self._regex_cache.get(pattern)
            if rx is None or not rx.fullmatch(str(value)):
                return Verdict(False, "regex", field, f"'{field}' has the wrong shape")

        for field, max_len in (policy.get("max_string_lengths") or {}).items():
            value = _nested_get(params, field)
            if value is not None and len(str(value)) > int(max_len):
                return Verdict(False, "max_length", field,
                               f"'{field}' longer than {max_len}")

        return ALLOW
