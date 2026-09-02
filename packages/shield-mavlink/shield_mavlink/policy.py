"""Deterministic policy evaluation, on the aircraft, with no model and no network.

The six rule families `storage.agentic_control_plane.evaluate_parameter_policy`
defines, executed locally. Set membership, numeric comparison, presence, and
shape: everything expressible without judgement, which is exactly the set that
survives loss of link.

`tests/test_mavlink_policy_parity.py` runs this and the server's evaluator over
the same policies and inputs and requires identical verdicts. That test is not
optional decoration. A local evaluator that drifts from the server is worse than
no local evaluator, because both sides go on believing they agree while the
aircraft quietly enforces something operations never wrote.

Judged rules are absent here and are not approximated. A keyword list standing
in for "is this prompt injection" is how a deterministic engine starts silently
answering questions it cannot answer. Where judgement is required and no model
is reachable, the action is refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    rule: str = ""          # which family refused
    field: str = ""
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return not self.allowed


ALLOWED = Verdict(True, reason="within policy")


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


class LocalPolicy:
    """A verified bundle's policy, ready to decide.

    Construct from the dict `bundle.verify_bundle` returned, never from a file
    read directly: the point of the signature is that unverified policy is not
    used, and a constructor that accepts a path would make bypassing it easy.
    """

    def __init__(self, policy: dict[str, Any]):
        self.parameter_policies: dict[str, Any] = policy.get("parameter_policies", {})
        self.held_tools: set[str] = {
            t for rule in (policy.get("approvals", {}) or {}).get("rules", [])
            for t in (rule.get("tool_names") or [])
        }
        # Compile once. An uncompiled pattern per call is the difference between
        # microseconds and milliseconds, and a malformed one should surface at
        # load rather than on the apron.
        self._rx: dict[str, Optional[re.Pattern]] = {}
        for pol in self.parameter_policies.values():
            for pattern in (pol.get("regex_rules") or {}).values():
                if pattern not in self._rx:
                    try:
                        self._rx[pattern] = re.compile(pattern)
                    except re.error:
                        self._rx[pattern] = None

    def __len__(self) -> int:
        return len(self.parameter_policies)

    def requires_human(self, tool: str) -> bool:
        """Held actions need an approver, who may not be reachable.

        Offline this is a refusal rather than a queue: an aircraft that cannot
        ask does not get to assume the answer would have been yes.
        """
        return tool in self.held_tools

    def check(self, tool: str, params: dict[str, Any]) -> Verdict:
        policy = self.parameter_policies.get(tool)
        if policy is None:
            # Fail closed. An unrecognised command on an aircraft is not an
            # implicitly permitted one.
            return Verdict(False, "unknown_tool", "",
                           f"no policy for '{tool}'; refusing rather than assuming")

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
                               f"{field}={value!r} is not permitted")

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
                return Verdict(False, "min", field, f"{field}={numeric:g} is below {lo}")
            if hi is not None and numeric > float(hi):
                return Verdict(False, "max", field, f"{field}={numeric:g} exceeds {hi}")

        for field, pattern in (policy.get("regex_rules") or {}).items():
            value = _nested_get(params, field)
            if value is None:
                continue
            rx = self._rx.get(pattern)
            if rx is None or not rx.fullmatch(str(value)):
                return Verdict(False, "regex", field, f"'{field}' has the wrong shape")

        for field, max_len in (policy.get("max_string_lengths") or {}).items():
            value = _nested_get(params, field)
            if value is not None and len(str(value)) > int(max_len):
                return Verdict(False, "max_length", field,
                               f"'{field}' is longer than {max_len}")

        return ALLOWED
