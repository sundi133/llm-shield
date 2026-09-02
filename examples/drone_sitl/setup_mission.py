"""Install the mission policy and approval rule on your tenant. Run once.

Together these are the demo's whole enforcement surface: the flight script holds
no rules, so what this posts is what decides whether the aircraft flies.

Two different mechanisms, deliberately:

  the data policy   refuses actions outright (restricted zone, ceiling, energy,
                    injection, egress). Judged per call against the arguments.

  the approval rule holds an action for a human. Rules match on TOOL NAME, not
                    on argument values, which is why "over people" is its own
                    action rather than a flag on an ordinary waypoint.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

POLICY = Path(__file__).with_name("mission_policy.json")


def main() -> int:
    url = os.environ.get("SHIELD_URL", "").rstrip("/")
    key = os.environ.get("SHIELD_TENANT_KEY", "")
    if not url or not key:
        print("Set SHIELD_URL and SHIELD_TENANT_KEY first.", file=sys.stderr)
        return 2

    body = json.loads(POLICY.read_text())
    r = requests.post(
        f"{url}/v1/data-policies/global/policy",
        json=body,
        headers={"Content-Type": "application/json", "X-API-Key": key},
        timeout=30,
    )
    if not r.ok:
        print(f"Policy install failed: {r.status_code} {r.text[:300]}", file=sys.stderr)
        return 1

    rules = body["role_policies"][0]
    print(f"Mission policy installed: {len(rules['input_rules'])} input rules, "
          f"{len(rules['output_rules'])} output rules.")

    # Flight over a populated area needs a named human to say yes. Scoped to
    # this one action so ordinary waypoints are not queued behind a person.
    r = requests.put(
        f"{url}/v1/tenant/me/agentic/config",
        json={"approvals": {"enabled": True, "rules": [{
            "rule_id": "transit-over-people-requires-supervisor",
            "tool_names": ["transit_over_people"],
            "workflows": ["perimeter_inspection"],
            "min_approvals": 1,
            "request_ttl_seconds": 600,
            "single_use": True,
        }]}},
        headers={"Content-Type": "application/json", "X-API-Key": key},
        timeout=30,
    )
    if not r.ok:
        print(f"Approval rule install failed: {r.status_code} {r.text[:300]}",
              file=sys.stderr)
        return 1
    print("Approval rule installed: transit_over_people holds for 1 supervisor.")

    print("\nEvery flight action now needs Shield's authorization. Verify with:")
    print(f'  curl -s "{url}/v1/data-policies/global/policy" -H "X-API-Key: $SHIELD_TENANT_KEY"')
    print(f'  curl -s "{url}/v1/tenant/me/agentic/approvals" -H "X-API-Key: $SHIELD_TENANT_KEY"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
