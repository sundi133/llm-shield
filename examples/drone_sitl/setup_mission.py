"""Install the mission policy on your tenant. Run once before the demo.

The policy is the demo's whole enforcement surface: the flight script holds no
rules, so what this posts is what decides whether the aircraft flies.
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
    print("\nEvery flight action now needs Shield's authorization. Verify with:")
    print(f'  curl -s "{url}/v1/data-policies/global/policy" -H "X-API-Key: $SHIELD_TENANT_KEY"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
