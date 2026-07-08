"""One-shot: register this server's agent + role->tool policy with Votal Shield.

Use instead of REGISTER_ON_BOOT when you want to control the policy explicitly
(e.g. from CI/CD) rather than have the server self-register on start.

    export SHIELD_URL=https://<your-shield-host>
    export SHIELD_TENANT_KEY=sk-...
    python register.py
"""

import os
import sys

from server import AGENT_ID, ROLE_PERMISSIONS, TOOLS  # reuse the single source of truth
from shield_guard import register_agent


def main() -> int:
    base_url = os.environ.get("SHIELD_URL", "").rstrip("/")
    tenant_key = os.environ.get("SHIELD_TENANT_KEY", "")
    if not base_url or not tenant_key:
        print("Set SHIELD_URL and SHIELD_TENANT_KEY", file=sys.stderr)
        return 2
    resp = register_agent(
        base_url=base_url,
        tenant_key=tenant_key,
        agent_id=AGENT_ID,
        tools=TOOLS,
        role_permissions=ROLE_PERMISSIONS,
        auth_token=os.environ.get("RUNPOD_TOKEN", ""),
    )
    print(f"Registered {AGENT_ID!r}: {resp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
