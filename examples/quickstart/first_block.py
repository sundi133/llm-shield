"""Votal Shield — your first block, in one file.

Run a Shield locally, then run this script. In ~5 lines it:

  1. connects to Shield in sandbox mode (no API key to provision),
  2. mints capabilities for an agent (which role may call which tool),
  3. shows an allowed call and a role-blocked call — with the reason.

No GPU, no Redis, no cloud account required.

    # terminal 1 — start Shield
    pip install -r requirements.txt && python handler.py   # serves :8080

    # terminal 2 — see a block
    pip install votal      # or: PYTHONPATH=sdk python examples/quickstart/first_block.py
    python examples/quickstart/first_block.py
"""

import os
import sys

try:
    from votal import VotalShield
except ModuleNotFoundError:
    # Allow running straight from a checkout without `pip install votal`.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk"))
    from votal import VotalShield


def main() -> int:
    # 1. Connect — sandbox mode needs no API key and no tenant setup.
    #    Override the URL with SHIELD_URL=... if Shield runs elsewhere.
    shield = VotalShield.sandbox(
        agent_id="support-bot",
        user_role="support",
        shield_url=os.environ.get("SHIELD_URL"),
    )

    if not shield.health():
        print(f"✗ Shield is not reachable at {shield.shield_url}")
        print("  Start it first:  python handler.py   (serves http://localhost:8080)")
        print("  Or point elsewhere: VotalShield.sandbox(shield_url='https://...')")
        return 1

    # 2. Mint capabilities — which role may call which tool. Idempotent.
    shield.register_agent(
        tools=["get_balance", "transfer_funds"],
        role_permissions={
            "admin": ["get_balance", "transfer_funds"],
            "support": ["get_balance"],          # support may read, not move money
        },
        name="Support Bot",
    )

    # 3. Check tools per role — this is the per-action capability check.
    print(f"\nShield: {shield.shield_url}   agent: {shield.agent_id}\n")
    for role, tool in [
        ("support", "get_balance"),
        ("support", "transfer_funds"),   # <- should be BLOCKED
        ("admin", "transfer_funds"),
    ]:
        guard = shield.check_tool(tool, user_role=role)
        mark = "✓ allow" if guard.allowed else "✗ BLOCK"
        reason = f"  ({guard.reason})" if guard.reason else ""
        print(f"  {mark}  {role:8} → {tool}{reason}")

    print("\nThat ✗ BLOCK is Shield enforcing the capability you minted — "
          "no agent code changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
