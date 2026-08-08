#!/usr/bin/env python3
"""Delegation chains: a proven parent, and a wall the chain cannot climb past.

Runs the real path in-process. Shield mints agent tokens, verifies them, and
decides whether a child may be minted — this drives those functions directly
rather than a stub, so what you see is what a deployment does.

    python examples/langchain/delegation_chain_demo.py

Why in-process rather than against a deployed Shield: the decision lives in
core/agent_tokens.py and api/routes_agent_auth.py, and the interesting part is
the refusal. Pointing this at a remote data plane would prove nothing that the
local functions do not, and would need an admin key to mint with.

What it shows, in order:

  1. Default: parent_agent_id is whatever the caller typed. Shield signs it.
  2. Proof required: the typed value is ignored; the parent comes from a
     verified token.
  3. A parent token from another tenant is refused.
  4. Depth limit: the chain stops climbing.

See docs/spec-delegation-chain-depth.md and docs/agent-governance.md.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from core.agent_tokens import (  # noqa: E402
    decode_claims_unverified, mint_agent_token, verify_agent_token)

G, R, Y, B, DIM, Z = ("\033[32m", "\033[31m", "\033[33m", "\033[1m",
                      "\033[2m", "\033[0m")

TENANT = "acme"


def _mint(agent_id, *, parent_agent_id=None, delegation_depth=0, tenant=TENANT):
    return mint_agent_token(
        user_sub="alice", agent_id=agent_id, agent_instance_id=f"{agent_id}-1",
        tenant_id=tenant, build_hash="b1", model_version="m1",
        session_id="s1", parent_agent_id=parent_agent_id,
        delegation_depth=delegation_depth, ttl_seconds=300)


def _resolve(*, tenant_id, body_parent_agent_id=None, parent_agent_token=None):
    """The same helper both mint endpoints call."""
    from api.routes_agent_auth import _resolve_parent
    return _resolve_parent(tenant_id=tenant_id,
                           body_parent_agent_id=body_parent_agent_id,
                           parent_agent_token=parent_agent_token)


def header(n, text):
    print(f"\n{B}{n}. {text}{Z}")


def main():
    os.environ.pop("SHIELD_DELEGATION_PARENT_PROOF", None)
    os.environ.pop("SHIELD_MAX_DELEGATION_DEPTH", None)

    print(f"{B}Delegation chains — what is proven, and what is merely typed{Z}")

    # ── 1 ────────────────────────────────────────────────────────────────
    header(1, "Default: the parent is whatever the caller typed")
    parent_id, depth = _resolve(
        tenant_id=TENANT, body_parent_agent_id="finance-approver-bot")
    print(f"   caller claimed parent {DIM}finance-approver-bot{Z}")
    print(f"   {R}recorded parent{Z}  {parent_id}   depth {depth}")
    print(f"   {DIM}Nothing verified that this agent exists or delegated "
          f"anything.{Z}")

    # ── 2 ────────────────────────────────────────────────────────────────
    os.environ["SHIELD_DELEGATION_PARENT_PROOF"] = "required"
    header(2, "Proof required: the typed value is ignored")

    root = _mint("orchestrator")
    print(f"   minted root token for {DIM}orchestrator{Z} (depth 0)")

    parent_id, depth = _resolve(
        tenant_id=TENANT,
        body_parent_agent_id="finance-approver-bot",   # a lie
        parent_agent_token=root)                        # the truth
    print(f"   caller claimed parent {DIM}finance-approver-bot{Z}")
    print(f"   {G}recorded parent{Z}  {parent_id}   depth {depth}")
    print(f"   {DIM}The token wins. The claim is discarded, not honoured.{Z}")

    # ── 3 ────────────────────────────────────────────────────────────────
    header(3, "A valid token from another tenant is still refused")
    foreign = _mint("orchestrator", tenant="other-corp")
    try:
        _resolve(tenant_id=TENANT, parent_agent_token=foreign)
        print(f"   {R}ACCEPTED — this is a cross-tenant hole{Z}")
    except Exception as e:
        detail = getattr(e, "detail", str(e))
        print(f"   {G}refused{Z}  {detail}")
        print(f"   {DIM}The token verifies fine. It just is not this "
              f"tenant's.{Z}")

    # ── 4 ────────────────────────────────────────────────────────────────
    os.environ["SHIELD_MAX_DELEGATION_DEPTH"] = "1"
    header(4, "Depth limit 1: one hop, then a wall")

    token, agent = root, "orchestrator"
    for hop in range(1, 4):
        child = f"worker-{hop}"
        try:
            parent_id, depth = _resolve(tenant_id=TENANT,
                                        parent_agent_token=token)
        except Exception as e:
            detail = getattr(e, "detail", str(e))
            print(f"   hop {hop}: {G}refused{Z}  {detail}")
            break
        token = _mint(child, parent_agent_id=parent_id,
                      delegation_depth=depth)
        agent = child
        print(f"   hop {hop}: {G}minted{Z} {child} "
              f"{DIM}(parent {parent_id}, depth {depth}){Z}")

    # ── 5 ────────────────────────────────────────────────────────────────
    header(5, "Lowering the ceiling invalidates tokens already issued")
    deep = _mint("deep-worker", parent_agent_id="orchestrator",
                 delegation_depth=5)
    print(f"   minted a depth-5 token {DIM}(claims: "
          f"{decode_claims_unverified(deep).get('delegation_depth')}){Z}")
    try:
        verify_agent_token(deep)
        print(f"   {R}still verifies{Z}")
    except Exception as e:
        print(f"   {G}refused at verification{Z}  {e}")
        print(f"   {DIM}Checked at verify as well as at mint, so a lowered "
              f"limit applies now — not after every token expires.{Z}")

    print(f"\n{DIM}Docs: docs/agent-governance.md#4-delegation-chains{Z}\n")


if __name__ == "__main__":
    main()
