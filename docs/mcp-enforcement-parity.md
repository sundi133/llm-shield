---
title: MCP enforcement parity
layout: default
nav_order: 35
permalink: /mcp-enforcement-parity/
description: The MCP gateway now enforces the same guard set and control plane as the REST tool path. What changed, how to roll back, and how to size the impact first.
---

# MCP enforcement parity
{: .no_toc }

The MCP gateway enforced less than `/v1/shield/tool/check`. It now enforces the
same. This page is the migration note.
{: .fs-6 .fw-300 }

---

## What was wrong

Two ingresses, two levels of enforcement:

| | REST `/v1/shield/tool/check` | MCP gateway (before) |
| --- | --- | --- |
| guard chain | 7 guards | **4** |
| circuit breaker | yes | no |
| parameter policies | yes | no |
| workflow constraints | yes | no |
| approval rules | yes | **no** |
| tenant config applied | yes | **no** |
| decision audited | yes | **no** |

A tool with an approval rule blocked over REST and **executed unapproved**
through the gateway. A tenant's own `tool_allowlist` settings and `policy_mode`
were silently ignored there, so a tenant in `monitor` could take hard blocks.
Gateway denials left no forensic record at all.

## What changed

| variable | old default | new default |
| --- | --- | --- |
| `SHIELD_MCP_TOOL_PARITY` | `0` | **`1`** |
| `SHIELD_MCP_CONTROL_PLANE` | (did not exist) | **`enforce`** |

The gateway now runs the same guard set as the REST path, plus the control
plane, and its decisions are written to the decision audit with the failing
guardrail and the role source.

`enforce_tool_call` also loads tenant config when the caller did not supply it.
Without that, turning enforcement on would apply the *wrong* policy — defaults
instead of the tenant's — which is worse than applying none.

## This will deny calls that previously succeeded

That is the point: those calls were escaping the control plane. But it is a
behaviour change on upgrade, with no monitor phase unless you ask for one.

**Size the impact before committing.** Set:

```
SHIELD_MCP_CONTROL_PLANE=monitor
```

The control plane then evaluates every check and records what it *would* have
denied — audit entries read `[monitor] would block: ...` — while denying
nothing. Run that for a release, read the entries, then remove the variable to
return to `enforce`.

A high count is not a regression. It is the gap this closes, measured.

## Rolling back

Both escape hatches are supported and tested:

```
SHIELD_MCP_TOOL_PARITY=0        # historical 4-guard chain
SHIELD_MCP_CONTROL_PLANE=off    # no control plane on the gateway
```

`tests/test_mcp_parity_off_is_frozen.py` pins the off path so it keeps behaving
exactly as it did.

## One asymmetry, on purpose

An approval rule **denies** on the MCP path rather than prompting. REST can
satisfy an approval with a signed grant; MCP has no channel to present one, so
it cannot be approved there. Denying is the only safe reading of "this tool
requires human approval" — the alternative is what shipped before, where it ran
unapproved.

Route tools that need approval through the REST tool endpoint.

## What is still not at parity

Being explicit, because "same enforcement everywhere" should not carry an
unstated asterisk:

- **`cert_identity`** is not in the MCP chain even with parity on.
- **Scoped execution grants** — REST validates `execution_grant_id`; the MCP
  call has no field for one.
- **Agent anti-spoof** — REST cross-checks the `X-Agent-Key` header against the
  body's `agent_key`. No MCP equivalent.

A test pins the REST and MCP guard sets as identical, so the first of these
surfaces as a failure if cert identity is enabled rather than drifting quietly.
