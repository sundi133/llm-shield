---
title: Shadow mode and the shadow report
layout: default
nav_order: 77
permalink: /shadow-mode/
description: Run Votal Shield in shadow mode (monitor) so it checks every request but blocks nothing, then read the shadow report to see what it would have stopped before you switch to enforce.
---

# Shadow mode and the shadow report
{: .no_toc }

Run Shield on live traffic without blocking anything, see exactly what it
would have stopped, then switch to enforce when you are ready.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## What shadow mode does

Shadow mode is the `monitor` value of your workspace's enforcement mode.

- Every guardrail still runs on every request.
- When a guardrail would block, Shield lets the request through and records it
  as a **would-block** instead.
- `/guardrails/input` and `/guardrails/file` answer `"action": "monitor"`,
  `"safe": true` and a `would_block` list naming the guardrails that would
  have blocked, so your application lets the request through.

The other mode, `enforce`, blocks as configured. A new workspace starts in
enforce unless your Shield administrator chose otherwise.

### What it covers

Shadow mode applies to `/guardrails/input`, `/guardrails/file`, tool and MCP
calls, the gateway, the OpenAI-compatible proxy, agent chat, LiteLLM, and
coding-agent prompts.

These still block in shadow mode:

- **Output checks** on `/guardrails/output`.
- **Kill-switch and disabled-agent blocks.** An operator turned them off on
  purpose, so they always apply. They are not counted as would-blocks.

## Turn shadow mode on

Switching to monitor needs a reason, because blocks stop being enforced. The
change is audited with who made it and why.

With an admin-scoped API key for your workspace:

```bash
curl -s -X PUT https://YOUR-SHIELD-HOST/v1/tenant/me/policy-mode \
  -H "X-API-Key: $SHIELD_KEY" -H "Content-Type: application/json" \
  -d '{"mode": "monitor", "reason": "Two-week shadow run before go-live"}'
```

A Shield platform administrator can also set it for any workspace:

```bash
curl -s -X PUT https://YOUR-SHIELD-HOST/v1/admin/tenants/YOUR-TENANT/policy-mode \
  -H "X-Admin-Key: $SHIELD_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"mode": "monitor"}'
```

The new mode reaches every Shield server within about 2 minutes (the response
says exactly how long, in `takes_effect_within_seconds`).

Other ways a workspace lands in shadow mode:

- Applying a policy template (`POST /v1/admin/tenants/{id}/apply-template`)
  always starts it in monitor.
- Self-serve trials start in monitor when the operator sets
  `SHIELD_SIGNUP_TRIAL_MODE=monitor` or picks it under **Sign-ups** in the admin
  console. See [Sign up and get an API key](/self-serve-signup/).

Check the current mode at any time:

```bash
curl -s https://YOUR-SHIELD-HOST/v1/tenant/me/policy-mode -H "X-API-Key: $SHIELD_KEY"
```

## Read the shadow report

In the portal, open **Board Report**. When your workspace is in shadow mode the
**Shadow report** section is at the top. It shows:

- **The headline:** how many requests Shield would have stopped, out of how
  many it checked, and the rate.
- **Top guardrails:** which guardrails found the most.
- **Daily:** would-blocks (blue) and real blocks (red) for each day.
- **By team:** would-blocked requests per team, if you use
  [team policies](/team-policies/).
- **Latest would-blocks:** the 20 most recent, with time, guardrails, team,
  agent, source and the guardrail's reason.

Pick **Last 7 days** or **Last 30 days**, and a team if you have teams.

**Prompt text is never included in the report**, so a printed copy cannot leak
the data that tripped a guardrail. To review a specific request, open
**Telemetry**, set **Status** to **Would block (monitor)**, and find it there.

### Print it or save it as PDF

Click **Print / Save as PDF**. Only the report prints, with a header naming
your workspace, the range and when it was generated. Choose **Save as PDF** in
your browser's print dialog to share it with your security leadership.

### How to read the numbers

- **Requests and findings are different.** One request can trip several
  guardrails. The headline, the rate and **By team** count requests. The
  guardrail totals ("findings") count each guardrail that would have blocked.
- **Filtered by team:** every number then comes from the request log, because
  the per-guardrail counters do not record teams.
- **Very busy workspaces:** the request-based numbers use the most recent 50,000
  requests in the range, and the report says so.
- **Before shadow reporting was installed**, would-blocks were counted as
  blocks. The report names the first day its split is exact, and earlier days
  may show would-blocks as blocked.
- Chat proxy and coding-agent decisions appear in **Latest would-blocks** and
  **By team**, but not in the guardrail totals.

### From the API

```bash
curl -s "https://YOUR-SHIELD-HOST/v1/tenant/me/shadow-report?days=30" \
  -H "X-API-Key: $SHIELD_KEY"
```

| Parameter | Values |
|---|---|
| `days` | 1 to 30 (default 30) |
| `team` | a team rule id, `global`, `unmatched`, or `(none)` for requests with no team |

Main fields in the response:

| Field | Meaning |
|---|---|
| `policy_mode` | `monitor` or `enforce`, now |
| `would_block_requests` | requests with at least one would-block |
| `checked_total` | requests checked in the range |
| `would_block_rate_pct` | `would_block_requests` as a share of `checked_total` |
| `would_block_total` | guardrail findings that would have blocked |
| `blocked_total` | guardrail findings that were really blocked |
| `by_guardrail`, `daily`, `by_team`, `examples` | the breakdowns shown in the portal |
| `exact_since` | first day would-blocks were counted apart from blocks |
| `sampled` | `true` when only the most recent 50,000 requests were read |
| `degraded` | `true` when the data store was unreachable; the numbers are then empty |
| `not_covered` | what shadow mode does not cover, as above |

A key for one workspace only ever sees that workspace's report.

## Switch to enforce

When the report shows Shield stops what you expect and nothing it should not:

- In the portal, click **Switch to enforce** in the Shadow report section and
  confirm, or
- call the API:

```bash
curl -s -X PUT https://YOUR-SHIELD-HOST/v1/tenant/me/policy-mode \
  -H "X-API-Key: $SHIELD_KEY" -H "Content-Type: application/json" \
  -d '{"mode": "enforce"}'
```

Enforce needs no reason. Blocks apply within about 2 minutes. The report stays
available afterwards, at the bottom of **Board Report**, for the days you ran in
shadow mode.

If the button says the mode is managed by your administrator, your Shield
operator has turned self-service off; ask them to switch it.

## For operators

| Setting | Default | Effect |
|---|---|---|
| `SHIELD_METRICS_SPLIT_WOULD_BLOCK` | on | Counts would-blocks apart from blocks. `off` restores the old counting, where would-blocks were added to `blocked`. |
| `SHIELD_TENANT_POLICY_MODE_SELF_SERVICE` | on | Lets a workspace change its own mode. `off` keeps it admin-only. |
| `SHIELD_SIGNUP_TRIAL_MODE` | `enforce` | The mode new self-serve trials start in. |
| `SHIELD_REGISTRY_WRITE_SCOPE` | off | Under `enforce`, only admin-scoped keys may change the mode. |

**Upgrade note.** After this release, a workspace in shadow mode sees a lower
**Blocked** number on the Board Report: would-blocks used to be counted as
blocks and now have their own count. Workspaces in enforce see no change. To
keep the old numbers, set `SHIELD_METRICS_SPLIT_WOULD_BLOCK=off` on the
guardrail servers and the admin portal.
