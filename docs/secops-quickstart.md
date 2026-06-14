---
title: Security Operations Quickstart
layout: default
nav_order: 6
permalink: /secops-quickstart/
description: For security teams — observe agent activity first, rank risk, then enforce. No code required.
---

# Security operations quickstart
{: .no_toc }

You operate Shield from the portal — no code. The posture is **observe first**:
watch what your agents and tools actually do, see the dangerous calls ranked,
then turn on enforcement for what you don't like.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## The eight concepts you need

1. **Agent** — an AI system that acts by calling tools. Each has an identity.
2. **Tool** — one capability an agent can invoke (`get_account`, `wire_transfer`).
3. **Role (RBAC)** — the caller's role gates which tools it may use.
4. **Risk tier** — every tool call is auto-scored `low` / `medium` / `high` with
   no policy needed, so dangerous activity surfaces on day one.
5. **Policy mode** — `monitor` (dry run, blocks nothing, records what *would*
   block) or `enforce` (actually blocks). You move tools from one to the other.
6. **Kill switch** — disable a tool fleet-wide, instantly, one click.
7. **Shadow agent/tool** — something that called Shield without being registered;
   flagged for you to approve or block.
8. **Audit / SIEM** — every decision recorded and streamed to your SIEM.

Fuller definitions: the [glossary]({{ "/glossary/" | relative_url }}) (shared with
your developers).

---

## The lifecycle: template → monitor → review → enforce

This is the safe path to production. Nobody flips a new policy to "block" blind.

1. **Start from a template.** Pick your industry (healthcare/HIPAA,
   financial/PCI, general) instead of a blank policy.
2. **Run in monitor mode.** Shield evaluates everything and records a
   *would-block* list, but blocks nothing. Zero risk to live traffic.
3. **Review.** In the portal, look at what *would* have been blocked and the
   high-risk calls. Confirm the policy matches reality.
4. **Enforce.** Flip the tools you're confident about to enforce. Leave the rest
   in monitor. Repeat.

Details and the operator walkthrough: [policy lifecycle]({{ "/policy-lifecycle/" | relative_url }}).

> **Why this matters:** monitor mode is the single biggest trust-builder. You
> prove a policy is safe against real traffic *before* it can break anything.

---

## Reading a block

Every block answers four questions, in the audit row and the SIEM event:

- **Which agent** acted (`agent_key`) and as **which role**.
- **Which tool** it tried to call.
- **Which guardrail** stopped it and **why** (the reason message).
- **When** (`trace_id` + timestamp), correlatable across the whole request.

If a block looks wrong, the reason tells you exactly which rule to change — you
never have to guess.

---

## Tabletop: "an agent goes rogue"

Run this with your team to learn the incident path.

1. **Detect.** An agent starts calling a high-risk tool (e.g. `delete_records`)
   it shouldn't. You see it ranked **high** in the discovery / activity view, or
   get a webhook/SIEM alert.
2. **Contain.** One click: **kill switch** the tool (fleet-wide, instant) and/or
   **disable the agent**. Both are *administrative* — they enforce even if the
   tenant is still in monitor mode.
3. **Investigate.** Open the audit log for that `trace_id`. The **taint graph**
   traces the action back through the tool-call chain to the originating prompt
   — prompt → execution, end to end.
4. **Remediate.** Tighten the role's permissions or move the tool to enforce.
   Re-enable the agent when safe.

The point to internalize: **disable is real enforcement, not a label** — a
toggled-off agent cannot act through any path, and a kill-switched tool is dead
fleet-wide, immediately.

---

## Compliance

Shield's controls map to NIST AI RMF, OWASP LLM Top 10, and ISO 42001; the audit
trail and evidence pack support those frameworks. See the compliance mapping in
the docs for the control-by-control table.

---

## Where to next

- [Policy lifecycle]({{ "/policy-lifecycle/" | relative_url }}) — monitor → enforce in the portal
- [Glossary]({{ "/glossary/" | relative_url }}) — shared vocabulary with developers
- [Developer guide]({{ "/developer-guide-mcp/" | relative_url }}) — how your developers connect agents
