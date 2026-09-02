---
title: AI DLP rollout runbook
layout: default
nav_order: 63
permalink: /swg-rollout-runbook/
description: A phased runbook for a security team introducing AI prompt inspection at the web gateway, from scoping and legal review through monitor, canary and fleet enforcement, with exit criteria at each phase.
---

# AI DLP rollout runbook

For the security team that owns the programme, rather than the engineer doing
the configuration. Each phase has an owner, an exit criterion, and the
decision it forces. Do not start the next phase until the current one exits.

Typical elapsed time is six to ten weeks, and almost none of that is
engineering. Phase 0 and Phase 2 are where it actually goes.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Phase 0. Scope and authorisation

**Owner:** security lead, with legal and HR. **Typical: 1 to 3 weeks.**

The engineering is the easy part. This phase is what actually gates the
programme, and starting Phase 1 before it exits is how a deployment gets
switched off after go-live.

1. **Decide what you are protecting against.** The realistic threat is an
   employee pasting something they should not while trying to do their job:
   a cost base, a customer list, unreleased financials, source code. It is not
   a determined insider. Say so explicitly, because it determines how much
   enforcement is proportionate.
2. **Confirm you already decrypt.** Run the pre-flight. If you run Zscaler,
   Netskope, Blue Coat, Cisco WSA, Forcepoint or Palo Alto, the traffic is
   already being inspected and no new interception point is needed.
3. **Legal and works council.** In the EU this is required, not advisory, and
   it takes longer than everything else combined. Bring the scope with you: a
   named list of AI destinations, and the fact that everything else is
   returned DIRECT and never decrypted.
4. **Decide the capture posture.** Metadata only, redacted content, or full
   content. Default to redacted. Decide who may see raw prompt text and under
   what approval.
5. **Name the exception path** before anyone is blocked. Who does a blocked
   employee contact, and who can grant an exception.

**Exit:** written authorisation, an agreed destination list, and a documented
exception path.

---

## Phase 1. Stand up inspection, inspect nothing

**Owner:** network or platform engineering. **Typical: 2 to 5 days.**

1. Deploy the adapter where the gateway can reach it with low latency.
2. Point the gateway's ICAP service at it, scoped to the AI destinations
   agreed in Phase 0.
3. Leave the policy empty. The adapter is deliberately inert with no rules:
   it forwards everything and blocks nothing.
4. Confirm the plumbing: `/healthz` reports the policy version and that the
   service is reachable, and prompts appear in Telemetry.

**Exit:** AI prompts visible in Telemetry, zero blocks, no user-visible
change. If anyone noticed, something is wrong.

---

## Phase 2. Monitor, and let the data write the policy

**Owner:** security operations. **Typical: 2 to 4 weeks.**

The phase people skip, and the one that decides whether this succeeds.

1. Run in `monitor` with rules in place. Every match is recorded as
   *would have blocked*, and nothing is stopped.
2. **Read what your staff actually send.** Most organisations are surprised
   here, in both directions: the leak they feared is rare, and a category they
   never considered is constant.
3. **Tune against real traffic.** Every false positive found now is free.
   The same one found in Phase 4 is a support ticket and a credibility cost.
4. Watch the ratio. If more than roughly 1 in 200 prompts would block, the
   policy is too broad, and enforcing it will train people to route around
   you.

**Exit:** two consecutive weeks where every *would have blocked* event is one
you are willing to defend to the employee it stops.

---

## Phase 3. Prepare the humans

**Owner:** security, with internal comms. **Typical: 1 week, overlapping.**

1. Tell people before you block them. A block that arrives unannounced is
   read as an outage, and the first response is to find a way around it.
2. Publish what is inspected and what is not. "Only these AI sites, nothing
   else" is a much better message than silence, and it is true.
3. Make sure the block message names the policy and gives a reference the
   help desk can look up.
4. Brief the help desk with the exception path from Phase 0.

**Exit:** announcement sent, help desk briefed.

---

## Phase 4. Canary enforcement

**Owner:** security operations. **Typical: 1 to 2 weeks.**

1. Switch a single group to `enforce`. Pick a team that will complain loudly
   and constructively: security itself, or a friendly engineering team.
2. Watch block volume daily and every exception request.
3. Have a rollback that takes minutes, and confirm it works before you need
   it. Reverting to `monitor` is a configuration change, not a redeploy.

**Exit:** a week with no unresolved exception and no rollback.

---

## Phase 5. Fleet enforcement

**Owner:** security operations plus endpoint management. **Typical: 1 to 2 weeks.**

1. Expand in rings: 5 percent, 25 percent, all. Pause on any spike in blocks
   or exception requests.
2. Push the endpoint configuration by MDM. See
   [swg-deployment](/swg-deployment/) for the per-browser settings, and do not
   skip Firefox or the QUIC policy.
3. Track coverage rather than assuming it: how many devices have the CA, the
   proxy configuration, and QUIC disabled.

**Exit:** enforcement on the whole fleet, with a coverage number you can show
an auditor.

---

## Phase 6. Operate

**Owner:** security operations, ongoing.

| Watch | Why |
|---|---|
| Policy version and rule count on `/healthz` | A policy that silently fails to load enforces nothing while looking healthy |
| The gateway's ICAP service status | A suspended service is silent from the adapter side, and fails closed for everyone |
| Block rate per week | A sudden rise is usually a policy edit, not a behaviour change |
| Exception requests | A recurring one is a policy bug, not a user problem |
| Coverage gaps | New devices, new browsers, people who moved teams |

Review the policy quarterly against what people are actually sending. AI usage
patterns move faster than most security policy, and a rule written for last
year's tools ages badly.

---

## The decisions this forces

Four things a security team has to decide, and they are all judgement rather
than configuration:

1. **Block or warn.** Blocking stops the leak and generates friction. Warning
   preserves goodwill and stops nothing. Most organisations should block a
   narrow, defensible set and warn on the rest.
2. **What a screening outage means.** Fail closed stops AI usage when the
   inspection service is down. Fail open keeps people working and stops
   inspecting. There is no correct answer, only an owned one.
3. **Who reads prompts.** Every prompt is an employee's work, and some of it
   will be personal. Decide the access rule before someone asks.
4. **What you tell people.** Announced inspection is a security control.
   Unannounced inspection is a trust problem that outlives the programme.

---

## What this does not do

Worth stating internally so nobody over-claims to an auditor. This makes the
gateway the default path for managed devices. It does not make it the only
one. A personal laptop, a phone on cellular, or a browser installed outside
management never touches this.

If the traffic must not escape, pair it with egress control: deny outbound 443
to AI destinations from anything except the proxy. That is what turns a strong
default into an actual boundary.
