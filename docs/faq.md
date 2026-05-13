---
title: FAQ
layout: default
nav_order: 2
permalink: /faq/
description: Buyer and integrator questions about LLM Shield's red-team coverage, production safety, deployment, and depth of testing.
---

# Frequently Asked Questions
{: .no_toc }

Customer-facing answers to the questions we hear most often during evaluation. Each answer is grounded in what's actually shipping today; gaps and roadmap items are called out explicitly.

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. How are you replicating the intuition and out-of-the-box thinking of an ethical hacker who can invent new vectors?

We combine a curated taxonomy of **185+ named attack techniques** across 8 categories — injection, cognitive control bypass, persona hijacking, reformulation/evasion, boundary manipulation, integrative, multimodal, and additional evasion — with an **LLM-backed adversarial detector** (Qwen3-class model) that recognizes 40+ threat patterns *semantically*. The detector catches mutated and encoded variants (Base64, ROT13, hex, URL encoding, Unicode normalization) it has never literally seen before.

That said, today the **offensive corpus is human-curated**, not autonomously generated. Generative, agent-driven novel-vector synthesis is on the roadmap; current "novelty" comes from semantic generalization on the detection side and from frequent corpus refreshes on the offense side.

{: .note }
> Implemented today: pre-programmed taxonomy + LLM-based semantic detection.
> On the roadmap: autonomous attack synthesis via generative red-team agents.

---

## 2. Is testing limited only to pre-programmed logic in the attack framework?

Today, yes. The red-team suite ships **1,850 attack prompts × 13 industry pools (~26K test cases)** drawn from a templated, pre-generated catalog. Variation comes from industry-specific field substitution (`industry_pools.py`, `generate_red_team_prompts.py`), not from on-the-fly LLM mutation.

We're transparent about this: it's a **deterministic, reproducible suite** — good for regression testing and benchmarking — but not yet an autonomous red-team agent.

---

## 3. Does it have any context into how the AI infrastructure is structured?

**Partially.** LLM Shield is tenant-aware and policy-aware:

- Each tenant declares allowed topics, blocklists, PII rules, and registered agents/tools (RBAC).
- For agentic systems, we do **tool taint tracking** — e.g., if `patient_lookup` returns an SSN, the framework prevents that data from being passed to `send_email`.
- MCP server registration tracks per-server trust scores and the tool surface the agent is allowed to touch.

What we **don't** do today is auto-discover model architecture (RAG vs. fine-tuned vs. agent) and tailor the attack mix accordingly — the same suite runs against any OpenAI-compatible endpoint. Architecture-adaptive test selection is roadmap.

---

## 4. Can it run continuously in production and pause testing when target systems experience performance issues?

The **runtime guardrails** (input/output classification, tool authorization, audit logging) are designed for production and run inline on every request, with a configurable inspection timeout (default **250 ms**; on timeout we degrade to log-only rather than block).

The **red-team suite itself is batch-mode** today — you schedule it, it runs, you get a report. Adaptive throttling that pauses test injection when target latency or error rates spike is **not** built in; customers typically wrap our test runner in their own scheduler/SRE guardrails. Native target-health-aware pacing is on the roadmap.

---

## 5. What means do users have to minimize risk of accidental crashes, overwhelming databases, or corrupting the AI application state?

| Mechanism | What it does |
|---|---|
| `rate_limiter` guardrail | Per-tenant sliding-window rate limiting (configurable) |
| `GUARDRAIL_INSPECTION_TIMEOUT_MS` | Default 250 ms per check; on timeout returns `{"action":"log"}` instead of blocking the call |
| `REQUEST_TIMEOUT` | Hard ceiling on total request time (default 300 s) |
| Graceful degradation | Failed LLM calls return a logged result, never a 500 to the application |
| Runtime config toggles | `PUT /v1/shield/config` — disable specific guardrails or attack categories without restart |
| Audit logging | Every decision persisted (SQLite/Elasticsearch) for forensic rollback |
| **Recommended pattern** | Point the red-team suite at a **staging or shadow tenant** first; production runs use a dedicated test tenant with isolated quotas |

{: .warning }
> Honest gap: there is no true dry-run/simulation mode and no automatic state-corruption detection today. Use a separate tenant + quotas to bound blast radius.

---

## 6. How easy is setup and kickoff — what are the steps, how much time is required, and how different is it for on-premises vs. cloud?

### Cloud (managed / RunPod)
- ~10 minutes
- Deploy our container, get an endpoint, point traffic at `/v1/shield/chat/completions`, configure a tenant in the admin portal

### On-premises
- 30–60 minutes for the standard Docker Compose stack (10 services: API gateway, LLM proxy, guardrail model, inspection service, Redis Stack, admin portal, red-team portal, NGINX)
- Hardware: 32+ CPU cores, 64 GB RAM, one A100/H100 (80 GB) for the guardrail model
- Full instructions in the [On-Premises Deployment Guide]({{ "/on-premises-deployment-guide/" | relative_url }})
- Kubernetes / OpenShift manifests included

### Steps either way
1. Deploy the stack
2. Create a tenant + policy via the admin portal
3. Register agents/tools (if applicable)
4. Point your app at the gateway
5. Kick off the red-team suite (`./01_healthcare.sh` or your industry equivalent)

### Differences
- **On-prem**: production-grade — fully air-gappable, multi-tenant HA, K8s-ready
- **Cloud**: faster to start but less customizable

---

## 7. What is the depth of testing it performs?

- **~26,000 test prompts** out of the box: 1,850 adversarial + 250 benign per industry × 13 industries (healthcare, banking, legal, e-commerce, HR, government, real estate, education, telecom, travel, IT/SaaS, insurance, logistics)
- **8 attack families / 185+ named techniques**: prompt injection (13 delivery vectors), overt instruction attacks, cognitive control bypass, evasion/reformulation, boundary manipulation, integrative, multimodal, plus output-side checks for harmful/toxic content, PII leakage, Unicode obfuscation, off-topic drift
- **Agentic depth**: tool RBAC violations, cross-tool data taint flows, goal-drift detection
- **Performance**: parallel execution of LLM-based guardrails with p50 latency ~181 ms on H100

{: .note }
> Honest gap: tests are currently treated as pass/fail; we do not emit CVSS-style severity scoring or auto-prioritized remediation guidance. That's on the roadmap.

---

## 8. Are you most interested in using it with other CART tools, alongside humans, or to fully automate testing replacing humans?

This is a question we **ask the customer** before we propose an architecture, but here's how LLM Shield typically fits:

- **Alongside humans (most common)** — security teams define policies, review blocked-request audit logs, and iterate the suite. LLM Shield handles the high-volume regression and inline blocking.
- **Alongside other CART tools** — drop in via our OpenAI-compatible gateway. We don't claim to replace bespoke human red-team campaigns or specialized adversarial-ML tools.
- **Not a full human replacement today** — LLM Shield is the **enforcement + continuous-regression layer** in your AI security program, not a strategist.

{: .tip }
> Tell us which of these three modes matches your security operating model and we'll recommend a specific deployment + integration shape.

---

## Still have questions?

- Open an issue on [GitHub](https://github.com/sundi133/llm-shield/issues)
- See the full [API Reference]({{ "/api-reference/" | relative_url }})
- Walk through the [Quickstart]({{ "/quickstart/" | relative_url }})
