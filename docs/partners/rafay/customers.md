---
title: For customers
parent: Rafay Integration
nav_order: 4
permalink: /partners/rafay/customers/
description: "For a Rafay customer: what AI guardrails do, how to turn them on, how to choose policies, and how to see what was blocked."
---

# AI guardrails on Rafay — for customers

A short guide for the customer turning on Votal Shield guardrails for their AI
workloads on Rafay. No code required.

## What guardrails do for you

When your people and apps use AI (chat, assistants, agents), guardrails inspect
each prompt and each model response and act on your policy. They can:

- **Stop sensitive data leaving** — Social Security and card numbers, secrets,
  API keys, and other protected data in a prompt.
- **Block prompt injection and unsafe content** — manipulation attempts and
  outputs your policy disallows.
- **Govern agents and tools** — what an AI agent is allowed to do and see.

Your policy is **yours alone**. It is applied only to your organization's traffic
and is isolated from every other customer.

## Turning it on

In the Rafay console, enable **Votal Shield guardrails** for your AI workloads.
Rafay provisions your dedicated guardrail tenant automatically — there is nothing
to install.

## Choosing your policy

You decide which guardrails are active. Depending on how Rafay surfaces it, you
configure this either in the **Shield policy portal** or directly in the **Rafay
UI**. Options include:

- **Built-in guardrails** — PII and secret detection, toxicity, prompt-injection
  defense, and more.
- **Custom policies** — describe a rule in plain language (for example, "block
  messages containing customer account numbers") and choose whether to warn,
  redact, or block.
- **Framework-aligned policies** — turn on sets mapped to common AI risk
  frameworks.

Changes take effect on the next request. No redeploy.

## Monitor first, then enforce

- **Monitor** — guardrails observe and record decisions without blocking. Use this
  to see what your traffic looks like.
- **Enforce** — guardrails block policy violations in real time.

Start in monitor, review what would have been blocked, then switch to enforce.

## What a user sees when something is blocked

In enforce mode, a prompt that violates your policy is stopped **before it reaches
the AI model** — the sensitive content never leaves. The person sees that their
message was blocked by policy.

## Seeing what happened

Every decision — allowed, blocked, or redacted — is recorded with the policy that
fired, visible in your telemetry/dashboard. Use it to tune policy and to show
auditors what was enforced.

## Where it runs and your data

- **Hosted** — Rafay calls the Votal Shield service.
- **In your cluster** — for strict data residency, Shield (and optionally its
  model) runs inside your own environment, so prompts are inspected without
  leaving it.

Either way, the guardrail decision is based only on the content being screened and
your policy; your model credentials are never shared with Shield.

## Getting help

Your Rafay administrator can adjust which guardrails are on, switch between
monitor and enforce, and pull decision reports. For policy design questions, Rafay
can bring in Votal.
