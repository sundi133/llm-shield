---
title: "Foundry Integration: Sales Guide"
layout: default
nav_order: 23
permalink: /foundry-sales-guide/
description: "Field guide for technical sales on Microsoft Foundry. Qualifying questions that route to the right integration pattern, objection handling, the one promise you must not make, and what is validated versus what needs a POC."
---

# Foundry integration, a sales guide
{: .no_toc }

A field reference for calls where the customer runs on **Microsoft Foundry**
(formerly Azure AI Foundry). Same discipline as the sales battle card
(`docs/sales-battle-card.md` in the repo): lead with the mechanism, and every
**⚠️ verify** marks a spot where the honest answer wins the room.

Engineering detail lives in
[Microsoft Foundry Integration](/microsoft-foundry-integration/). Send that to
their architect after the call.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## The one-sentence frame

> *Foundry gives you the models and the agent runtime. Shield governs what those
> agents are actually allowed to do, per action, and produces the audit trail.
> We attach at Foundry's own extension points, so your Azure architecture does
> not change.*

Say "we attach to Foundry" and never "we sit in front of Azure." The second
sounds like a rip-and-replace and puts the Microsoft account team against you.

---

## Qualify first: three questions that pick the pattern

Do not pitch an architecture before these. The answers route you.

| Ask | If they say | Lead with |
|---|---|---|
| **"Who writes the code that calls the model?"** | Our own apps | **Pattern A** (LiteLLM bridge) |
| | A vendor app we cannot modify | **Pattern B** (endpoint substitution) |
| | We are building on Foundry Agent Service | **Pattern C** (MCP gateway) |
| **"Is anything already between your apps and Foundry?"** | Azure API Management | **Pattern D** (policy calls the guardrail API) |
| | LiteLLM or another AI gateway | **Pattern A**, and it is mostly config |
| **"Are your agents calling tools, or is this chat only?"** | Tools, actions, data | **C is the real deal**, A is table stakes |
| | Chat only, for now | A or B, and plant C for phase two |

**Most enterprise deals land on A plus C.** A covers the prompt and completion
path. C covers what the agent is allowed to *do*. They are independent and can
be sold in either order, which makes A a clean phase one.

---

## The four patterns in one table

| Pattern | Where Shield attaches | Pitch it as |
|---|---|---|
| **A. LiteLLM bridge** | A proxy hop between the app and Foundry, running the Shield guardrail plugin | "Your models stay in Foundry. One hop adds inspection to every call." |
| **B. Endpoint substitution** | The client's OpenAI `base_url` points at Shield | "Zero code change. One config line." |
| **C. MCP gateway** | Foundry agent connects to Shield, which fronts the real tool server | "Your agent cannot reach a tool without passing enforcement." |
| **D. Direct API** | An APIM policy calls Shield's stateless guardrail endpoints | "Enforcement inside the policy layer you already run." |

---

## ⚠️ The one promise you must not make

**Never say "just point Shield at your Foundry endpoint and you are done."**

Shield's upstream forwarder posts the request body to the upstream with **no
auth headers attached**, and it targets `/v1/chat/completions`. Foundry requires
an `api-key` header (or an Entra bearer) and serves `/openai/v1/chat/completions`.
So Shield cannot today authenticate directly to Foundry as its upstream.

**What to say instead:** "The credential stays with the hop that owns it. In the
standard pattern LiteLLM holds your Foundry key, and Shield never needs one,
which is usually what the security team wanted anyway."

That reframe turns a gap into a trust argument, and it is true. Promising the
direct path gets discovered in week one of the POC and costs you the account.

⚠️ **Verify** before any statement of work: if the customer's architecture
genuinely forbids a proxy hop, the direct-upstream path is a product change, not
a config toggle. Bring it to engineering as a spec, do not price it as setup.

---

## ROUND 1 · Positioning against Microsoft

### Q1 · Architect · "Azure already has Content Safety and Prompt Shields. Why you?"

**Different layer, and say so immediately.** Their filters classify **content**.
We enforce **actions**.

- Content Safety answers "is this text harmful." Useful, and we tell customers to keep it on.
- It does not answer "may this agent call `transfer_funds` with these arguments, on behalf of this human, right now."
- It does not carry identity through the hop, scope a permission to one resource for one use, or emit a per-action audit row an auditor can filter.

**The line:** "Keep Prompt Shields. It is a good content filter. It is not an
authorization system, and the thing that will hurt you in an agentic deployment
is an authorized-looking action, not a rude sentence."

*Jab, "So you are just RBAC?"* → "RBAC plus data policy. Authorization asks whether
this role may call this tool. Data policy asks what sensitive content may cross
the tool boundary. Those are different checks at different endpoints, and most
integrations only do the first one."

### Q2 · Buyer · "We are a Microsoft shop. Why add a third party?"

**We are additive and we federate, we do not replace.**

- Models stay in Foundry. Identity stays in Entra. The agent runtime stays Foundry Agent Service.
- We attach at Microsoft's own documented extension points: the Agent Service MCP tool with custom headers, the OpenAPI tool, or an APIM policy. Nothing bespoke.
- Removing us is deleting an integration, not unwinding a dependency.

*Jab, "Will Microsoft ship this themselves?"* → "They may ship more content
filtering. The agent authorization and per-action audit problem is
cross-platform by nature, because your agents will call tools that are not in
Azure. Betting on one cloud's runtime to govern a multi-cloud tool surface is
the risk."

### Q3 · Security · "Does our data leave Azure?"

**Not if you deploy it in your subscription, and that is the normal shape.**

- Shield runs as two planes in your tenancy: a **GPU data plane** doing inspection, and a **CPU admin plane** for policy and portal.
- The data plane is what sees prompt text. On AKS with a GPU node pool inside your VNet, inspection never leaves your network boundary.
- Contrast with API-based guardrail services, where every prompt is shipped to a third-party cloud.

⚠️ **Verify** the deployment topology they are actually buying. The self-hosted
story is only true if they self-host. If they are evaluating a hosted data
plane, say so plainly and discuss residency.

---

## ROUND 2 · The technical round

### Q4 · Developer · "Concretely, what changes in my code?"

**For Pattern A, one line.** Their app points at the LiteLLM proxy URL instead of
the Foundry endpoint. The Foundry deployment, model name and prompts are
untouched.

On the Shield side it is configuration, not development: LiteLLM already has a
first-class Azure provider, and Shield's config generator already detects
`AZURE_API_KEY` and `AZURE_API_BASE` and emits the matching model spec. The
guardrail plugin is registered with `default_on: true` so it runs on every
request, including from plain OpenAI clients.

*Jab, "Days or weeks?"* → "Hours for pattern A in a dev subscription. The
calendar time is their change control, not our integration."

### Q5 · Security · "We use Entra managed identity, not API keys."

**Good, and that lives in the hop that holds the credential.** LiteLLM can carry
an Entra credential to Foundry. Shield still holds nothing.

⚠️ **Verify** their exact auth mode before promising. Managed identity to
Foundry is a LiteLLM and Azure configuration question, not a Shield feature, so
confirm it with their platform team rather than asserting it works.

### Q6 · Platform Engineer · "What does inspection cost me in latency?"

**Give the real number and the shape, not a marketing number.**

- Benchmarked p50 is **181 ms** server-side at concurrency 1, on an H100 with FP8 serving.
- It scales sub-linearly: 10x the concurrency is about 3.6x the p50, with throughput holding near 9 requests per second.
- The design reason is a two-tier pipeline. Cheap CPU checks plus a fast classifier resolve the confident majority in roughly 18 ms, and only the inconclusive band reaches the GPU tier, where checks run concurrently so the tier costs the slowest check rather than the sum.

*Jab, "So what happens at 10 concurrent users?"* → "p50 goes to about 657 ms on a
single H100. That is a capacity planning input. If you need sub-250 ms at that
concurrency you need more GPU, and we will size it with you."

Never quote a single latency figure without its concurrency. The number is
defensible; a naked number is not.

### Q7 · Architect · "We are building on Foundry Agent Service. Does this cover tools?"

**This is the strongest part of the story, so slow down here.**

Foundry's MCP tool connects an agent to a remote MCP server and passes **custom
headers**. That is exactly the shape our gateway expects. The agent points at
`https://<shield>/gateway/<route>/mcp` with the tenant key as a header, and every
`tools/call` runs authorization, then input screening, then forwarding, then
data-loss prevention on the result, before the agent ever sees it.

Their existing MCP servers do not change. One gateway fronts many servers by
config.

*Jab, "Does that mean rewriting our tools?"* → "No. The gateway makes an outbound
call to your unmodified server. You register a route, you do not touch the tool."

### Q8 · Security · "What stops the agent from just calling the tool directly?"

**Say the hard part out loud, because it is the precondition of the whole deal.**

"Nothing, if the tool server stays reachable. A gateway only protects what
cannot be reached around it. Locking the upstream down so it accepts traffic
only from the gateway is not optional hardening, it is what makes the deployment
mean anything. We will put that in the runbook and we will check it at go-live."

Security architects reward this answer. Vendors who skate past it lose them.

---

## ROUND 3 · Closing stage

### Q9 · Compliance · "What can I hand my auditor?"

Mappings against six frameworks: NIST AI RMF, OWASP Top 10 for LLM Applications
(2026), OWASP Top 10 for Agentic Applications (2026), NIST SP 800-53, the EU AI
Act high-risk provisions, and ISO/IEC 42001. Each control maps to a named
guardrail, and enforcement decisions are queryable per action.

**Then volunteer a gap.** "Two rows in our OWASP mapping say out of scope and
partial. Data and model poisoning needs training-pipeline controls, which is not
us. Human-agent trust exploitation is only partially covered, because approval
fatigue is a behavioral risk a confirmation prompt does not fix."

Volunteering the gap is the move. It converts the mapping from a marketing
artifact into evidence, and it is the moment compliance buyers start trusting
the rest of the document.

### Q10 · Buyer · "What does a POC actually look like?"

Scope it to one pattern and one measurable outcome. Do not POC all four.

1. **Pattern A in their dev subscription.** LiteLLM in front of one Foundry deployment, Shield guardrail on, one app repointed.
2. **The proof.** Send an injection string through their own app and show it blocked, with the guardrail decision in the audit trail. A live block beats a slide.
3. **The number.** Run their traffic shape and report p50 and p95 at their real concurrency, not ours.

If they are on Agent Service, add one tool behind the MCP gateway and show a
denied `tools/call` for an out-of-role user. That single demo sells pattern C
better than any deck.

---

## Claim tiers: what you may assert flat out

Say **shipped** only for the first row. For the rest, say "documented extension
point on both sides, and we validate it in your subscription during the POC."

| Pattern | Status | Safe wording |
|---|---|---|
| **A. LiteLLM bridge** | Plugin and example config ship in our repo; the Azure provider is LiteLLM's own | "Shipped on our side, standard on theirs." |
| **B. Endpoint substitution** | The endpoint is shipped and validated. Reaching Foundry as upstream needs the credential hop | "Shipped, with the credential caveat above." |
| **C. Agent Service MCP tool** | Both halves exist and are documented. We have not run the joined path end to end | "Integration pattern. We prove it in your POC." |
| **D. APIM policy** | Our API is stable and stateless. The policy is theirs to author | "Our side is stable. The policy is a short engagement." |

---

## Never say

- ❌ "Point Foundry at Shield and you are done." → the credential gap, above.
- ❌ "We replace Azure Content Safety." → we are a different layer, keep theirs on.
- ❌ "No latency impact." → give p50 with its concurrency.
- ❌ "We cover the whole OWASP Top 10." → LLM05 is out of scope, ASI09 is partial.
- ❌ "The MCP self-check tools enforce policy." → those are cooperative. The gateway is the enforcement path.
- ❌ "It works with managed identity." → until their platform team has confirmed it.

---

## Glossary: Foundry terms for sales

**Microsoft Foundry** = the rebranded Azure AI Foundry, covering models, agents
and tooling · **Foundry Models** = the model catalog and inference endpoint;
exposes an OpenAI-compatible surface so standard clients work · **deployment
name** = what they call their specific model instance, and the string LiteLLM
needs · **Foundry Agent Service** = Microsoft's hosted agent runtime · **MCP
tool** = how a Foundry agent connects to a remote tool server, with support for
custom headers, which is our attachment point · **OpenAPI tool** = the
alternative, connecting an agent to an HTTP API with anonymous, API key or
managed identity auth · **toolbox** = Foundry's reusable grouping of tools
across agents · **APIM** = Azure API Management, their API gateway, and where a
Pattern D policy would live · **Entra** = Microsoft's identity platform,
formerly Azure AD · **Private Link** = private network path to an Azure service,
which their security team will ask about · **Content Safety / Prompt Shields** =
Microsoft's built-in content filtering, complementary to us, not competing.
