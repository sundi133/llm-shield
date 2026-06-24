---
title: Enterprise Integration Architecture
layout: default
nav_order: 22
permalink: /enterprise-integration-architecture/
description: How Shield integrates across an enterprise — a policy decision/inspection engine (PDP) that plugs into enforcement points in the path, plus platform connectors to cover agents you didn't build. Includes a coverage matrix by agent type and device class.
---

# Enterprise integration architecture
{: .no_toc }

Shield is the **decision and inspection engine** for AI agents. It does not have
to be your network proxy. It plugs into the points already in your traffic and
control planes, and reads the agent platforms you don't control — so you can
cover agents you built *and* agents you didn't, across the org.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. The model: PDP + PEP

Shield uses the standard separation security teams already trust:

- **PEP — Policy Enforcement Point.** Sits *in the path*; can allow / redact / block.
- **PDP — Policy Decision Point.** *Decides* — content inspection, RBAC, DLP, identity. **This is Shield.**

> Shield is the PDP. End-to-end enforcement always happens at a PEP that calls
> Shield. You are never required to make Shield your network proxy.

There are three sources of PEP, and a healthy deployment uses all three:

| PEP source | Examples | Who owns the pipe |
|---|---|---|
| **Shield-native PEPs** | LiteLLM/relay gateway with Shield guardrails, transparent **MCP proxy**, SDK/middleware | Shield |
| **Your existing PEPs (callout)** | API gateway, **SWG/CASB** (via ICAP/REST), model gateway | You — Shield is the AI-inspection callout |
| **Platform connectors** | Admin/audit APIs of SaaS agent platforms | The platform — Shield reads it |

## 2. End-to-end flows

**Agent you built (full inline enforcement):**
```
agent → Shield MCP proxy / LiteLLM gateway (PEP) → Shield decision (PDP) → allow/redact/block → tool/model
```

**Agent you didn't build, on a managed device (ride the enterprise pipe):**
```
3rd-party agent → corp SWG/CASB (PEP) → ICAP/REST callout → Shield (PDP) → verdict → SWG enforces
```

**SaaS agent you can't sit in front of (read the platform):**
```
Shield connector → platform admin/audit API → discover agents, assess posture, monitor activity → govern (inventory / reviews / detection)
```

**Tool/data boundary (any agent, anywhere):**
```
any agent → Shield MCP/API proxy (PEP) in front of the tool → Shield (PDP) → enforced at the resource
```

## 3. Coverage matrix — by agent type

| Agent type | Mechanism | Shield role |
|---|---|---|
| Agents **you build** / your gateways | Shield-native PEP (MCP proxy, LiteLLM, SDK) | PEP **+** PDP — full inline content enforcement |
| **3rd-party SaaS agents** (low-code / vendor copilots) | **Platform API connectors** | discovery + posture + detection; inline where the platform exposes a hook |
| **Direct-to-provider** traffic (managed devices) | enterprise **SWG/CASB callout** | PDP (callout); enterprise owns the PEP |
| **Tools / data** any agent touches | Shield **MCP / API proxy** | PEP + PDP at the resource boundary |
| **Browser / agentic-browser** agents | managed browser extension (later) | PEP on device → PDP callout |

## 4. Org-wide coverage (within an enterprise)

Inside an org you own the levers, so you can make the sanctioned path the **only**
path for managed devices:

- **Block direct egress** to model providers at the firewall/SWG; allow only via a Shield-fronted gateway or SWG-with-callout.
- **Issue model access as Shield-fronted keys**; direct provider keys aren't reachable from the network.
- **Put tools and data behind Shield** (+ SSO), so even an unseen agent is enforced where it acts.
- **MDM** pushes the egress/CA config and any browser extension to every managed endpoint.
- **IdP conditional access** requires a managed, compliant device to reach corporate AI apps/tools.

**Residual gap (state it honestly):** a personal/unmanaged device on a personal
network with a personal model key cannot be inspected inline by anyone. Contain
it by denying corporate tool/data/model access (IdP + resource gating) and
covering it with detective platform/provider logs.

## 5. Coverage by device class

| Device class | Covered by | Org lever |
|---|---|---|
| Corp servers / VPC | egress gateway → Shield; model-key gateway; tool boundary | network routing |
| Managed laptops/desktops | SWG/proxy callout; model-key gateway; browser ext | MDM (CA cert, proxy/PAC, extension) |
| Managed browsers | browser extension; SWG egress | browser enterprise policy |
| On-network generally | corp proxy → Shield | firewall egress rules |
| Unmanaged / BYOD | resource gating + IdP conditional access + detective logs | IdP; no device install |

## 6. New capability — the platform-connector framework

This is the piece that covers **agents you didn't build** without sitting inline.

**What a connector is:** a read-mostly integration to a SaaS agent platform's
**admin / audit / management API** that maps the platform's agents and activity
into Shield's governance model (inventory, used-vs-granted, reviews, detection).

**Connector interface (target shape):**
- `discover()` → list agents/bots/flows on the platform, with their granted tools, data connections, owners.
- `activity(since)` → recent agent executions / tool invocations / data access (for usage + detection).
- `posture(agent)` → configuration risk (over-broad scopes, public exposure, no auth on a connector).
- `act(agent, action)` *(optional, platform-permitting)* → disable / restrict an agent where the platform exposes a control.

**Maps onto what Shield already has:**
- `discover()` → the **agent inventory** (registered + shadow).
- `activity()` → **used-vs-granted** + detection signals.
- `posture()` → findings surfaced in the portal.
- `act()` → the **access-review / revoke** workflow.

**Delivery model:** connectors run on the **admin/control plane** (no GPU),
authenticate to each platform with least-privilege admin credentials (stored as
tenant secrets), and run on a schedule (pull) plus webhook (push) where the
platform supports it. Read-only by default; any `act()` is explicit and audited.

**Phasing:**
1. Connector framework + interface + one reference connector (discovery + activity).
2. Posture rules + findings in the portal.
3. Optional `act()` (disable/restrict) where platforms allow, wired to reviews.
4. Provider/admin **audit-log ingestion** for detective coverage of direct-to-provider usage.

**Where Shield is differentiated:** connectors give parity on *discovery,
posture, and detection* for third-party agents; Shield's edge remains **runtime
enforcement** — inline prompt-injection blocking, DLP redaction on tool
args/results, and per-action capability authorization — applied wherever a PEP
(native, callout, or resource boundary) is in the path.

## 7. Latency & planes

- **Connectors and governance** are control-plane logic — they run on the admin/tenant plane (CPU, no GPU) and never touch the guard path, so guarded/LLM traffic has no added latency.
- **Inline enforcement** runs at the PEP. Shield-native PEPs and SWG callouts consult the data-plane decision/inspection engine; the model-inspection cost (~hundreds of ms) applies only to traffic that is actually inspected.

## See also

- [AI Gateway & Proxy Interoperability](/ai-gateway-interoperability/) — Shield-native and gateway PEPs.
- [Agent Governance & Access Reviews](/agent-governance/) — the governance model connectors feed.
- [Identity Provider Interoperability](/idp-interoperability/) — IdP conditional access as an org-wide lever.
- [Continuous Identity & Auto-Revoke](/continuous-identity/) — signal exchange with IdP/EDR.
