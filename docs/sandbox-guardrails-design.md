# Design: Guardrails for Agent Sandboxes (E2B / Daytona / Modal)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until this is
signed off.

## 1. Problem & outcome

Agents run in per-agent sandboxes (E2B / Daytona / Modal). Inside each sandbox
there is **mixed trust**: a trusted orchestration loop *and* untrusted,
agent-generated code that may execute arbitrary logic. We want Votal Shield to
enforce, at the sandbox boundary:

1. **LLM input/output content** — screen prompts and model responses.
2. **Tool-call RBAC** — role→tool authorization + argument data policy.
3. **Data egress / DLP** — sanitize/block sensitive data leaving the sandbox.
4. **Per-sandbox identity + capabilities** — bind identity to each sandbox
   instance; authorize each side-effecting action with a single-use capability.

**Outcome / success:** a sandbox where (a) the trusted loop is guarded
cooperatively with near-zero friction, and (b) **no untrusted code inside the
sandbox can perform an authorized side effect or exfiltrate data without passing
a Shield policy enforcement point (PEP) that lives *outside* the sandbox.**

**Non-goals.** Not a change to Shield's guard endpoints (we compose existing
ones). Not a replacement for the sandbox provider's own isolation. Not a promise
that ungoverned *read-only* LLM calls are impossible when a provider offers no
egress control (see §6 — we state the residual risk explicitly rather than
pretend).

## 2. Threat model (mixed trust)

| Actor | Can be trusted to… | Must NOT be relied on for… |
|---|---|---|
| Orchestration loop (your code) | call Shield guardrails cooperatively, hold a short-lived token | — |
| Agent-generated code (untrusted) | nothing | calling guardrails, honoring RBAC, not attempting egress, not reading env |

Design consequence: **cooperative enforcement is necessary but not sufficient.**
Anything that matters (side effects, sensitive data) must be enforced by a PEP the
untrusted code cannot bypass — i.e. **outside** the sandbox. The sandbox is
treated as hostile for high-value paths.

## 3. Core principle — keep secrets and PEPs out of the sandbox

Three rules drive everything below:

1. **No long-lived secret in the sandbox.** The tenant API key never enters a
   sandbox. The sandbox receives only a **short-lived, instance-bound agent
   token** (≤15 min) minted by the orchestrator.
2. **Side-effecting tools execute outside the sandbox**, behind capability
   verification. The sandbox can *request* an action but cannot *perform* it.
3. **Egress is funneled through a Shield-enforcing gateway** the sandbox is
   configured (and, where the provider allows, network-locked) to use.

## 4. Architecture — layered PEPs

```
                        ┌─────────────────────────────────────────────┐
                        │  TRUSTED ORCHESTRATION (your control plane)   │
                        │                                               │
  tenant API key ──────▶│  Sandbox Broker                               │
  (never leaves here)   │   • mint_agent_token(instance_id, build_hash) │
                        │   • injects token into sandbox at boot        │
                        │                                               │
                        │  Egress Gateway (PEP)  ◀── LiteLLM/proxy path │
                        │   • LLM I/O   -> /guardrails/input|output     │
                        │   • net DLP   -> /v1/shield/tool/output       │
                        │                                               │
                        │  Tool Executor (PEP)                          │
                        │   • verify cap -> /v1/shield/cap/verify       │
                        │   • runs the real side-effecting tool         │
                        └───────▲───────────────▲──────────────▲────────┘
                                │ agent token    │ LLM/net       │ cap + request
                                │ (mint caps)    │ (guarded)     │ (verified outside)
        ┌───────────────────────┴────────────────┴──────────────┴───────┐
        │  SANDBOX (E2B / Daytona / Modal)  — mixed trust                 │
        │                                                                 │
        │   Trusted loop ──(L1 cooperative)── shield_guard / guarded MCP  │
        │   Untrusted code ──(no creds, no direct egress, no cap)──✗      │
        └─────────────────────────────────────────────────────────────────┘
```

**L0 — Identity (per-sandbox agent token).**
At sandbox boot, the **broker** (outside the sandbox) calls
`POST /v1/tenant/me/agent-auth/agent-token` with a unique
`agent_instance_id` (e.g. `{sandbox_id}-{pid}`), `build_hash`, `model_version`,
`session_id`. The token's claims are cryptographically bound to that instance and
build (`core/agent_tokens.py:176`). It is injected into the sandbox as an env var
with a ≤15-min TTL. Revoking the instance (`revoke_instance(agent_instance_id)`)
kills all its tokens+caps in ≤1s.
→ satisfies **requirement 4 (identity)**.

**L1 — Cooperative enforcement (in-sandbox, for the trusted loop).**
The trusted loop uses the guard helper we already shipped
(`examples/mcp_server/shield_guard.py`) or connects to the **guarded MCP server**
(`examples/mcp_server/`). It calls `/v1/shield/tool/check` (RBAC) and
`/guardrails/*` (content) using the **agent token**, not the tenant key. Low
friction, full coverage for cooperative code. Best-effort only for untrusted code
— hence L2/L3.

**L2 — Non-bypassable egress gateway (LLM + network).**
All LLM traffic from the sandbox points its `base_url` at an **egress gateway**
running in the trusted plane. Shield's LiteLLM callback (`votal_guardrail.py`)
enforces `/guardrails/input` (pre-call) and `/guardrails/output` (post-call +
tool-arg DLP) transparently — any process in the sandbox that makes an LLM call
is guarded, cooperative or not (`docs/ai-gateway-interoperability.md`). For raw
network egress, the same gateway runs result DLP via `/v1/shield/tool/output`.
→ satisfies **requirement 1 (LLM I/O)** and part of **3 (egress DLP)**.

**L3 — Capability-gated tool executor (side effects, outside the sandbox).**
Side-effecting tools (send_email, delete_account, db writes, external API calls)
do **not** run in the sandbox. The sandbox, using its agent token, calls
`POST /v1/shield/cap/mint {tool, resource}` — Shield runs RBAC + resource-scope +
clearance checks and returns a **single-use, ≤60 s capability** (or 403 with
reasons). The sandbox passes the cap to the **Tool Executor** (trusted plane),
which calls `POST /v1/shield/cap/verify` (**bearer-of-cap, no tenant key** —
`examples/shield_client.py:206`) and only then executes. Untrusted code cannot
forge a cap (Ed25519; mint is policy-gated and requires the agent token) and
cannot reach the real tool directly.
→ satisfies **requirement 2 (tool RBAC)** and **3 (egress DLP)** for side effects,
and completes **4 (capabilities)**.

## 5. Enforcement matrix

| Requirement | Primitive | Endpoint(s) | PEP location |
|---|---|---|---|
| LLM input/output | LiteLLM/gateway callback | `/guardrails/input`, `/guardrails/output` | Egress gateway (outside) |
| Tool RBAC | tool check / cap mint | `/v1/shield/tool/check`, `/v1/shield/cap/mint` | in-sandbox (cooperative) **and** mint is server-side policy-gated |
| Data egress / DLP | tool-output sanitizer | `/v1/shield/tool/output` | Egress gateway + Tool Executor (outside) |
| Per-sandbox identity + caps | agent token + cap verify | `/v1/tenant/me/agent-auth/agent-token`, `/v1/shield/cap/verify` | Broker + Tool Executor (outside) |

Auth headers: tenant key (`X-API-Key`) only on the **broker/gateway** (outside);
sandbox holds `X-Agent-Token`; cap verify needs **no** secret.

## 6. Provider-specific notes (the honest part)

"Non-bypassable" for L2 depends on the provider's egress control. L3 is
bypass-proof **regardless** of egress (no valid cap ⇒ no side effect).

| Provider | Egress lockdown today | Recommended posture |
|---|---|---|
| **Modal** | Strong — sandboxes can block network / allowlist hosts (`block_network` / restricted egress). | Allowlist only the egress gateway host ⇒ L2 is genuinely non-bypassable. |
| **K8s Agent Sandbox** (SIG Apps, `agents.x-k8s.io/v1beta1`) | Strong — Kubernetes NetworkPolicy deny-by-default egress + allowlist (CNI-dependent, e.g. Cilium/Calico); gVisor/Kata isolation. | Allowlist only the egress gateway + Shield ⇒ L2 non-bypassable in-cluster. The on-prem/in-VPC option. Per-sandbox ServiceAccount identity composes with Shield's SPIFFE support. Deliver the agent token at claim time — never bake it into a `SandboxTemplate`/warm-pool image. |
| **E2B** | Partial — sandbox templates + evolving egress controls; not a guaranteed firewall for arbitrary outbound. | Configure agent `base_url`/MCP to the gateway; rely on L3 for anything that matters; document residual risk of ungoverned read-only LLM calls if code reaches the internet directly. |
| **Daytona** | Partial — runner/network-policy dependent. | Same as E2B: gateway config + L3 executor as the hard boundary; egress allowlist where the runner supports it. |

**Residual risk statement (must ship in the doc):** where the provider cannot
guarantee egress lockdown, untrusted code *may* make ungoverned read-only calls
to third parties. It still **cannot** perform authorized side effects or exfil
through Shield-mediated tools (L3), and cannot obtain the tenant key (L0). Close
the gap with provider egress allowlisting when available.

## 7. Key request flows

**Guarded LLM call (any code in sandbox):**
`sandbox -> egress gateway (base_url) -> [pre: /guardrails/input] -> upstream LLM
-> [post: /guardrails/output] -> sandbox`. Blocked input never reaches the model.

**Side-effecting tool call (untrusted-safe):**
`sandbox (agent token) -> /v1/shield/cap/mint {tool,resource}` → (RBAC ok) cap →
`sandbox -> Tool Executor(cap) -> /v1/shield/cap/verify` (nonce burned) → execute
→ result through `/v1/shield/tool/output` (DLP) → sandbox. A second use of the cap
fails (replay). Unauthorized tool ⇒ mint returns 403.

## 8. Plane & latency contract

- Shield side: **off the hot path** — every component here is a *client* of
  existing guard endpoints; no change to `/guardrails/*`, `cap/mint`,
  `tools/call`, or either plane.
- New components (broker, egress gateway config, tool executor) live in the
  **customer trusted plane**, not in this repo's data/admin planes.
- Added latency is per-sandbox-action (1 LLM round-trip through the gateway; 1
  mint + 1 verify per side-effecting tool). That is the deployer's budget.

## 9. Security & failure modes

- **Fail policy:** cooperative L1 fails **closed** by default (our
  `shield_guard`), `SHIELD_FAIL_OPEN=1` escape hatch. Gateway (LiteLLM) default is
  fail-open — call out and set `block_on_failure` per risk. Cap verify **must**
  fail closed (no verify ⇒ no execute).
- **Token/cap theft:** agent token is ≤15 min + instance-bound; cap is ≤60 s +
  single-use + resource-scoped. Instance revocation propagates ≤1 s.
- **What untrusted code still can't do:** read the tenant key (never present),
  forge a cap, call the executor without a cap, or exceed its role's tools/scopes.
- **Edge cases:** Shield unreachable (fail policy per PEP), sandbox clock skew (exp
  checks server-side), broker mint failure (sandbox starts unregistered → shadow
  agent, blocked from privileged tools), oversized payloads (capped before send).

## 10. What exists vs. what we'd build

**Exists (no work):** all guard/RBAC/token/cap endpoints; LiteLLM gateway
callback (`votal_guardrail.py`); transparent MCP proxy (`core/mcp/upstream.py`);
the guarded MCP server + `shield_guard` (`examples/mcp_server/`);
`examples/shield_client.py` (token + cap SDK).

**Would build (examples only, off hot path) — proposed one-branch delivery:**
1. **Sandbox broker** — `examples/sandbox/broker.py`: mint an instance-bound
   agent token and launch an E2B/Modal/Daytona sandbox with it injected + LLM
   `base_url` pointed at the gateway. Provider adapters behind one interface.
2. **In-sandbox client** — `examples/sandbox/agent_runtime.py`: uses the agent
   token for L1 cooperative checks and the cap flow for L3 requests (no tenant
   key). Reuses `shield_guard` + `shield_client`.
3. **Tool executor** — `examples/sandbox/tool_executor.py`: verifies caps
   (bearer-of-cap) and runs the real tools outside the sandbox; result DLP.
4. **Egress gateway config** — `examples/sandbox/gateway/` LiteLLM
   `config.yaml` with the `votal_guardrail` callback + per-provider egress
   allowlist notes.
5. **Docs + tests** — this design doc, a README, and mocked unit tests for the
   broker/executor/cap paths (network stubbed, like the MCP server tests).

## 11. Test plan (DoD)

- Unit (network mocked): token mint binds `agent_instance_id`; cap mint denied →
  no execution; cap verify success burns nonce; **replay fails**; executor refuses
  a tool the cap wasn't minted for; DLP redacts a PII tool result; fail-closed on
  Shield down; role sourced from token/broker, not sandbox-supplied args.
- Integration (opt-in, live sandbox): Modal egress-blocked sandbox proves L2
  non-bypassable; untrusted snippet attempting a direct side effect is denied.
- Clean-venv green; full `pytest tests -q` green; CI passes.

## 12. Open questions (for approval)

1. **Primary provider to implement first** — the broker/egress specifics differ.
   Recommend **Modal first** (real egress lockdown ⇒ demonstrably non-bypassable),
   then E2B, then Daytona.
2. **Executor transport** — expose the Tool Executor as its own guarded MCP server
   (reuse `examples/mcp_server/`) or a plain HTTP service? Recommend MCP so the
   sandbox speaks one protocol.
3. **Scope of first delivery** — full 5-component set, or start with L0+L3
   (identity + cap-gated executor, the hard security boundary) and add the egress
   gateway wiring next?

## 13. Enterprise readiness (sandbox-specific)

What an enterprise security review will ask for when agents run in sandboxes, and
where Shield already answers it. Most of this is existing capability
(`docs/enterprise-features.md`) applied to the sandbox boundary — no new build.

| Requirement | How the sandbox design meets it | Primitive |
|---|---|---|
| **Attestation — "which code ran?"** | The per-sandbox agent token is bound to `build_hash` + `agent_instance_id` + `model_version` at L0. Every cap minted and action taken is traceable to that exact build/instance. Optional `SHIELD_AGENT_ALLOWED_BUILDS` allowlist refuses unknown builds. | `core/agent_tokens.py` |
| **Instant containment (kill a rogue sandbox)** | `revoke_instance(agent_instance_id)` invalidates all that sandbox's tokens **and** caps in ≤1s across verifier replicas. Tool kill-switch disables a compromised tool globally (0 ms lookup). | `storage/revocation.py`, kill-switch |
| **Audit — "prove what the sandbox did"** | Every RBAC/guard/cap decision is audited per tenant, queryable via `/v1/shield/decisions` and `/v1/shield/audit`; cryptographic tamper-evidence is on the [audit roadmap](/spec-tamper-evident-audit/). | decision audit + [tamper-evident spec](/spec-tamper-evident-audit/) |
| **Data residency / sovereignty** | Run the gateway, tool executor, and Shield data plane **in-region / in-VPC / air-gapped**; sandbox holds no tenant key and phones only in-boundary PEPs. Nothing leaves the customer boundary. | `docs/on-premises-deployment-guide.md` |
| **Human oversight on high-risk sandbox actions** | Side-effecting tools gated at L3 can require human approval before cap verify succeeds — see the [HITL + break-glass spec](/spec-hitl-breakglass/). | `sensitive_action_confirmation` + HITL spec |
| **Egress DLP across chained tools** | Taint tracking follows sensitive data (SSN/PII) from one tool output into the next tool's input and blocks unclearance egress — critical when untrusted code chains tools. | taint tracking (`docs/enterprise-features.md` §7) |
| **Cost / runaway containment** | Per-sandbox token, cost, and API-call budgets; loop detection stops a stuck agent. | `budget_controls`, `loop_detection` |
| **Alerting / IR integration** | Webhook events (`guardrail_blocked`, `budget_exceeded`, `tool_disabled`) to Slack/PagerDuty; SIEM stream (ECS). | webhooks, `storage/siem_store.py` |
| **Compliance evidence** | The sandbox controls map to the auditor evidence pack (audit, decisions, policy bundle, RBAC matrix, revocation history). | `docs/compliance-mapping.md` §9 |

**Sandbox-specific hardening beyond the defaults:**
- Set a **short agent-token TTL** (≤5 min) per sandbox and re-mint from the broker;
  a leaked token dies fast.
- **Never** put the tenant key, signing key, or long-lived credentials in a sandbox
  env — only the short-lived agent token.
- Prefer **`build_hash` allowlisting** so only attested sandbox images can mint
  caps at all.
- For untrusted-code sandboxes, treat L3 (cap-gated executor outside) as the
  compliance boundary of record — it's the PEP you can prove was in the path.
