# Spec: Sandbox guardrails — enforcement for agents in E2B / Daytona / Modal / K8s Agent Sandbox

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until
sign-off. Formalizes `docs/sandbox-guardrails-design.md` (architecture +
threat model) into a scoped, deliverable spec. The design doc remains the
architecture reference; this spec is the build contract.

## 1. Problem & outcome

Customers increasingly run agents inside per-agent code-execution sandboxes
(E2B, Daytona, Modal, or in-cluster via the Kubernetes SIG [Agent
Sandbox](https://agent-sandbox.sigs.k8s.io/) CRDs — `Sandbox`, `SandboxClaim`,
`SandboxWarmPool`, `agents.x-k8s.io/v1beta1`). Inside each sandbox is
**mixed trust**: a trusted
orchestration loop and untrusted agent-generated code. Today Shield has no
story for this boundary — a sandboxed agent can hold credentials, call tools,
and egress data with no policy enforcement point (PEP) the untrusted code
cannot bypass.

**Outcome:** a reference deployment (broker + egress gateway config + tool
executor + in-sandbox runtime, all composing *existing* Shield endpoints)
where:

- no long-lived secret ever enters a sandbox (tenant key stays in the broker;
  sandbox holds only a ≤15-min instance-bound agent token),
- side effects execute **outside** the sandbox, gated by single-use ≤60 s
  capabilities (`cap/mint` → `cap/verify`), so untrusted code cannot perform
  an unauthorized side effect even with full control of the sandbox,
- LLM and network egress funnel through a Shield-enforcing gateway
  (`votal_guardrail.py` LiteLLM callback → `/guardrails/input|output`,
  `/v1/shield/tool/output` DLP),
- a rogue sandbox is containable in ≤1 s via instance revocation
  (`storage/revocation.py`).

Success condition: the live integration test proves an untrusted snippet in a
Modal egress-locked sandbox (a) cannot read a tenant key, (b) cannot execute a
side-effecting tool without a minted cap, (c) cannot replay a used cap, and
(d) has all its LLM I/O screened.

**Non-goals.** No change to Shield's guard endpoints or either plane (we
compose existing ones). Not a replacement for provider isolation. Not a
guarantee against ungoverned *read-only* egress on providers without network
lockdown (E2B/Daytona today) — that residual risk is stated, not hidden
(design doc §6). Not a hosted service in v1: this ships as `examples/sandbox/`
reference components customers run in their trusted plane.

## 2. Plane & latency contract

- **Off the hot path — zero changes to `/guardrails/*`, `cap/mint`,
  `tools/call`, or either plane.** Every new component is a *client* of
  existing endpoints and runs in the **customer's trusted plane**, not in
  Shield's data or admin plane.
- Per-action budget (customer-side, documented): one guarded LLM round-trip
  via the gateway per model call; one `cap/mint` + one `cap/verify` per
  side-effecting tool call. No added latency for non-sandbox traffic.

## 3. Data model

**No new Redis keys.** The design deliberately reuses existing stores:

- Agent tokens + instance binding: `core/agent_tokens.py` (claims bind
  `agent_instance_id`, `build_hash`, `model_version`).
- Capabilities (single-use nonce burn): `core/capabilities.py`.
- Revocation (≤1 s propagation): `storage/revocation.py`.
- RBAC / registry: `agents:{tenant_id}` via `guardrails/agentic/rbac_guard.py`.

Tenant scoping is inherited: the broker authenticates with the tenant API key;
everything downstream is scoped by the token/cap claims minted from it. The
sandbox never sees `tenant_id` credentials, only its own instance-bound token.

## 4. API / interface

**No new Shield endpoints.** Consumed (all existing, prefix per
`api/routes_agent_auth.py`):

| Endpoint | Used by | Purpose |
|---|---|---|
| `POST /v1/shield/auth/agent-token` (tenant-self alias under `/v1/tenant/me/agent-auth/`) | Broker (tenant key) | Mint instance-bound agent token at sandbox boot |
| `POST /v1/shield/cap/mint` | In-sandbox runtime (agent token) | Request a single-use capability for one tool+resource |
| `POST /v1/shield/cap/verify` | Tool executor (bearer-of-cap, no secret) | Verify + burn nonce before executing |
| `POST /v1/shield/auth/revoke` | Broker / operator | Kill a sandbox instance's tokens + caps |
| `/guardrails/input`, `/guardrails/output` | Egress gateway (LiteLLM callback `votal_guardrail.py`) | Screen all LLM I/O from the sandbox |
| `/v1/shield/tool/check`, `/v1/shield/tool/output` | Runtime (cooperative) / executor + gateway (DLP) | Tool RBAC; result sanitization |

New **customer-side** components (reference implementations):

```
examples/sandbox/broker.py         # mint token, launch sandbox with token +
                                   # gateway base_url injected; provider
                                   # adapters (Modal first) behind one interface
examples/sandbox/agent_runtime.py  # in-sandbox: cooperative checks (L1) +
                                   # cap request flow; reuses shield_guard +
                                   # examples/shield_client.py; no tenant key
examples/sandbox/tool_executor.py  # outside sandbox: cap verify (fail-closed)
                                   # → execute real tool → result DLP; exposed
                                   # as a guarded MCP server (reuses
                                   # examples/mcp_server/)
examples/sandbox/gateway/          # LiteLLM config.yaml with votal_guardrail
                                   # callback + per-provider egress-allowlist
                                   # notes
```

Auth: tenant key (`X-API-Key`) exists **only** in broker/gateway config.
Sandbox holds the short-lived agent token. `cap/verify` requires no secret.

## 5. Security & backward compatibility

- **Purely additive.** No Shield defaults change; nothing existing is
  modified. No escape-hatch flag needed on the Shield side.
- Fail policy (stated per PEP): `cap/verify` **fails closed** — no verify, no
  execute, no exceptions. Cooperative in-sandbox checks fail closed by default
  (`SHIELD_FAIL_OPEN=1` existing escape hatch). The LiteLLM gateway defaults
  fail-open upstream — the shipped `config.yaml` sets `block_on_failure` for
  guarded routes and documents the trade.
- Threat containment (what untrusted code still cannot do, even with arbitrary
  code execution in the sandbox): read the tenant key (never present), forge a
  cap (Ed25519-signed, policy-gated mint), replay a cap (nonce burned), call
  the executor without a cap, exceed its role's tools/scopes, or survive
  instance revocation.
- Residual risk (must ship verbatim in the README): on providers without
  guaranteed egress lockdown (E2B, Daytona today), untrusted code may make
  ungoverned read-only calls to third parties. It still cannot perform Shield-
  mediated side effects or obtain credentials. Close the gap with provider
  egress allowlisting: Modal (`block_network`/`cidr_allowlist`) and K8s Agent
  Sandbox (NetworkPolicy deny-by-default egress + allowlist to the gateway,
  CNI-dependent) both support the strong posture, so the L2
  non-bypassability claim holds on either.
- Hardening defaults in the reference code: agent-token TTL ≤5 min for
  sandboxes; `build_hash` allowlisting via existing
  `SHIELD_AGENT_ALLOWED_BUILDS`; broker mint failure → sandbox starts
  unregistered → shadow-agent blocking applies.

## 6. Packaging & deploy

- Everything lands under `examples/sandbox/` + docs. **No module is imported
  by `admin_app.py` or `core/app.py`** → no `Dockerfile.admin` changes, no
  data-plane image changes, nothing to rebuild.
- **Invariant — dependencies:** provider SDKs (`modal`, `e2b`, `daytona-sdk`,
  `agentic-sandbox-client`/`kubernetes` for the K8s Agent Sandbox adapter)
  go in `examples/sandbox/requirements.txt` ONLY (pattern:
  `examples/mcp_server/requirements.txt`). They must NOT enter root
  `requirements.txt`/`requirements-test.txt`. Unit tests mock the network and
  import provider SDKs lazily, so CI needs no new deps.
- Env for the reference components (customer-side): `SHIELD_BASE_URL`,
  `SHIELD_TENANT_API_KEY` (broker/gateway only), `SANDBOX_TOKEN_TTL_SECONDS`
  (default 300), `SHIELD_AGENT_ALLOWED_BUILDS` (existing).
- Rollout: docs + examples release; opt-in live integration test workflow
  (manual dispatch, needs Modal credentials as Actions secrets).

## 7. Failure modes & edge cases

- **Shield unreachable:** executor and cooperative checks fail closed (deny);
  gateway per `block_on_failure` config; sandbox degrades to "can compute,
  cannot act."
- **Broker mint failure at boot:** sandbox launches without a token →
  unregistered/shadow agent → blocked from privileged tools by existing
  registry enforcement; broker retries with backoff and surfaces the error.
- **Token expiry mid-task:** runtime re-requests from the broker (broker-side
  re-mint endpoint pattern in the example); in-flight caps remain valid ≤60 s.
- **Cap replay / theft:** nonce burned on first verify — second use fails;
  ≤60 s TTL and resource scoping bound the blast radius; instance revocation
  kills outstanding caps ≤1 s.
- **Clock skew in sandbox:** all expiry checks are server-side; sandbox clock
  is untrusted.
- **Oversized/hostile payloads from untrusted code:** runtime caps request
  bodies before send; executor validates tool args against the cap's scope,
  not sandbox-supplied role claims (role comes from the token, never args).
- **Concurrent sandboxes:** instance ids are `{sandbox_id}-{pid}`-unique;
  token/cap stores already handle concurrent mints; revocation is per-instance.
- **Warm pools (K8s Agent Sandbox):** pre-warmed pods exist *before* they are
  claimed, so the per-instance token MUST be delivered at claim/attach time
  (SDK file write or per-claim projected Secret) — never baked into a
  `SandboxTemplate` or warm-pool image, where every pod in the pool would
  share it.
- **Provider without egress lockdown:** documented residual risk (§5); L3
  executor remains the hard boundary regardless.

## 8. Test plan (Definition of Done)

- Unit (network mocked, no provider SDK required): token mint binds
  `agent_instance_id` + `build_hash`; disallowed build refused; cap-mint
  denial → executor never runs the tool; verify success burns nonce;
  **replay fails**; executor refuses a tool the cap wasn't minted for; result
  DLP redacts seeded PII; fail-closed on Shield down; role sourced from
  token, not sandbox-supplied args; broker failure → shadow-agent block.
- Integration (opt-in, live, manual-dispatch CI): Modal sandbox with egress
  allowlisted to the gateway only — untrusted snippet attempting direct
  side effect + direct LLM call is denied; the four success-condition asserts
  from §1 pass.
- Regression guard: a test asserting no `examples/sandbox` import appears in
  `admin_app.py`/`core/app.py` (keeps the packaging invariant true over time).
- Full suite green in a clean venv; CI pytest gate passes with no new deps.

## 9. Task breakdown (one PR each)

1. **Broker + Modal adapter** (`broker.py`): token mint + injection, sandbox
   launch with gateway `base_url`, egress allowlist config; mocked unit tests.
2. **Tool executor** (`tool_executor.py` as guarded MCP server): cap verify
   fail-closed, nonce-burn/replay tests, result DLP; reuses
   `examples/mcp_server/`.
3. **In-sandbox runtime** (`agent_runtime.py`): cooperative L1 checks + cap
   request flow; reuses `shield_guard` + `examples/shield_client.py`.
4. **Egress gateway config** (`gateway/config.yaml` + README): LiteLLM
   `votal_guardrail` callback, `block_on_failure`, per-provider egress notes,
   residual-risk statement.
5. **K8s Agent Sandbox + E2B + Daytona adapters + live integration test.**
   The Modal proof stays manual-dispatch (needs vendor credentials); the K8s
   adapter's non-bypassability proof can run on a `kind` cluster with a
   NetworkPolicy-capable CNI in ordinary CI — no vendor account. Keep the
   K8s adapter thin: the API is `v1beta1` and may churn.

Recommended sequencing if we cut scope: 1 + 2 first (L0 identity + L3
executor — the hard security boundary), then 3 + 4, then 5.

## 10. Open questions (for approval)

1. **Provider order** — recommend **Modal first** (real egress lockdown makes
   the non-bypassability claim demonstrable), then **K8s Agent Sandbox**
   (equally strong egress via NetworkPolicy, and it is the on-prem/in-VPC
   answer for customers who won't ship code to a sandbox vendor's cloud;
   per-sandbox ServiceAccount identity composes with Shield's existing
   SPIFFE support), then E2B, then Daytona.
2. **Executor transport** — recommend **MCP** (reuse the guarded MCP server;
   sandbox speaks one protocol) over a bespoke HTTP service.
3. **First delivery scope** — recommend **L0+L3** (tasks 1–2) as the minimum
   sellable boundary, with L2 gateway wiring (task 4) in the same quarter.
4. **Productization trigger** — v1 is reference code in `examples/`; decide
   later whether the broker/executor graduate into a supported deployable
   (own image) once ≥2 design partners run it.
