---
title: "Spec: Infrastructure Guardrails (Runtime Policy)"
layout: default
nav_exclude: true
permalink: /specs/infra-guardrails/
description: One Shield policy for an agent's runtime boundary (network, files, processes, tools, identity, resources), compiled into the sandboxes and proxies that enforce it at the kernel and network level, checked the same way on Shield's own tool paths, and fed back into audit and cross-app flow control.
---

# Spec: Infrastructure Guardrails (Runtime Policy)

> Status: **DRAFT, awaiting approval.** No code until approved.
> Planes:
> - **Admin plane:** policy, compilers and bundles.
> - **Data plane:** the decision API and event ingest.
> - **Separate enforcement points:** OpenShell, Kubernetes, Squid/Envoy. Shield
>   configures them and does not run them.
>
> Builds on `docs/sandbox-guardrails-design.md` (DRAFT), `docs/spec-swg-icap-adapter.md` (APPROVED),
> `docs/specs/cross-app-flow-control.md` (APPROVED, shipped in #443).

## 0. The idea in one paragraph

Shield today guards what an agent **says and asks for**: prompts, tool calls,
capabilities, data flows. Almost all of that is cooperative, because the agent
calls Shield's API. The infrastructure layer (the column NVIDIA's OpenShell
emphasises: runtime boundary, process isolation, network policy, file access,
tool/API access, identity, resource access) is enforced by the **runtime**: the
kernel (Landlock, seccomp), the network (egress proxy, NetworkPolicy) and the
orchestrator. Shield should not become a sandbox. It should be the **one place
the security team writes that policy**. Shield then does four things with it:

1. Compiles it into each runtime's native format and serves it as a signed
   bundle.
2. Applies the same rules to its own tool paths, so cooperative and enforced
   layers never disagree.
3. Takes the runtime's deny events back into audit, SIEM (ASIM) and the
   cross-app flow session state.
4. Refuses capabilities to an agent whose sandbox is not running the current
   policy.

Integrating a new runtime then means writing one compiler and one event
adapter. There is no new policy language for customers.

## 1. What exists vs what is missing

Evidence from `origin/main` (2026-09-28).

| Area | Today | Enforced where | Gap |
|---|---|---|---|
| **Runtime boundary** | A hand-written OpenShell policy (`examples/openshell/shield-policy.yaml`) and the guide `docs/openshell-sandbox.md`. The sandbox broker, executor and runtime live only on unmerged `feat-sandbox-*` branches (examples). | OpenShell kernel controls, but Shield neither generates nor pushes the policy | No policy model, no generator, no distribution, and no way to know which policy a sandbox actually runs |
| **Process isolation** | Nothing command-level. `tool_allowlist` and `action_classification` are per tool name only. | n/a | No allowed-binaries or deny-commands model. Shell and code-exec tools are judged only by an LLM (`payload_risk`). |
| **Network policy** | SWG/ICAP (`icap/`, `deploy/swg/`) decrypts only AI hosts and screens prompts, failing closed. `core/url_safety.py` protects Shield's own outbound calls. The vault binds each secret to a host. xflow classifies destinations. | Network-level for people's AI traffic through Squid; cooperative for agents | No **agent egress allowlist**. Nothing is generated for OpenShell `network_policies`, K8s NetworkPolicy/Cilium, or Squid ACLs. |
| **File access** | `scope_boundaries` namespace globs on caller-supplied `resource_type`. | cooperative | No filesystem path policy. The `read_file`/`write_file` arguments of MCP filesystem tools are unchecked. |
| **Tool/API access** | Strong: MCP gateway, `cap/mint`/`cap/verify`, allowlists, kill switch, xflow. | cooperative, plus the gateway proxy | Only non-bypassable when egress is locked to Shield. No capability check against the sandbox's actual policy. |
| **Identity** | Agent tokens, SPIFFE/mTLS/OIDC workload identity, DPoP, cert identity. | app layer | A token says **who**, not **what boundary it runs in**. No runtime-profile claim or policy attestation. |
| **Resource access** | Token, cost and call budgets (`budget_controls`) from **self-reported** usage. Rate limits and circuit breakers. | cooperative / Shield API | No CPU, memory, GPU, pids or wall-clock limits. Budgets trust the agent's own numbers. |
| **Feedback loop** | `POST /v1/tenant/me/siem/ingest`, decision audit, telemetry and ASIM (only the `AuditEvent` schema). | n/a | No normalized runtime event. A sandbox denial never reaches Shield's audit or the xflow session. |
| **Distribution** | `GET /v1/edge/policy-bundle` carries content regexes only, with ETag. | n/a | No runtime bundle and no signature. |

**Main finding:** Shield has strong decisions and a strong network-level screen
for people's AI traffic. For agents, it has no infrastructure policy to hand to
the runtime, and it gets nothing back from it.

## 2. Problem & outcome

**Problem:**
- A security team that adopts OpenShell, Modal or Kubernetes for agents has to
  write every sandbox policy by hand, in each runtime's format.
- Those policies drift from Shield's tool policies.
- Nothing ties "this agent may mint a capability" to "this agent runs inside
  the approved boundary".
- A sandbox that blocks `curl evil.io` or a read of `~/.aws/credentials` tells
  nobody.

**Outcome:** one **Runtime Profile** per class of agent, for example
`coding-agent`, `research-agent` or `support-bot`:

```yaml
profile: research-agent
network:
  default: deny
  allow:
    - {host: api.guardrails.votal.ai, port: 443}      # always added: the Shield gateway
    - {host: "*.googleapis.com", port: 443, methods: [GET]}
    - {host: api.github.com, port: 443}
filesystem:
  read_only: [/usr, /lib, /etc, /bin]
  read_write: [/sandbox, /tmp]
  deny: ["~/.ssh/**", "~/.aws/**", "/var/run/docker.sock", "/proc/*/environ"]
process:
  run_as: sandbox
  allow_binaries: [/usr/bin/python3, /usr/bin/git, /usr/bin/curl]
  deny_commands: ["curl * | sh", "rm -rf /*", "nc *", "ssh *"]
  no_new_privileges: true
tools:
  from_registry: true            # reuse the agent registry's tools and roles; no duplication
identity:
  require_agent_token: true
  max_token_ttl_seconds: 900
  spiffe_id: "spiffe://acme.com/agent/research/*"
resources:
  cpu: "2"
  memory: 4Gi
  gpu: 0
  max_pids: 256
  wall_clock_seconds: 3600
  llm_tokens_per_hour: 200000     # metered at Shield's LLM gateway, not self-reported
```

**Observable success:**

1. `GET .../runtime-profiles/research-agent/export?target=openshell` returns a
   policy that OpenShell accepts. A sandbox created with it:
   - reaches only the allowed hosts;
   - cannot read `~/.aws`;
   - cannot run `nc`.

   This is proven by a live test, like the existing OpenShell doc test.
2. The same profile exported as a K8s `NetworkPolicy` plus `securityContext` and
   limits applies on a kind+Calico cluster, and denies egress to `example.com`.
3. `/v1/shield/tool/check` on `shell_exec {"command": "curl x | sh"}` or on
   `read_file {"path": "~/.aws/credentials"}` is denied by the same profile. No
   LLM is involved, and the result is the same as the kernel's.
4. A sandbox deny event posted to `/v1/shield/runtime/events` appears in the
   decision audit and in ASIM `NetworkSession`/`FileEvent`/`ProcessEvent`
   shape. If it was a read of a classified path, the xflow session now holds
   it, so a later public post is blocked.
5. With attestation on, `cap/mint` from an agent whose token claims profile
   hash `H1` is refused once the profile has moved to `H2`, until the sandbox
   is restarted on `H2`.

**Non-goals:**
- Shield does not run sandboxes, kernels or proxies.
- No new sandbox runtime, and no eBPF agent of our own.
- No kernel-level enforcement on runtimes that lack it: the export says
  plainly what the target cannot express (§5).
- Not replacing the SWG/ICAP screen, which covers people's AI traffic. This
  spec covers agent workloads.
- No CPU/GPU scheduling. Limits are passed to the orchestrator.

## 3. Plane & latency contract

| Component | Plane | Guard path? | Budget |
|---|---|---|---|
| Profile CRUD, validate, export, compilers | admin (and data, for parity with other tenant APIs) | **No.** Off hot path, no guarded-traffic impact. | n/a |
| `GET /v1/edge/runtime-bundle` (signed, ETag) | both | No. Runtimes poll it at boot and every N minutes; a 304 is cheap. | n/a |
| Profile checks inside `/v1/shield/tool/check`, MCP `tools/call`, `cap/mint` | data | **Yes** | CPU only, precompiled like xflow: path globs, a binary set, command patterns. Target ≤ 0.2 ms p99. Zero cost when the agent has no profile. |
| `POST /v1/shield/runtime/check` (decision API for runtime hooks, Envoy `ext_authz`) | data | **Yes**, a new guard endpoint | Deterministic, no LLM. One cached profile lookup. ≤ 2 ms p99. |
| `POST /v1/shield/runtime/events` (deny and audit events) | data | No. Asynchronous: queued, returns 202. | Batch ≤ 500 events, and never blocks the sender. |
| Attestation check in `cap/mint` | data | **Yes** | Compare one token claim with the cached profile hash. Microseconds. |

## 4. Data model

### 4.1 Runtime profile

Stored at Redis key `rtprofile:{tenant_id}:{profile}` as JSON, with no TTL.

- The index is `rtprofile:{tenant_id}:_index`.
- The version is a sha256 of the normalized profile, returned as the bundle
  ETag and the attestation hash.
- Validation is strict, like xflow: unknown fields, bad globs and unsafe
  patterns are all rejected with every error listed.
- Limits:
  - ≤ 100 profiles
  - ≤ 200 entries per list
  - regexes compiled at save time, ≤ 500 characters

A profile is bound to agents by a new registry field, `runtime_profile`
(default none: unchanged behaviour). An agent without a profile gets exactly
today's behaviour.

`tools.from_registry: true` means the tool section is **derived**, never
duplicated. The compiler reads the agent registry's tools and the MCP routes
those tools live on, and emits the matching egress allow entries, for example
the MCP gateway host. This removes the most common drift.

`network.allow` entries may reference **xflow apps** (`{app: github}`), which
expand to that app's MCP route hosts. Destination knowledge then lives in one
place.

### 4.2 Runtime event (ingest)

One normalized shape, whatever the source:

```json
{"source": "openshell|k8s|cilium|falco|squid|envoy|custom",
 "kind": "network|file|process|resource|policy",
 "decision": "deny|allow|audit",
 "agent_id": "...", "agent_instance_id": "...", "session_id": "...",
 "profile": "research-agent", "profile_hash": "sha256:...",
 "detail": {"host": "evil.io", "port": 443} ,
 "at": "2026-09-28T17:00:00Z"}
```

- **Where events go:** into `log_decision` (guardrail `runtime_boundary`) and
  `record_event`. ASIM gains the `NetworkSession`, `FileEvent` and
  `ProcessEvent` schemas beside `AuditEvent`.
- **Tenant:** taken from the authenticated key or agent token, never from the
  event.
- **File reads:** an allowed `file` event on a path the profile marks
  `classified` (optional `filesystem.classified: [{path: "/data/customers/**",
  classification: confidential}]`) calls `xflow.record_call`. Cross-app flow
  rules then cover data read from disk as well as from SaaS APIs.

### 4.3 Attestation claim

This is a backward-compatible optional claim, and old tokens verify unchanged:
- `mint_agent_token` gains an optional `runtime_profile` plus
  `runtime_profile_hash`.
- The broker that starts the sandbox sets them, from the bundle it applied.

## 5. Compilers (the integration surface)

Each compiler is a pure function, `profile -> (artifact, unsupported[])`,
registered by name. Adding a runtime means adding one module plus one test
fixture. `unsupported` lists what the target cannot enforce, so the export
never silently weakens a policy. For example, K8s NetworkPolicy has no HTTP
methods and no file rules.

| Target | Emits | Covers | Order |
|---|---|---|---|
| `openshell` | OpenShell policy YAML (`network_policies`, `filesystem_policy`, `landlock`, `process`, binaries per endpoint) | network, file, process | **1st** (NVIDIA focus; the example is already verified live) |
| `k8s` | `NetworkPolicy` (deny-by-default egress plus allows), Pod `securityContext` (runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation false, seccomp RuntimeDefault), `resources.limits` | network (L3/L4), process (partial), resources | 2nd (the `feat-sandbox-providers` NetworkPolicy builder is reused) |
| `cilium` | `CiliumNetworkPolicy` with FQDN and L7 HTTP rules | network L7 | 3rd |
| `squid` | ACL fragment for the existing SWG (`deploy/swg/squid.conf`) scoped to agent source IPs | network | 3rd (reuses the SWG) |
| `envoy` | `ext_authz` config pointing at `/v1/shield/runtime/check` | network L7 | later |
| `modal` / `e2b` | the provider's egress allowlist parameters | network | later (from the sandbox broker branch) |
| `seccomp` | a seccomp JSON profile for deny-lists of syscalls | process | later |

**Distribution:** `GET /v1/edge/runtime-bundle?profile=X&target=openshell`
- Returns `{artifact, profile_hash, unsupported, signature}` with ETag/304.
- The signature is Ed25519, with a dedicated signer (`SHIELD_RUNTIME_BUNDLE_*`,
  same pattern as `core/approvals.py`), so a sidecar can verify the bundle
  before applying it.
- Auth is a tenant key or agent token.

## 6. API

| Method | Path | Purpose |
|---|---|---|
| GET/PUT/DELETE | `/v1/tenant/me/runtime-profiles/{profile}` | CRUD (writes go through the registry write gate, like xflow) |
| GET | `/v1/tenant/me/runtime-profiles` | list, with hashes and bound agents |
| POST | `/v1/tenant/me/runtime-profiles/validate` | validate without saving |
| GET | `/v1/tenant/me/runtime-profiles/{profile}/export?target=` | artifact plus `unsupported` |
| GET | `/v1/tenant/me/runtime-profiles/templates` | starters: `coding-agent`, `research-agent`, `support-bot` |
| GET | `/v1/edge/runtime-bundle?profile=&target=` | signed bundle for runtimes, ETag |
| POST | `/v1/shield/runtime/check` | `{kind, agent/token, detail}` → `{allowed, rule, reason}`; Envoy `ext_authz` compatible |
| POST | `/v1/shield/runtime/events` | batch ingest, returns 202 |
| GET | `/v1/tenant/me/runtime-profiles/{profile}/drift` | agents or instances seen running a stale `profile_hash` |

**Existing paths, extended only for agents that have a profile:**
- `/v1/shield/tool/check` and MCP `tools/call` add a `runtime_boundary` result
  when the tool's arguments name a path, a command or a URL. The extraction
  rules are declared per tool in the profile, with defaults for common MCP
  filesystem, shell and fetch tools.
- `cap/mint` adds attestation, as an opt-in per profile:
  `identity.require_attestation: true`.

## 7. Security & backward compatibility

- **Default:** nothing changes. No profile means no checks, no claims and no
  events.
  - `SHIELD_RUNTIME_POLICY=off` disables every hook (escape hatch).
  - Attestation is opt-in per profile, and starts in `warn` mode (an audit row
    only) before `enforce`.
- **The runtime is the boundary; Shield is the author.** Shield's own checks are
  a second, earlier layer, not a replacement. The docs say that without a
  runtime that enforces the policy, file, process and network rules are
  cooperative.
- **Bundle integrity:** signed bundles, with a `profile_hash` in the ETag and
  the attestation claim. A tampered bundle fails verification in the reference
  sidecar.
- **Event trust:** events are evidence, not commands. They can **add** session
  state (a classified read) or raise alerts; they can never lift a block or
  delete state. Tenant comes from auth. Ingest is rate-limited per tenant.
- **Command matching:** deny-commands are glob patterns over a
  shell-tokenized, normalized command (`shlex`, with whitespace, quotes and
  `$IFS` tricks normalized).
  - The docs are explicit that a command deny-list is defense in depth, not a
    boundary. `allow_binaries` plus the runtime's exec control is the boundary.
  - The starter profiles lead with allowlists.
- **Path matching:** paths are normalized before matching (`~`, `..`, symlink
  components not resolved server-side, which is documented), and a deny always
  beats an allow.
- **Loosening needs admin:** writes that loosen go through the registry write
  gate, as they do for xflow.

## 8. Packaging & deploy

- **New package `core/runtime_policy/`:**
  - `model.py`: validation and normalization
  - `compilers/`: one module per target
  - `check.py`: the hot-path matcher
  - `events.py`: normalization plus sinks
  - `bundle.py`: signing
- **New routes:** `api/routes_runtime_policy.py` (tenant, both planes) and
  `api/routes_runtime.py` (`check` and `events`, data plane). If admin_app
  imports them, they go in `Dockerfile.admin` COPY, guarded by the existing
  test.
- **Dependencies:** none new. PyYAML is already in `requirements.txt` and
  `requirements-admin.txt`.
- **Env:**
  - `SHIELD_RUNTIME_POLICY`
  - `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` / `_KID`
  - `SHIELD_RUNTIME_EVENTS_MAX_BATCH`
- **Reference integrations** (examples/, not server planes):
  - `examples/runtime/openshell-sync.sh`: pull bundle, verify signature, apply
  - `examples/runtime/openshell-events.py`: tail OpenShell decisions and post
    them to `/events`
  - `examples/runtime/k8s/`: an init-container that fetches the bundle
  - `examples/runtime/envoy/`: `ext_authz` config

## 9. Failure modes

| Case | Behaviour |
|---|---|
| Bundle endpoint unreachable at sandbox boot | The reference sync script fails closed: the sandbox does not start without a verified bundle. There is an `--allow-stale` flag to use the last verified bundle. |
| Profile changed while sandboxes run | New hash. The drift endpoint lists stale instances. Attestation `warn` records it; `enforce` refuses new capabilities until restart. |
| Compiler cannot express a rule | Listed in `unsupported`. The export response and the portal show it. The export fails only if `strict=true`. |
| Event flood | Per-tenant rate limit, then 429. The sampler keeps every deny and samples allows. |
| Redis down | Hot-path checks use the in-process cached profile (TTL 5 s) and fail open with an advisory result, unless `fail_closed` is set on the profile, as in xflow. |
| Unknown tool argument shape | No extraction, so no `runtime_boundary` result. The tool policy still applies. |

## 10. Test plan (Definition of Done)

- **Model:** validation (every error class), normalization idempotence,
  hashing stability.
- **Compilers:** a golden-file test per target over the three starter
  profiles, and an `unsupported` completeness test (every profile field is
  either compiled or listed).
- **OpenShell live test:** opt-in, like the existing doc test. The allowed
  host works; `example.com`, `~/.aws` and `nc` are denied.
- **K8s live test:** opt-in, on kind+Calico (reusing the sandbox-providers
  harness). Egress to `example.com` is denied.
- **Hot-path checks:** path, command and URL extraction for the MCP filesystem,
  shell and fetch tools; normalization evasion cases; no-profile zero-cost
  (no Redis, results identical).
- **Events:** normalization per source; ASIM shape per kind; a classified
  read feeds xflow and a later public post is blocked; events never lift a
  block.
- **Attestation:** stale hash → warn row, then 403 under enforce; old tokens
  without the claim are unchanged.
- **Packaging:** the `Dockerfile.admin` import guard, and the full suite in a
  clean venv.

## 11. Task breakdown

One branch, `feat/infra-guardrails`, per the single-branch preference. Commits
are reviewable per task, and each task is shippable on its own.

| # | Task | Size |
|---|---|---|
| 1 | Runtime profile model, validation, storage, CRUD/validate/templates API, registry `runtime_profile` field | M |
| 2 | OpenShell compiler, export endpoint, signed `runtime-bundle`, `examples/runtime/openshell-sync.sh`, live test; replace the hand-written example with a generated one | M |
| 3 | Hot-path `runtime_boundary` checks in `/tool/check` + MCP (path, command, URL extraction) | M |
| 4 | Event ingest, ASIM Network/File/Process schemas, xflow feed, OpenShell event adapter | M |
| 5 | K8s compiler (NetworkPolicy, securityContext, limits) and kind+Calico test | M |
| 6 | Attestation claim, drift endpoint, `cap/mint` warn/enforce | S |
| 7 | Squid and Cilium compilers; `/runtime/check` + Envoy `ext_authz` example | M |
| 8 | Portal tab (profile editor, export preview with `unsupported`, drift view) and customer docs | M |

Resource metering (`llm_tokens_per_hour` counted at Shield's LLM gateway
instead of self-reported) rides on task 1's model and task 3's hot path. It is
listed in the model now and wired after task 4.

## 12. Decisions for the approver

Recommendations are marked; the spec assumes them unless changed.

1. **First runtime: OpenShell** (recommended). It is NVIDIA's stack, the example
   is already verified live, and it covers network, file and process in one
   artifact. K8s comes second.
2. **Profile granularity: per agent class**, bound through the registry
   (recommended), rather than per agent. That means fewer policies, and drift is
   visible.
3. **Merge the `feat-sandbox-*` broker and executor examples** under
   `examples/runtime/` as part of tasks 2 and 5 (recommended), rather than
   keeping them on separate branches.
