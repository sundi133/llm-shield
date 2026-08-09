---
title: "Spec: Shield Identity Bundle"
layout: default
permalink: /spec-shield-identity-bundle/
---

# Spec: Shield Identity Bundle (embedded SPIRE + agent governance)

Status: **DRAFT — awaiting approval.** No code written.

## 1. Problem & outcome

On-prem customers who want strong agent identity face a three-way assembly job:
stand up a workload-identity issuer (SPIRE), buy/operate a non-human-identity
product (Aembit/Astrix) for the agent layer, and separately bolt on runtime
guardrails. Nobody ships the **combination** as one on-prem install.

Shield already owns the differentiated half — **agent-scoped identity binding
(`build_hash`/`model_version`/`session`), capability minting per tool call,
runtime guardrails, tool RBAC, tamper-evident audit** (`core/agent_tokens.py`,
`core/capabilities.py`, the guardrail pipelines). What it lacks is a turnkey
**issuer/attestation core** for on-prem — the piece SPIRE already does well.

**Outcome:** an **opt-in Shield Identity Bundle** that packages a proven issuer
(**SPIRE**, embedded) with Shield's agent-governance behind one install
(compose profile / Helm subchart). A partner enables it and gets:
attested workload identity → Shield agent token → capability minting → guarded
tool calls, end to end, on-prem, with **no third-party NHI product and no
hand-rolled CA.**

The moat is the **integration + the governance layer**, delivered as one
package. Shield **consumes** SPIRE identity via the modular provider layer
([spec-modular-workload-identity.md](/spec-modular-workload-identity/)); it does
**not** reimplement attestation or PKI.

### Non-goals
- **Not building an issuer/CA/attestation authority.** SPIRE provides it; we
  embed and integrate, never reinvent. (Rolling our own is precisely how critical
  security functionality gets missed — cf. the forgeable X.509 check, `task_02d25da6`.)
- Not replacing cloud IAM or a customer's existing SPIRE — if they have one, the
  bundle federates to / points at it instead of running its own.
- Not on the guard path; no new latency to `/guardrails/*`, `cap/mint`, `tools/call`.
- Not default-on. Existing deploys are unchanged unless the profile is enabled.

## 1a. Critical-functionality coverage matrix (the "nothing missing" check)

Every load-bearing function of a workload/agent identity system, and who owns it.
**Bold = the differentiated layer Shield owns.**

| # | Function | Owner | Verified by |
|---|---|---|---|
| 1 | Trust domain + SPIFFE naming | SPIRE | bundle boot test |
| 2 | Root/intermediate CA + key mgmt, rotation | SPIRE (+ optional HSM/KMS) | SPIRE health + rotation test |
| 3 | Node attestation (join_token, k8s PSAT, x509pop, cloud IID) | SPIRE | attestation e2e |
| 4 | Workload attestation (uid/path/sha, pod, docker) | SPIRE | attestation e2e |
| 5 | SVID issuance (X.509 + JWT) | SPIRE | SVID fetch test |
| 6 | Short TTL + automatic SVID/key rotation | SPIRE | rotation test |
| 7 | Workload API (local socket; no secrets on disk) | SPIRE Agent | socket fetch test |
| 8 | **Real** SVID cryptographic verification | **Envoy mTLS front door** (not the name-only in-Shield check) | forged-cert rejection test |
| 9 | Trust-bundle distribution + rotation to consumers | SPIRE + Envoy SDS | bundle refresh test |
| 10 | Revocation (workload/node) | SPIRE (entry delete) + **Shield token/auto-revoke** | revoke e2e |
| 11 | Federation (cross-cluster/domain) | SPIRE federation | documented + optional test |
| 12 | Registration entries / selectors | SPIRE (+ Controller Manager on k8s) | registration test |
| 13 | HA datastore + DR | SPIRE (Postgres) | ops doc |
| 14 | Issuance/attestation audit | SPIRE + **Shield tamper-evident audit** | audit chain test |
| 15 | **Identity → Shield agent token exchange** | **Shield** (modular provider) | provider tests |
| 16 | **Agent binding: build_hash / model_version / session** | **Shield** `agent_tokens` | existing tests |
| 17 | **Capability minting per tool call** | **Shield** `capabilities` | existing tests |
| 18 | **Runtime guardrails + tool RBAC on the identity** | **Shield** pipelines | existing tests |
| 19 | Human-on-behalf (`user_sub`) binding | **Shield** (+ OIDC) | existing tests |

Rows 1–14 are commodity/hard → **SPIRE + Envoy**. Rows 15–19 are the moat →
**Shield, already built.** The bundle is the wiring between them.

## 2. Plane & latency contract

- **Plane:** the bundle is **infrastructure packaging** (new containers:
  spire-server, spire-agent, an Envoy front door) plus **data-plane** consumption
  via the modular provider. **No admin-plane change → no `Dockerfile.admin` impact.**
- **Guard path:** identity resolution + SVID→token exchange happens **only at
  token issuance** (`/v1/shield/auth/agent-token`), per-process. **Not** on
  `/guardrails/*`, `cap/mint`, `tools/call`. SPIRE/Envoy run as separate
  processes/containers — **zero added latency to the core guardrail image.**

## 3. Data model

- **No new Shield Redis state.** SPIRE owns its own datastore (SQLite dev /
  Postgres prod) — outside Shield's Redis, its own volume.
- Shield consumes the identity via `request.state` (provider layer); no persisted
  Shield state beyond the existing agent-token/cap stores.
- Config surfaces (env / values file), not Redis:
  `SHIELD_WORKLOAD_IDENTITY_PROVIDERS=spiffe,mtls`, `SHIELD_SPIFFE_TRUST_DOMAIN`,
  `SHIELD_SPIFFE_TRUST_BUNDLE`, plus SPIRE server/agent config and Envoy config
  shipped in the bundle.

## 4. API / interface

**No new public Shield endpoints.** This is packaging + integration. Surfaces:

### The bundle (opt-in deployment artifact)
- **Compose:** a `identity` profile in `deploy/identity/docker-compose.identity.yml`
  adding `spire-server`, `spire-agent`, `envoy` (mTLS front door pre-wired to the
  guardrail server). Enabled via `docker compose --profile identity up`.
- **Helm:** an `identity` subchart (`deploy/helm/shield/charts/identity/`), gated
  by `identity.enabled=false` (default). Includes SPIRE + the SPIRE Controller
  Manager for auto-registration, and Envoy as the Shield ingress when enabled.

### The flow (all existing endpoints)
```
agent workload
  └─ fetch SVID from SPIRE Workload API socket        (SPIRE)
  └─ mTLS to Shield ingress presenting the SVID       (Envoy verifies vs trust bundle)
      Envoy injects X-Forwarded-Client-Cert            (real crypto here)
  └─ POST /v1/shield/auth/agent-token                  (Shield `spiffe`/`mtls` provider
                                                         accepts the XFCC identity)
      → agent_token (bound to build_hash/model/session)
  └─ POST /v1/shield/cap/mint  per tool call           (Shield)
  └─ guarded tool calls / /v1/chat/completions         (Shield guardrails + RBAC)
```

### New helper (agent side, optional dep)
`sdk/spiffe_helper.py` (or `examples/`) — fetch the SVID from the Workload API
socket via `py-spiffe`, present it, exchange for an agent token, mint caps.
Builds on `examples/langchain/spiffe_guarded_e2e.py`.

## 5. Security & backward compatibility

- **Opt-in, default off.** No profile → no SPIRE, no Envoy, behavior identical to
  today. Non-breaking.
- **Envoy does the real cryptographic verification** of the SVID chain against
  SPIRE's trust bundle, then injects `X-Forwarded-Client-Cert`. This **mitigates
  the forgeable in-Shield X.509 check** (`task_02d25da6`) for the bundle: Shield
  trusts only Envoy-injected XFCC.
  - **Hard requirement:** the network must ensure **only Envoy can reach the
    guardrail server**, and Shield must **strip/ignore client-supplied XFCC**
    (accept it only from the trusted proxy). Documented + enforced in the bundle's
    network policy. Without this, a client sets XFCC directly and bypasses mTLS.
  - The in-Shield X.509 fix (`task_02d25da6`) remains a **prerequisite for the
    "Shield validates SVID directly, no Envoy" mode** — that mode is not shipped
    until the fix lands.
- **Revocation is two-layer:** SPIRE entry delete (stops new SVIDs) + Shield
  token/auto-revoke (kills live agent tokens/caps immediately).
- **No secret on disk:** SVIDs come from the Workload API socket, auto-rotated.
- **Trust levels** recorded per issuance (from the provider layer) so policy can
  require attested identity for high-risk tools.

## 6. Packaging & deploy

- **New containers, NOT new pip deps in the core image:** `spire-server`,
  `spire-agent`, `envoyproxy/envoy` are upstream images referenced by the bundle.
  **The core guardrail image gains nothing** → no `requirements.txt` bloat, no
  `Dockerfile.admin` change.
- **Optional agent-side dep:** `py-spiffe` for the SDK helper goes in an **extras**
  group (`requirements-spiffe.txt` / `pip install shield[spiffe]`), never in the
  core runtime requirements. Only agents using the Workload API need it.
- **New files:** `deploy/identity/` (compose + SPIRE + Envoy config),
  `deploy/helm/shield/charts/identity/`, `docs/identity-bundle.md`,
  `scripts/smoke_identity_bundle.sh`. Self-contained.
- **Depends on:** the modular-workload-identity providers landing first
  (`spiffe`/`mtls` providers) — that PR is the prerequisite.
- **Rebuild:** none of the core images change; the bundle ships config + upstream
  images. (If a helper is added to the Shield image later, that PR updates the
  relevant Dockerfile + import test.)

## 7. Failure modes & edge cases

- **SPIRE server down** → no new SVIDs issued; existing SVIDs work until TTL;
  agent-token issuance fails closed (403) once SVIDs expire. Documented HA setup
  (3 servers + Postgres) mitigates.
- **Envoy misconfig / bypass** → covered by the network-policy requirement (§5);
  a smoke test asserts a direct-to-Shield request (no Envoy) is refused.
- **Forged / self-signed SVID** → rejected at Envoy (real chain verification);
  smoke test #forged asserts rejection.
- **Trust bundle stale** (SPIRE rotated CA) → Envoy SDS / spiffe-helper refresh;
  test asserts post-rotation SVIDs still verify.
- **Clock skew / expired SVID** → Envoy rejects; short TTL bounds exposure.
- **Customer already runs SPIRE** → bundle federates to their trust domain instead
  of running its own server (config flag); don't double-run.
- **Profile disabled** → nothing new runs; core unaffected (regression).
- **Revocation race** → SPIRE delete + Shield auto-revoke both fire; Shield side is
  authoritative for live tokens.

## 8. Test plan (Definition of Done)

`scripts/smoke_identity_bundle.sh` + `tests/test_identity_bundle.py` (compose-based
where feasible, mocked where not):
1. **Bundle boots**: spire-server, spire-agent, envoy, shield all healthy.
2. **Attestation e2e**: a registered workload fetches an SVID from the Workload API.
3. **Token exchange**: SVID → mTLS → Envoy XFCC → `/auth/agent-token` returns a
   token bound to the workload's SPIFFE id.
4. **Forged cert rejected** at Envoy (self-signed / wrong CA) — the security-critical check.
5. **Direct-to-Shield refused**: a request bypassing Envoy (no XFCC, or client-set
   XFCC) does not get a token (network + strip-header enforcement).
6. **Full chain**: token → `/cap/mint` → guarded tool call allowed; a forbidden
   tool blocked by RBAC (reuses `spiffe_guarded_e2e.py`).
7. **Rotation**: after SVID rotation, a fresh SVID still exchanges successfully.
8. **Revocation**: SPIRE entry delete + Shield revoke → subsequent issuance denied.
9. **Profile-off regression**: with `identity.enabled=false`, the core suite passes
   unchanged and no SPIRE/Envoy runs.

Green in a clean venv for the Python tests; CI `pytest` gate passes; the
compose-based smoke runs in CI as a separate job (or documented manual gate if CI
can't run nested containers).

## Invariant risk flags
- ✅ Off the hot path — identity only at token issuance; SPIRE/Envoy are separate containers.
- ✅ No core pip deps / no admin import → no `Dockerfile.admin` drift. `py-spiffe` is agent-side extras only.
- ✅ Opt-in, default off → non-breaking.
- ⚠️ **Network policy is load-bearing:** only-Envoy-reaches-Shield + strip client XFCC. Without it the mTLS gate is bypassable. Enforced in the bundle + smoke test #5.
- ⚠️ **Prerequisite:** modular-workload-identity providers must land first. The direct-SVID-in-Shield mode also needs the X.509 fix (`task_02d25da6`); the Envoy mode does not.

## Dependencies & sequence
1. **(prereq)** Modular workload-identity providers — [spec-modular-workload-identity.md](/spec-modular-workload-identity/) PR 1.
2. **(prereq, for direct mode only)** X.509 validation fix — `task_02d25da6`.

## Proposed task breakdown (PRs)
- **PR 1 — Compose bundle:** `deploy/identity/` with spire-server + spire-agent +
  Envoy front door pre-wired to the guardrail server; `docs/identity-bundle.md`;
  `scripts/smoke_identity_bundle.sh` (tests #1-6). The core "one-stop" install.
- **PR 2 — Agent SDK helper:** `py-spiffe`-based SVID fetch → token → cap helper
  (extras dep) + a LangChain e2e that runs fully on the bundle (no cloud). Test #7.
- **PR 3 — Helm subchart:** `identity.enabled` k8s deployment with SPIRE +
  Controller Manager (auto-registration) + Envoy ingress. Tests #8-9.
- **PR 4 — Federation mode:** point-at-existing-SPIRE / cross-cluster federation
  config for customers who already run SPIRE.

## Open decisions for approver
1. **Ingress choice** — Envoy (recommended: SPIRE has first-class Envoy SDS) vs
   nginx/other for mTLS + XFCC?
2. **Default trust domain naming** — `spiffe://<tenant>.shield.local/...` vs a
   customer-supplied domain in values?
3. **Ship the "Shield validates SVID directly (no Envoy)" mode at all**, or
   Envoy-only until `task_02d25da6` lands? (Recommended: Envoy-only first.)
4. **PR 1 scope** — compose-only first (recommended), or compose+Helm together?
