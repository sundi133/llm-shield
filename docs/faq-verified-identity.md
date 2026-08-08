# FAQ: verified identity — what Shield proves, and what it doesn't

Written for the questions a security architect asks in the first twenty minutes.
Answers state the current position, not the roadmap. Where a control is
incomplete it says so, with the flag or spec that closes it.

---

### Do I have to replace my identity provider?

No. Shield authenticates nobody.

It is a **credential service**, not an identity provider. Keep Okta, Entra,
Keycloak or Auth0 for your people and SPIFFE or mTLS for your workloads. Shield
consumes both and derives a short-lived credential from them:

```
your IdP        -> which human           ─┐
SPIFFE / mTLS   -> which workload        ─┼─> Shield -> agent token -> capability
Shield registry -> which agent, which tools ─┘
```

There is no user store, no login flow, no MFA, no SCIM. Nothing about your
existing identity estate moves.

### Why isn't our existing workload identity enough?

Because workload identity answers one question and agent authorization needs
seven. SPIFFE, mTLS and Kubernetes ServiceAccount tokens were designed to say
*which service is calling*. That is necessary and it is not sufficient.

| Question | Workload identity | Shield agent token |
|---|---|---|
| Which service? | yes | `agent_id` |
| Which process? | roughly (the pod) | `agent_instance_id` |
| Which **build** of the agent? | no | `build_hash` |
| Which **model version**? | no | `model_version` |
| Acting for **which human**? | no | `user_sub` |
| **Delegated by** which agent? | no | `parent_agent_id`, `delegation_depth` |
| Which **task or session**? | no | `session_id` |

Four consequences, in practice:

- **Same code, different behaviour.** A service with fixed code behaves the
  same tomorrow. An agent with the same code and new model weights does not.
  Identity that stops at "which binary" cannot tell you whether an incident came
  from the code or the model, so `model_version` is part of the credential.
- **Delegation is native, not bolted on.** Services call services as themselves.
  Agents act *on behalf of* a human and spawn sub-agents. Authorization is the
  **intersection** — the agent's grant AND the user's role — so neither can
  exceed its own.
- **Lifetime.** A workload identity lives as long as the pod, in hours or days.
  An agent's authority should live as long as the task. Agent tokens are capped
  at 15 minutes and each action gets its own single-use capability.
- **Revocation granularity.** Revoking workload identity means killing the pod.
  Shield revokes one agent instance or one leaked token without touching the
  deployment.

If you already run SPIRE or issue service-account tokens, Shield verifies those
rather than asking you to adopt a second system. Set
`SHIELD_WORKLOAD_IDENTITY_PROVIDERS` to the ones you have.

### What identity does Shield actually accept?

Four levels. Most deployments run at level 2.

| Level | What it is | What it proves |
|---|---|---|
| 1 | `X-Agent-Key` header | Nothing — a claimed string. Useful for discovering unregistered agents, not for authorization |
| 2 | Shield-issued agent token | Ed25519-signed, ≤15 min, carries the full claim set above. Holding it is the proof |
| 3 | Level 2 bound to a keypair | Holding the token is **not** enough — see the possession question below |
| 4 | SPIFFE SVID, mTLS cert, OIDC service account | Verified against your existing infrastructure; Shield issues nothing |

Above all of it sits the **agent registry**: agents are registered per tenant
with the tools they may call. In managed mode an unregistered agent cannot get a
token at all. Tenants with no registry stay permissive so you can bootstrap.

### Is `X-User-Role` trusted?

By default, yes — it is a caller assertion, exactly like `user_role` in a
request body. Anything that can reach the API can claim any role.

`SHIELD_ROLE_BINDING` changes that. There are four modes:

| mode | verified claim present | no verified claim |
|---|---|---|
| `off` (default) | header wins | header wins |
| `prefer` | claim wins, header ignored | header wins |
| `strict` | claim wins, header ignored | **no role** |
| `strict_proxy` | claim wins, header ignored | header accepted **only** from the trusted proxy |

The decision records `role_source`, so an audit entry distinguishes `oidc` from
`header` from `proxy`.

Three things to know before relying on it:

- **`prefer` does not close the forgery.** It only upgrades callers that
  *present* a credential. A caller that presents none and sends
  `X-User-Role: admin` still gets `admin`, because there is no verified claim to
  prefer. On a publicly reachable deployment, `prefer` is not a control.
- If the verifying provider is misconfigured — issuer mismatch, missing
  audience — verification returns nothing. Under `prefer` the header is then
  used and **no error is raised**. Test it by sending a request with no
  credential and a claimed privileged role; if it succeeds, binding is not
  enforcing.
- `strict_proxy` accepts a self-asserted role only from a peer that presents
  `X-Shield-Proxy-Token`. It is recorded as `role_source: proxy` and
  `role_verified: false` — the proxy vouched for the hop, it did not prove the
  user's credential to Shield. See
  [the role-binding runbook](role-binding-runbook.md).

### Can a caller mint an agent token naming someone else?

Not when a verified user credential is present. `user_sub` is checked against
the subject of that credential and a mismatch is refused:

```
403 user_sub 'ceo@example.com' does not match the verified subject 'user-abc'
```

When **no** user credential is presented, `user_sub` is still caller-supplied.
This control closes *"the claim contradicts the proof"*, not *"there is no
proof"*. Requiring proof is role binding's job, above.

### Can one tenant mint credentials for another?

No. A tenant API key authorizes issuance for the tenant it resolves to and no
other; the body's `tenant_id` must match, and an empty value is treated as a
mismatch rather than consent. The check binds to the **resolved** tenant, never
the requested one.

Operator admin keys are deliberately not tenant-bound — that is what makes them
operator credentials. Do not distribute them to tenants; use the `tenant_key`
provider instead.

### Does a capability token prove who authorized the action?

It proves a decision was made, by whom it was **claimed**, and exactly what was
permitted: one tool, one resource, one agent instance, a short TTL, single use.
The signature is real and replay is rejected.

It does **not** yet record how the identity in it was established. A capability
minted over a header-claimed role is byte-indistinguishable from one minted
over a verified OIDC claim. If your threat model needs that distinction — and
for a non-repudiation argument it does — it is not there today. Carrying
`role_source` / `identity_method` / `trust_level` into the cap claims is the
planned fix.

Read a capability as *"this decision was made under these constraints"*, not
*"this person was proven to be who they said"*.

### What stops an agent skipping Shield entirely?

At `tool/check`, nothing — it is advisory. Shield answers allow/deny and the
client chooses to honour it. That is appropriate for guardrail screening and
insufficient for authorization.

The capability path is the enforcing one: the tool server refuses to act
without a valid, unburned capability, so skipping Shield means the tool does
not run. Use it for actions that matter.

### Is the agent's own identity verified, or just the user's?

Both, but the agent's identity is a **bearer** token by default: the agent token
is signed by Shield and cannot be forged, yet anything *holding* it is that
agent. A copy in a log file, crash dump, or proxy access log works until it
expires.

Three ways to close that, none of them on by default:

- **`SHIELD_AGENT_TOKEN_POP`** binds the token to a keypair. See below.
- **mTLS / SPIFFE** bind identity to a workload rather than a secret. Neither is
  in the default provider chain — enable explicitly.

### Can a stolen agent token be used by someone else?

By default, yes, for up to 15 minutes. That lifetime is a mitigation, not a
control.

With `SHIELD_AGENT_TOKEN_POP=required` it cannot. The agent generates a keypair,
sends Shield only the **public** half at mint, and signs a proof on every
request with the private half. Shield stores no keys — the thumbprint travels
inside the signed token. The proof also covers the method and URI being called,
so a captured proof cannot be replayed or redirected.

Two limits, stated plainly because you will be asked:

- **It does not contain a compromised agent.** An attacker with code execution
  inside the agent process has the private key. This binds a credential to a
  key, not to a machine or a person.
- **It cannot work behind an LLM gateway.** The proof covers the URL being
  called; the agent signs for the gateway's URL and Shield receives its own.
  There is no configuration that fixes this — it is the mechanism. On that path
  the gateway authenticates itself instead and the audit records
  `pop_verified: false`, so a vouched request stays distinguishable from a
  proven one.

`cap/mint` and `tools/call` — the endpoints that actually authorize an action —
are direct paths, so the guarantee holds where it matters. The accurate claim:

> On paths where the agent calls Shield directly, a stolen agent token is
> useless without the agent's private key.

`examples/langchain/agent_token_theft_demo.py` runs it: the thief holds the
complete token every time, and every attempt is refused for a different reason.

### Can an agent delegate its way around its own permissions?

By default the delegation record is not trustworthy: `parent_agent_id` is
whatever the caller put in the request body, and Shield signs it. Nothing
verifies the named parent exists or delegated anything. No authorization
decision reads it, so the impact is a poisoned audit trail rather than an
escalation — but that still matters if you rely on the audit.

`SHIELD_DELEGATION_PARENT_PROOF=required` derives the parent from a verified
parent token the caller must present, and refuses a parent belonging to a
different tenant. `SHIELD_MAX_DELEGATION_DEPTH` then bounds the chain, enforced
both when a token is minted and when it is verified, so lowering the limit takes
effect immediately.

The order matters: a depth limit **without** parent proof bounds nothing,
because the depth is computed from the parent the caller named. Shield logs a
warning at boot if you configure it that way.

Known limit: revoking a parent does not revoke its children. A child stays valid
until its own expiry, capped at 15 minutes. Cascading revocation would need a
lookup on every guarded request; the short lifetime is the mitigation instead.

`examples/langchain/delegation_chain_demo.py` shows the refusals.

### Are policies deterministic?

Partly. RBAC (role → tool, role → data) is deterministic and reads from the
agent registry — the matrix in the portal is what is enforced.

Custom policies and payload/data policies are **natural-language rules
evaluated by an LLM**. That is flexible and it is not auditable in the way a
rule engine is: an evaluation can reach a conclusion no configured rule states.
Use deterministic RBAC for anything that must be certain, and treat LLM policy
as defence in depth on top.

### What is the latency cost?

Measured against a deployed data plane: input guardrails 4–17s, tool
authorization 1–6s, capability mint ~1.3s, verify ~0.9s. A tool call on the
enforcing path is therefore several seconds on top of model latency.

This is the most common reason a pilot stalls. Budget for it, measure your own
numbers, and decide per tool whether the capability path is warranted.

### How do I verify any of this myself, rather than take it on trust?

Five checks, in order. Run them against your deployment, not a local instance.

1. **No credential, privileged role.** Send `X-User-Role: <privileged>` with no
   bearer. If it is allowed, role binding is not enforcing on your deployment.
2. **Cross-identity mint.** Present a valid user credential and a different
   `user_sub`. It must 403.
3. **Replay.** Mint a capability, use it, present it again. The second must
   fail with a replay error — that also proves the nonce store is shared across
   workers rather than per-process.
4. **Token theft.** Copy an agent token to a second process without the private
   key and repeat a call. Under `SHIELD_AGENT_TOKEN_POP=required` it must 401.
5. **Chain depth.** Mint a delegation chain one hop past
   `SHIELD_MAX_DELEGATION_DEPTH`. It must 403.

`examples/cap_flow_demo.py` runs 2 and 3,
`examples/langchain/agent_token_theft_demo.py` runs 4, and
`examples/langchain/delegation_chain_demo.py` runs 5. Each prints the reason for
every refusal. A refusal for the wrong reason is reported as a failure, because
a control that refuses for an unrelated reason is not the control you tested.

### Which of these are on by default?

**None of the hardening.** Shield ships permissive so an install does not break,
which means an unconfigured deployment proves considerably less than this page
might suggest.

| Control | Env | Default |
|---|---|---|
| Role binding | `SHIELD_ROLE_BINDING` | `off` |
| Delegated user | `SHIELD_DELEGATION` | `off` |
| Agent-token possession | `SHIELD_AGENT_TOKEN_POP` | `off` |
| Proven delegation parent | `SHIELD_DELEGATION_PARENT_PROOF` | `off` |
| Chain depth limit | `SHIELD_MAX_DELEGATION_DEPTH` | unlimited |
| Workload token binding | `SHIELD_TOKEN_BINDING` | `off` |
| Trusted-proxy boundary | `SHIELD_TRUSTED_PROXY_ONLY` | `off` |
| Identity providers | `SHIELD_WORKLOAD_IDENTITY_PROVIDERS` | `admin_key,spiffe` |

Note the last row: **`oidc_sa` is not in the default chain**, so a Keycloak or
Okta bearer token is not verified until you add it.

Turn them on in the order given in
[the role-binding runbook](role-binding-runbook.md) — several interact, and two
combinations fail closed in ways that look like a broken feature rather than a
missing setting.
