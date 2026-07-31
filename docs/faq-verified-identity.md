# FAQ: verified identity — what Shield proves, and what it doesn't

Written for the questions a security architect asks in the first twenty minutes.
Answers state the current position, not the roadmap. Where a control is
incomplete it says so, with the flag or spec that closes it.

---

### Is `X-User-Role` trusted?

By default, yes — it is a caller assertion, exactly like `user_role` in a
request body. Anything that can reach the API can claim any role.

`SHIELD_ROLE_BINDING` changes that. With `prefer`, a role in a **verified**
credential (OIDC, agent token, mTLS, SPIFFE) wins over the header. The decision
records `role_source`, so an audit entry distinguishes `oidc` from `header`.

Two things to know before relying on it:

- If the verifying provider is misconfigured — issuer mismatch, missing
  audience — verification returns nothing and the header is used. **No error is
  raised.** Test it by sending a request with no credential and a claimed
  privileged role; if it succeeds, binding is not enforcing.
- `strict` does not currently reject a header-derived role. There is no mode
  today meaning *"self-asserted roles are refused"*. That gap is tracked; until
  it lands, treat `prefer` as "prefer when available", not "require".

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

Just the user's, on the default path. The agent presents a bearer agent token;
possession is the proof. Anything holding that token is that agent.

mTLS and SPIFFE providers exist and bind identity to a workload rather than a
secret. Neither is in the default provider chain — enable them explicitly. If
an architect asks "what proves *which process* is calling", this is the honest
answer, and it is a deployment decision rather than a missing feature.

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

Three checks, in order:

1. **No credential, privileged role.** Send `X-User-Role: <privileged>` with no
   bearer. If it is allowed, role binding is not enforcing on your deployment.
2. **Cross-identity mint.** Present a valid user credential and a different
   `user_sub`. It must 403.
3. **Replay.** Mint a capability, use it, present it again. The second must
   fail with a replay error — that also proves the nonce store is shared across
   workers rather than per-process.

`examples/cap_flow_demo.py` runs 2 and 3 and prints the reason for each
refusal. A refusal for the wrong reason is reported as a failure, because a
control that refuses for an unrelated reason is not the control you tested.
