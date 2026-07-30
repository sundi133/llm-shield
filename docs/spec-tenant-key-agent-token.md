# Spec: tenants issue their own agent tokens

## 1. Problem & outcome

`POST /v1/shield/auth/agent-token` is gated by the workload-identity chain,
whose default is `admin_key,spiffe`. In a deployment without SPIFFE that means
`SHIELD_ADMIN_KEY` — **one platform-wide operator secret** — is the only way an
agent can get an identity token.

So a tenant that wants to run agents must be handed the operator's master key.
That key is not tenant-scoped: it authorizes issuance for *every* tenant, plus
whatever else it gates. Distributing it to tenants is a worse outcome than the
one it protects against, and it does not scale past the first customer.

Meanwhile the tenant already holds a credential that identifies it precisely:
its API key, which `resolve_tenant_by_api_key` maps to exactly one `tenant_id`.
`cap/mint` already treats that key as authoritative — it cross-checks the agent
token's tenant against it and refuses a mismatch. Issuance is the one step that
does not accept it.

**Outcome.** A tenant can mint agent tokens for **its own tenant** with its own
API key, and for no other tenant, without any operator secret.

**Non-goals.**
- Changing what an agent token authorizes once issued.
- Per-agent or per-user credentials — the key identifies a tenant, not a human.
  Binding a real person to the token is what the OIDC path (`oidc_sa`) is for,
  and the two compose: a signed user token AND a tenant key can both be present.
- Replacing `admin_key`. Operators keep it; this adds a tenant-scoped peer.

## 2. Plane & latency contract

Data plane. `/auth/agent-token` is on the guard path.

One Redis lookup (`resolve_tenant_by_api_key`) on the issuance path, and only
when the provider is enabled and an `X-API-Key` is present. `cap/mint` and
`tools/call` are untouched — no new work per guarded call, since an agent token
is minted once per process, not once per request.

## 3. Data model

No new keys. Reuses the existing API-key → tenant mapping.

Tenant scoping is the whole point: the resolved tenant is carried on the
`WorkloadIdentity` and the route refuses any request whose body claims a
different `tenant_id`. Cross-tenant issuance is therefore impossible with a
tenant key, however the body is crafted.

## 4. API / interface

`POST /v1/shield/auth/agent-token` — unchanged request and response. A tenant
may now authorize it with `X-API-Key` when the `tenant_key` provider is enabled.

New provider name `tenant_key` for `SHIELD_WORKLOAD_IDENTITY_PROVIDERS`, e.g.
`admin_key,tenant_key,oidc_sa`. Trust level `medium` — a shared bearer secret,
the same class as `admin_key`, weaker than mTLS or a signed OIDC assertion.

New failure: `403 tenant key authorizes tenant '<a>', not '<b>'` when the body
asks for a tenant the key does not own.

## 5. Security & backward compatibility

**Not in the default chain.** The default stays `admin_key,spiffe`. Enabling
this widens who can mint agent tokens, so it is an operator's explicit decision
— an existing deployment behaves identically until it opts in.

What a tenant key can do: mint agent tokens for its own tenant. That is already
implied by holding the key, which authorizes guarded traffic for that tenant.

What it cannot do: mint for another tenant (the route rejects the mismatch),
or reach anything else `admin_key` gates — this provider is only consulted by
the workload-identity chain, and a `tenant_key` identity is distinguishable
from an `admin_key` one by `provider`, so a future endpoint can require the
stronger of the two.

A stolen tenant key is already a tenant compromise; the blast radius does not
widen, because the tenant boundary is enforced on the resolved tenant rather
than the claimed one. The failure to avoid is trusting the *body's* tenant_id,
which is why the check binds to the resolved value and not the request.

`_require_registered_agent` still applies, so a tenant in managed mode can only
issue for agents it has registered.

## 6. Packaging & deploy

Provider lives in the existing `core/workload_identity/providers.py` and is
registered in `registry.py` — no new module, so no `Dockerfile.admin` change.
The route already imports the registry.

No new pip dependencies. Rollout is one env var on the data plane:
`SHIELD_WORKLOAD_IDENTITY_PROVIDERS=admin_key,tenant_key,oidc_sa`.

## 7. Failure modes & edge cases

- **No `X-API-Key`** → provider returns None, chain continues.
- **Key does not resolve** (revoked, typo, wrong environment) → None, chain
  continues; the caller gets the chain's 403 naming what was tried.
- **Redis down** → `resolve_tenant_by_api_key` raises or returns None → None.
  Fail closed: an unresolvable key must not authorize anything.
- **Body `tenant_id` differs from the key's tenant** → 403 naming both, so the
  mismatch is legible rather than looking like a bad key.
- **Body `tenant_id` empty** → treated as a mismatch, not as consent. Silently
  substituting the resolved tenant would let a caller stay vague and get a
  token for whatever the key happened to own.
- **Both `X-Admin-Key` and `X-API-Key` present** → chain order decides;
  `admin_key` first keeps operator behaviour unchanged and is not
  tenant-bound.

Fail-closed throughout: every ambiguous case yields no identity rather than a
guessed one.

## 8. Test plan (Definition of Done)

- Provider disabled → tenant key is ignored (default behaviour preserved).
- Enabled, valid key, matching `tenant_id` → 200, token issued.
- Enabled, valid key, **different** `tenant_id` → 403, message names both.
- Enabled, valid key, empty `tenant_id` → 403.
- Enabled, unresolvable key → 403 from the chain, not a 500.
- Resolution raising (Redis down) → 403, not a 500.
- The issued identity records `provider="tenant_key"` for audit.
- `admin_key` path unchanged when both credentials are present.
- Full suite green in a clean venv; CI `pytest` gate passes.
