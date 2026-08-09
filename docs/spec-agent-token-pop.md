---
title: "Spec: proof-of-possession for agent tokens"
layout: default
nav_order: 41
permalink: /spec-agent-token-pop/
description: "Shield issues agent tokens with no cnf claim, so a stolen agent token works for whoever holds it. The DPoP machinery to fix this already exists and is applied to external IdP tokens but never to Shield's own credential."
---

# Spec: proof-of-possession for agent tokens
{: .no_toc }

`grep -c cnf core/agent_tokens.py` returns 0. Shield's own agent credential is a
bearer token: copy it and it works. `core/dpop.py` already implements everything
needed to fix that, and `core/identity_resolution.py` already uses it — on
somebody else's tokens.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

`mint_agent_token()` ([agent_tokens.py:153](../core/agent_tokens.py)) emits
claims `iss, aud, user_sub, agent_id, agent_instance_id, parent_agent_id,
tenant_id, build_hash, model_version, session_id, roles, iat, exp, jti, kid`.
There is no `cnf`. `verify_agent_token()`
([agent_tokens.py:214](../core/agent_tokens.py)) checks signature, expiry,
required claims, build allowlist and revocation — but there is nothing binding
the token to a key, so there is nothing to check possession against.

`AgentIdentityMiddleware` ([agent_identity_middleware.py:47](../core/agent_identity_middleware.py))
therefore grants full agent identity to anyone presenting the string.

The asymmetry is the striking part. `core/dpop.py` is a complete DPoP
implementation — `jwk_thumbprint`, `verify_proof`, `cnf_jkt`, `claim_jti` replay
protection, private-key-member rejection, an 8 KiB proof ceiling and a 30 s age
window. `core/identity_resolution.py:88` uses all of it, via
`SHIELD_TOKEN_BINDING`, against **workload-identity tokens from external IdPs**.
Shield binds other people's credentials and not its own.

The module docstring at [agent_tokens.py:38](../core/agent_tokens.py) names the
current mitigation: "≤15 minute lifetime caps the window of a stolen token." A
15-minute window is a mitigation, not a control.

**Outcome.** An agent token carries `cnf: {"jkt": ...}` bound to a keypair the
agent holds, and a request presenting that token must carry a DPoP proof signed
by the matching private key. Observable success condition: a token copied
verbatim to a second process, without the private key, is refused with 401.

### Non-goals
- **Not** RFC 9421 HTTP Message Signatures (what AAuth specifies). DPoP achieves
  the same property, is already implemented here, and is already understood by
  the OAuth ecosystem. Adopting 9421 is an interop decision, not a security one,
  and belongs in a conformance spec if it happens at all.
- **Not** a change to `SHIELD_TOKEN_BINDING`. That flag governs external IdP
  tokens and keeps its exact current meaning. §4 explains why these stay
  separate rather than merging.
- **Not** capability-token binding. `core/capabilities.py` has its own signer,
  audience and nonce namespace by design; binding caps is a follow-on with a
  different latency argument (`cap/mint` is hotter).
- **Not** key management. Where the agent's private key lives — process memory,
  file, TPM, KMS — is the deployer's decision. Shield only ever sees the public
  JWK.
- **Not** mTLS-derived identity. The `mtls_identity` fallback at
  [agent_identity_middleware.py:30](../core/agent_identity_middleware.py) is
  already channel-bound by a client certificate and does not need a second
  possession proof.

## 2. Plane & latency contract

**Planes: both.**

- **Admin plane** — minting. `routes_agent_auth` is mounted at
  [admin_app.py:1109](../admin_app.py).
- **Data plane** — verification, in `AgentIdentityMiddleware`, on every request
  carrying `X-Agent-Token`.

**Touches the guard path: YES, and this is the expensive item on the roadmap.**

Verification adds, per request, when enabled:

| step | cost |
|---|---|
| parse + validate the proof JWT | ~10 µs |
| one signature verification (EdDSA / ES256 / RS256) | 50–250 µs, algorithm-dependent |
| JWK thumbprint + constant-time compare | ~5 µs |
| `claim_jti` replay check | **one nonce-store round trip** |

The signature is not the problem; the nonce store is. `claim_jti` is the same
call `identity_resolution.verify_token_binding` already makes at line 110 with a
60 s TTL, so the infrastructure and its failure behaviour are established rather
than new.

**Latency budget: < 1 ms added at p99 on `/guardrails/*`, `cap/mint` and
`tools/call`, and 0 when disabled.**

What keeps the default free:

- The whole path sits behind `agent_token_pop_mode()`. In `off` — the default —
  the middleware reads one cached env value and does nothing else. No header
  read, no import, no crypto.
- `core.dpop` is imported lazily inside the branch, matching the existing lazy
  import at [identity_resolution.py:98](../core/identity_resolution.py).
- The check runs **after** `verify_agent_token()` succeeds. An invalid token
  never pays for a proof verification, so this cannot be used to make rejection
  more expensive than acceptance.

If the p99 budget is exceeded in practice, the mitigation is a local LRU in
front of the nonce store keyed by `jti`, not relaxing the check. Out of scope
here; flagged so the option is on record.

## 3. Data model

### New token claim

```
cnf   {"jkt": "<base64url SHA-256 JWK thumbprint>"}   omitted when unbound
```

Omitted rather than null when absent, so tokens minted without a key stay
byte-compatible with today — the same convention `roles` uses at
[agent_tokens.py:190](../core/agent_tokens.py).

`IdentityTuple` gains `cnf_jkt: str = ""` and `pop_verified: bool = False`, so
the audit can distinguish three states that must never be conflated: a bound
token whose proof verified, a bound token in `optional` mode whose proof was
merely recorded, and an unbound legacy token.

### Redis

**No new keys.** The replay store is `core/dpop.claim_jti`'s existing namespace,
already in production use for `SHIELD_TOKEN_BINDING`. Reusing it means one
eviction policy and one operational surface rather than two.

**No key storage.** Shield stores no public keys. The thumbprint lives in the
signed token; the full JWK arrives inside each proof header and is checked
against the thumbprint. This is the property that makes DPoP cheap to operate —
there is no key registry to provision, rotate, or lose.

### Tenant scoping

Inherited. The thumbprint is inside a token already bound to `tenant_id` and
verified by `verify_agent_token()` before any of this runs. Nothing new is
tenant-keyed, so there is no new isolation surface.

## 4. API / interface

### Config

```
SHIELD_AGENT_TOKEN_POP              = off | optional | required   # default: off
SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND = true | false               # default: false
```

Mode semantics deliberately mirror `SHIELD_TOKEN_BINDING`
([identity_resolution.py:51](../core/identity_resolution.py)) so operators learn
one model:

| mode | bound token, valid proof | bound token, bad/missing proof | unbound token |
|---|---|---|---|
| `off` | pass, not checked | pass, not checked | pass |
| `optional` | pass, recorded | **pass**, recorded as failed | pass |
| `required` | pass | **401** | **401**, unless allow-unbound |
| `required`, trusted-proxy peer | pass | pass, recorded | pass |

The last row is the LiteLLM case and is not a weakening: a proof cannot exist on
that path for reasons given in §9. The peer must satisfy
`trusted_proxy_only() and peer_is_trusted(request)` — the same gate
`strict_proxy` uses — so possession is delegated to a hop that authenticated
itself with a shared secret. `pop_verified` stays `false` and `role_source`-style
provenance keeps the two cases distinguishable in the audit. A caller that is not
the trusted proxy gets no exemption.

`SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND` is meaningful **only** in `required`, and
exists because the jump from "deny nothing" to "deny every legacy token" is
where outages live. It is the escape hatch the repo's secure-by-default
invariant requires: enforce proofs on tokens that have them, while clients that
have not yet migrated keep working. Setting it in any other mode MUST log a
warning at startup and MUST NOT change behaviour.

`cnf` is minted whenever the caller supplies a key, **independent of mode**.
That separation is what makes the rollout ladder possible: clients can start
binding while enforcement is still `off`, and the operator advances the mode
only once the audit shows the fleet is bound.

### Mint request

`AgentTokenRequest` gains:

```python
agent_jwk: Optional[dict] = Field(
    None, description="Agent's PUBLIC JWK. Its SHA-256 thumbprint is bound "
                      "into the token as cnf.jkt. Private key members are rejected.")
```

In `mint_agent_token()`:

```python
if agent_jwk is not None:
    from core.dpop import jwk_thumbprint, _reject_private_key
    _reject_private_key(agent_jwk)        # raises if d/p/q/dp/dq/qi/k present
    claims["cnf"] = {"jkt": jwk_thumbprint(agent_jwk)}
```

`_reject_private_key` ([dpop.py:82](../core/dpop.py)) already exists and must be
called, not reimplemented. A client that posts its private JWK by mistake gets a
400 rather than having Shield helpfully accept it — and both mint sites (lines
271 and 956 of `routes_agent_auth.py`) need it.

### Proof header

The agent-token proof travels in **`X-Agent-DPoP`**, not `DPoP`.

This matters. `DPoP` is already consumed by
`identity_resolution.verify_token_binding` for the workload-identity token. With
both bindings enabled and different keypairs, one header cannot satisfy two
thumbprints, and overloading it would make the two features silently
incompatible. A separate header lets them be enabled independently. When a
deployer uses the same keypair for both, sending an identical value in both
headers is valid and costs one extra verification.

### Verification

In `AgentIdentityMiddleware.dispatch`, immediately after line 47:

```python
identity = verify_agent_token(token)

mode = agent_token_pop_mode()
if mode != POP_OFF:
    status, err = verify_agent_pop(request, identity)
    identity = replace(identity, pop_verified=(status == POP_VERIFIED))
    if mode == POP_REQUIRED and status != POP_VERIFIED:
        if not (status == POP_UNBOUND and allow_unbound()):
            return JSONResponse(401, {"error": "agent_pop_required", "detail": err})
```

with the helper in `core/agent_tokens.py`:

```python
def verify_agent_pop(request, identity) -> tuple[str, str]:
    """(status, reason). Never raises: a PoP check that 500s on the guard path
    is worse than one that reports failure and lets the caller decide."""
    try:
        from core import dpop
        if not identity.cnf_jkt:
            return POP_UNBOUND, ""
        proof = request.headers.get("X-Agent-DPoP", "").strip()
        if not proof:
            return POP_FAILED, "bound agent token presented without a proof"
        from core.proxy_trust import effective_request_uri
        p = dpop.verify_proof(proof, expected_jkt=identity.cnf_jkt,
                              http_method=request.method,
                              http_uri=effective_request_uri(request))
        if not dpop.claim_jti(p.jti, 60):
            return POP_FAILED, "proof replayed"
        return POP_VERIFIED, ""
    except Exception as e:
        return POP_FAILED, str(e)
```

Structure and never-raises posture copied from `verify_token_binding`
([identity_resolution.py:88](../core/identity_resolution.py)) on purpose: two
functions doing the same job should look the same.

### Shared htu canonicalization — do not skip this

`verify_proof` compares the proof's `htu` against the URI Shield computes.
Behind a load balancer, `str(request.url)` is the *internal* URL, so a proof
signed over the public URL fails. `identity_resolution._request_uri`
([identity_resolution.py:62](../core/identity_resolution.py)) already solves
this, reading `X-Forwarded-Proto`/`Host` **only** when `trusted_proxy_only()`
and `peer_is_trusted()` agree.

Promote it to `core/proxy_trust.effective_request_uri(request)` and have both
call sites use it. `core/proxy_trust.py` is already the module that owns proxy
trust and is already in the admin allowlist
([Dockerfile.admin:74](../Dockerfile.admin)). Leave `_request_uri` as a thin
delegating alias so nothing else moves.

Two independent implementations of htu canonicalization is how you get a feature
that works in tests and fails in every real deployment. It is also how you get a
security bug, since the unsafe version of this function trusts
`X-Forwarded-Host` unconditionally and lets a caller choose its own `htu`.

## 5. Security & backward compatibility

**Default behaviour: unchanged.** `SHIELD_AGENT_TOKEN_POP` defaults to `off`,
`agent_jwk` is optional, and a token minted without it has no `cnf`. Existing
clients need no change and see no difference.

**The threat this closes.** Today, an agent token in a log file, a crash dump,
an error report, a proxy access log, or a compromised sidecar is a working
credential for up to 15 minutes. After: it is inert without the private key,
which never leaves the agent process.

**What it does not close.** An attacker with code execution *inside* the agent
process has the private key and can sign proofs. DPoP binds the credential to a
key, not to a machine or a human. Say this plainly in the customer docs — the
claim is "a stolen token is useless," not "a compromised agent is contained."

**Replay.** Bounded twice: `claim_jti` burns the proof's `jti` for 60 s, and
`verify_proof` enforces a 30 s age window (`_DEFAULT_MAX_AGE_S`,
[dpop.py:42](../core/dpop.py)). A proof captured in flight cannot be reused.

**Proof-as-DoS.** `_MAX_PROOF_BYTES = 8192` ([dpop.py:41](../core/dpop.py))
caps parse cost, `ALLOWED_ALGS` ([dpop.py:26](../core/dpop.py)) excludes `none`
and symmetric algorithms, and the check runs only after token verification
succeeds — so an unauthenticated caller cannot trigger the expensive path at
all.

**Private key submission.** `_reject_private_key` refuses a JWK containing
`d, p, q, dp, dq, qi, k`. Tested explicitly, because a client SDK bug that
posts the full JWK is far more likely than an attack, and silently accepting it
would leak the key into Shield's logs and audit.

**Migration path, four rungs:**

1. `off`, clients start supplying `agent_jwk`. Tokens gain `cnf`. Nothing is
   enforced. No risk.
2. `optional`. Proofs are verified and recorded, denied never. Watch the audit
   for `pop_verified` and for clients sending bad proofs.
3. `required` **with** `SHIELD_AGENT_TOKEN_POP_ALLOW_UNBOUND=true`. Bound tokens
   must now prove possession; unmigrated clients still work.
4. `required` alone, once the audit shows zero unbound tokens.

Skipping rung 3 is how you take down every client that has not shipped a key
yet. The runbook must present these as four steps, not as three modes.

## 6. Packaging & deploy

- **New module:** none. `core/agent_tokens.py`, `core/identity.py`,
  `core/agent_identity_middleware.py`, `core/proxy_trust.py`,
  `api/routes_agent_auth.py`.
- **`Dockerfile.admin`: no change needed, and this is worth verifying rather
  than assuming.** The admin plane mints, so it now imports `core.dpop` via
  `core.agent_tokens`. `core/dpop.py` is **already** in the allowlist at
  [Dockerfile.admin:72](../Dockerfile.admin), as are `core/agent_tokens.py`
  (line 58) and `core/proxy_trust.py` (line 74). Had `dpop` not been there, the
  admin image would crash-loop at boot — exactly the incident
  `tests/test_admin_dockerfile_imports.py` exists to prevent. That test must
  pass and is in the DoD.
- **New pip dependency:** none. `cryptography` is already required by
  `core/agent_tokens.py` ([agent_tokens.py:56](../core/agent_tokens.py)) and
  `core/dpop.py`.
- **Images to rebuild: both, data plane first.** An admin plane minting `cnf`
  tokens against a data plane that ignores them is safe (the claim is unknown
  and unchecked). The reverse — a data plane in `required` against an admin
  plane that cannot mint `cnf` — refuses every request. Order matters and must
  be in the runbook.
- **Rollback:** `SHIELD_AGENT_TOKEN_POP=off`. Tokens already carrying `cnf`
  remain valid; the claim is simply not checked. No data migration, no
  re-minting.

## 7. Failure modes & edge cases

Fail-closed in `required`, fail-open in `optional`, inert in `off`. The helper
never raises: a 500 from a possession check on the guard path is a worse outcome
than a denial, and `verify_token_binding` already set this precedent.

| condition | `optional` | `required` |
|---|---|---|
| bound token, valid proof | pass, `pop_verified=true` | pass |
| bound token, no `X-Agent-DPoP` | pass, recorded failed | 401 |
| bound token, proof for a different key | pass, recorded | 401 |
| bound token, proof for a different URL or method | pass, recorded | 401 |
| bound token, proof older than 30 s | pass, recorded | 401 |
| bound token, replayed `jti` | pass, recorded | 401 |
| bound token, proof > 8 KiB | pass, recorded | 401 |
| bound token, proof `alg: none` | pass, recorded | 401 |
| unbound legacy token | pass | 401, or pass if allow-unbound |
| no `X-Agent-Token` at all | untouched — middleware returns early at line 28 | same |
| mTLS fallback identity | untouched — no `cnf`, treated as unbound | same |
| `core.dpop` import fails | recorded failed | 401 (closed) |
| nonce store unreachable | `claim_jti` behaviour, unchanged from `SHIELD_TOKEN_BINDING` | same |
| behind a proxy, `trusted_proxy_only` off | `htu` compares against the internal URL; proofs signed over the public URL fail | **closed, and this is the most likely misconfiguration** |
| `agent_jwk` contains private members | 400 at mint | 400 at mint |
| `agent_jwk` malformed | 400 at mint | 400 at mint |
| allow-unbound set in `off`/`optional` | startup warning, no effect | n/a |

The proxy row deserves attention in the runbook. It fails closed, which is
correct, but it presents as "PoP is broken" rather than "the proxy boundary is
not configured." The startup log should state which htu source is in effect.

## 8. Test plan (Definition of Done)

New file `tests/test_agent_token_pop.py`. Existing DPoP tests cover
`verify_proof` internals; these cover the agent-token wiring.

**Minting**
1. No `agent_jwk` → no `cnf` claim; token verifies as today.
2. Public JWK → `cnf.jkt` equals `jwk_thumbprint(jwk)`.
3. JWK containing `d` → 400, and the response body does not echo the key.
4. Malformed JWK → 400.
5. `cnf` is minted in `off` mode too (the rung-1 property).
6. Both mint sites (lines 271 and 956) parameterised, as in the delegation spec.

**Verification — `required`**
7. Valid proof → 200, `pop_verified is True`.
8. Missing `X-Agent-DPoP` → 401 `agent_pop_required`.
9. Proof signed by a different key → 401.
10. Proof with wrong `htm` → 401.
11. Proof with wrong `htu` → 401.
12. Proof older than 30 s → 401.
13. Replayed `jti` → first 200, second 401.
14. Proof > 8 KiB → 401.
15. `alg: none` proof → 401.
16. Unbound legacy token → 401.
17. Unbound legacy token + allow-unbound → 200.
18. `core.dpop` monkeypatched to raise → 401.

**Verification — `optional` and `off`**
19. Every case in 8 to 16 under `optional` → 200, with `pop_verified is False`.
20. Every case under `off` → 200, and `verify_agent_pop` is never called
    (assert via monkeypatched spy — proves the zero-cost claim, not just the
    behaviour).

**htu canonicalization — the one most likely to be skipped**
21. `effective_request_uri` returns the internal URL when
    `trusted_proxy_only()` is off, even with `X-Forwarded-Host` present.
22. Returns the forwarded URL when the boundary is on and the peer is trusted.
23. Ignores `X-Forwarded-Host` when the boundary is on and the peer is **not**
    trusted. This is the security case: without it a caller picks its own htu.
24. `identity_resolution._request_uri` and
    `proxy_trust.effective_request_uri` return identical values across all of
    21 to 23. The regression guard against the two implementations drifting.

**Trusted-proxy exemption (§9)**
24a. `required` + bound token + no proof + trusted-proxy peer → 200,
     `pop_verified is False`.
24b. `required` + bound token + no proof + peer **not** trusted → 401. The
     exemption must not be reachable without the secret.
24c. `required` + unbound token + trusted-proxy peer → 200.
24d. Exemption does not apply when `trusted_proxy_only()` is off, even if the
     secret happens to match. Mirrors `_proxy_vouched()` in
     [spec-proxy-trusted-role-header](/spec-proxy-trusted-role-header/).
24e. A valid proof from a trusted-proxy peer still sets `pop_verified is True` —
     the exemption relaxes the requirement, it does not skip verification.

**Regression guards**
25. A token minted with no `agent_jwk` in `off` mode has a claim set identical
    to one minted before this change, excluding `jti`/`iat`.
26. `SHIELD_TOKEN_BINDING` behaviour is unchanged with `SHIELD_AGENT_TOKEN_POP`
    at every value — the two features are independent.
27. Both enabled with different keypairs, `DPoP` and `X-Agent-DPoP` both sent →
    both verify. The header-separation design from §4.
28. mTLS fallback identity is unaffected in all three modes.
29. `tests/test_agent_auth_portal.py`, `tests/test_signers.py` and the existing
    DPoP tests pass unmodified.
30. `tests/test_admin_dockerfile_imports.py` passes.

**Gate**
31. `python -m pytest tests -q` green in a clean venv.
32. CI `pytest` gate green.

## 9. Deployment topologies — where PoP applies, and where it cannot

**PoP is a direct-path control.** This is a property of DPoP, not a gap in the
implementation, and the customer-facing claim must be scoped accordingly.

### A. Direct — PoP works fully

    agent ──► Shield /guardrails/*, cap/mint, tools/call

The agent is the HTTP client, signs a proof over the method and URI it is
actually calling, and `verify_proof` compares against the same values. This is
where "a stolen agent token is useless" is true, and it covers `cap/mint` and
`tools/call` — the two endpoints that actually authorize an action.

### B. Behind LiteLLM — PoP cannot work, by construction

    agent ──► LiteLLM /v1/chat/completions
                └─ VotalGuardrail hook ──► Shield /guardrails/input|output

DPoP binds a proof to `htm` and `htu`. The agent signs for
`POST /v1/chat/completions` at LiteLLM; Shield receives
`POST /guardrails/input`. The agent cannot sign a proof for a request it does
not make, and LiteLLM cannot sign one because it does not hold the agent's
private key. Forwarding the proof unchanged fails the `htu` comparison, and
relaxing that comparison would delete the control.

There is no configuration that fixes this. The options are:

1. **Trusted-proxy exemption** (specified in §4). LiteLLM authenticates itself
   with `X-Shield-Proxy-Token`; possession of the *agent* key is not proven on
   this path, and the audit says so. Chosen.
2. LiteLLM does its own PoP with LiteLLM's key. Proves LiteLLM, which the shared
   secret already does, at the cost of a keypair to manage. Rejected as
   redundant.
3. Re-sign at the hook. Requires the agent's private key at LiteLLM. Rejected —
   it destroys the property the feature exists to create.

`votal_guardrail.py` should still forward `X-Agent-Token`
(`_extract_shield_headers` currently forwards neither it nor any proof — `grep
-c` returns 0). Forwarding it gives Shield verified agent *identity* on the
LiteLLM path — signature, expiry, revocation, `build_hash` allowlist — which is
strictly more than the `x-agent-key` string it gets today. Only possession is
unproven. That is a real improvement and belongs in the same hook PR as the
`X-On-Behalf-Of` forwarding specified in
[spec-proxy-trusted-role-header §10](/spec-proxy-trusted-role-header/).

### What to tell customers

Not "a stolen agent token is useless." The accurate claim is:

> On paths where the agent calls Shield directly — including every tool
> authorization and capability mint — a stolen agent token is useless without
> the agent's private key. Where an LLM gateway sits in front, the gateway
> authenticates itself to Shield and the audit records that possession was
> vouched for rather than proven.

The demo in PR 5 must run on a direct path, and the runbook must say why.

## 10. Task breakdown (one PR each)

**PR 1 — shared htu, no behaviour change.**
Promote `_request_uri` to `proxy_trust.effective_request_uri`, alias the old
name, add tests 21 to 24. Independently correct, and it removes the trap before
anyone can fall into it.

**PR 2 — minting.** `agent_jwk`, `cnf`, `_reject_private_key` at both sites,
`IdentityTuple.cnf_jkt`, tests 1 to 6 and 25. Ships rung 1 of the migration: the
fleet can start binding while nothing is enforced.

**PR 3 — verification.** `agent_token_pop_mode()`, `verify_agent_pop()`, the
middleware branch, `X-Agent-DPoP`, `pop_verified` in the audit, tests 7 to 20
and 26 to 28. The only PR that can deny a request.

**PR 4 — trusted-proxy exemption + `X-Agent-Token` forwarding.**
The §9 exemption in `verify_agent_pop`, tests 24a to 24e, and the hook change
forwarding `X-Agent-Token` so the LiteLLM path gains verified agent identity.
Must land **with or before** any deployment sets `required`, or every
LiteLLM-routed request 401s.

**PR 5 — allow-unbound + operations.** The escape hatch, the startup warnings
(mode, htu source, misplaced allow-unbound), and the runbook: four migration
rungs from §5, image order from §6, the proxy misconfiguration from §7, and the
scoped customer claim from §9.

**PR 6 — the proof.** `examples/langchain/agent_token_theft_demo.py`, in the
[keycloak_binding_demo.py](../examples/langchain/keycloak_binding_demo.py)
style: mint a bound token, use it successfully, then replay the same token from
a second process without the private key and show the 401. Doubles as the manual
test and the customer-facing artifact.

**Follow-on:** binding capability tokens. Same primitives, different latency
argument, own spec.
