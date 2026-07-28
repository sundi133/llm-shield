---
title: "Spec: Token binding (proof-of-possession)"
layout: default
nav_order: 36
permalink: /spec-token-binding/
description: Bind agent tokens and capabilities to a key the holder must prove, so a stolen token is useless. DPoP primary, mTLS-bound optional. Opt-in, off by default.
---

# Spec: Token binding (proof-of-possession)
{: .no_toc }

Status: DRAFT — awaiting approval. No code written.
{: .fs-6 .fw-300 }

---

## 1. Problem & outcome

Shield's agent tokens and capabilities are **pure bearer credentials**. Whoever
holds the bytes is the agent. Verified: no `cnf`, no DPoP, no `x5t#S256`
anywhere in `api/` or `core/`.

That matters more for agents than for humans. An agent token sits in a process
that also parses untrusted input, calls third-party tools, and echoes content
into logs and traces. Exfiltration paths are the product's own threat model —
prompt injection, a poisoned MCP server, an over-broad log sink. A ≤15 minute
TTL narrows the window; it does not close it.

The nearest thing today is the `X-Client-Cert-Fingerprint` path, which accepts a
fingerprint **with no certificate present** and stamps `trust_level="high"`.
That is a binding-shaped hole, not a binding mechanism.

**Outcome.** A tenant can require that the presenter of a token prove possession
of the key it was issued to. Observable success: capture a valid agent token and
capability off the wire, replay both from another process, and both are refused
— while the legitimate holder is unaffected.

### Non-goals
- Not an IdP. Shield verifies proofs; it does not issue user credentials.
- Not FAPI compliance. FAPI requires mTLS-bound tokens (RFC 8705); this spec
  makes that possible where the edge terminates client certs, but DPoP is the
  primary mechanism and is **not** a FAPI substitute. Say so in the docs.
- No change to authorization. Binding answers *is the presenter the party this
  was issued to*, never *may they do this*.
- Not delegation. `parent_agent_id` attenuation is a separate gap.

---

## 2. Plane & latency contract

**Data plane** (`core/app.py`), and squarely on the guard path: agent tokens are
verified by `AgentIdentityMiddleware` on every request, and capabilities by
`verify_cap`.

Cost per request when binding is active:

- one asymmetric signature verification of the proof (ES256 or EdDSA)
- one RFC 7638 thumbprint computation (SHA-256 over a small canonical JSON)
- one atomic replay claim — Redis `SET NX`, the same primitive
  `_burn_nonce_if_unused` ([core/capabilities.py:141](https://github.com/sundi133/llm-shield/blob/main/core/capabilities.py#L141)) already uses

No JWKS fetch: the proof carries its own public key in the JWT header, and that
key is trusted only because its thumbprint matches `cnf.jkt` in a token Shield
itself signed. **No network I/O on the hot path.**

Budget: **p99 added latency < 3 ms**. Measured in the PR that enables it, not
asserted here.

---

## 3. Data model

### 3.1 The `cnf` claim

Added to agent tokens and capability tokens **at mint**, only when the client
presents a key:

```json
"cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }
```

`jkt` is the base64url SHA-256 JWK thumbprint (RFC 7638). For the mTLS variant,
`cnf` carries `x5t#S256` instead. A token with no `cnf` is unbound and behaves
exactly as today.

### 3.2 Per-tenant config (new)

Redis `shield:token_binding:{tenant_id}`, JSON, no TTL:

```json
{
  "mode": "off",
  "methods": ["dpop"],
  "proof_max_age_s": 30,
  "allowed_algs": ["ES256", "EdDSA"],
  "updated_at": 1785200000
}
```

`mode` is `off` | `optional` | `required` (§5). In-process cache, 30 s TTL,
consistent with how tenant config is cached elsewhere.

### 3.3 Replay store

Redis `shield:dpop:jti:{jti}`, TTL = `proof_max_age_s` + skew. Claimed
atomically via the existing `SET NX` helper, generalised out of
`core/capabilities.py` rather than duplicated.

### 3.4 `IdentityTuple`

Two optional fields, defaulted so every construction site keeps working:

```python
bound: bool = False
binding_method: str = ""   # "" | "dpop" | "mtls"
```

Audit records both. Without them an operator cannot tell a bound request from an
unbound one, which makes rolling out `required` guesswork.

---

## 4. API / interface

### 4.1 Mint

`POST /v1/shield/auth/agent-token`, its tenant twin, and `POST /v1/shield/cap/mint`
accept the binding key one of two ways:

- a `DPoP` proof header on the mint request — Shield derives `jkt` from it, which
  proves the client holds the private key at mint time; **preferred**
- an explicit `dpop_jkt` body field, for clients that cannot sign at mint

If `mode=required` and neither is present, minting is refused. An unbound token
must not be issuable to a tenant that requires binding, or the control is
trivially sidestepped by asking for a token without a proof.

### 4.2 Verify

Every request presenting `X-Agent-Token` or a capability may carry:

```
DPoP: <compact JWS>
```

Proof claims per RFC 9449: `htm` (method), `htu` (URI), `iat`, `jti`, and the
public key in the JWT header `jwk`.

Verification order — each step cheap-to-expensive so a bad proof fails fast:

1. Token has `cnf`? If not, apply the mode rule (§5) and stop.
2. Proof present and parseable; header `alg` is in `allowed_algs`; `typ` is
   `dpop+jwt`. **Reject `none` and any symmetric alg outright.**
3. Verify the proof signature against the embedded `jwk`.
4. Compute the RFC 7638 thumbprint of that `jwk`; require it to equal `cnf.jkt`.
5. `htm` matches the request method; `htu` matches the request URI (§7).
6. `iat` within `proof_max_age_s`.
7. Claim `jti` atomically; a second use is a replay.

Failure returns the existing 401 shape with a machine-readable `code`
(`binding_required`, `binding_proof_invalid`, `binding_replayed`). Not free text
— a caller has to distinguish "retry with a proof" from "you were replayed".

### 4.3 Admin

`GET`/`PUT /v1/tenant/me/token-binding` on the admin plane. Off the hot path.

---

## 5. Security & backward compatibility

| mode | token has `cnf` | token has no `cnf` |
| --- | --- | --- |
| `off` (default) | proof ignored | accepted — today's behaviour exactly |
| `optional` | proof **required and verified** | accepted, audited as unbound |
| `required` | proof required and verified | **rejected**; minting unbound is also refused |

`off` is byte-for-byte current behaviour. `optional` is the migration state: new
tokens get bound, old ones keep working, and the audit shows the ratio.

**Escape hatch:** `SHIELD_TOKEN_BINDING=off` disables globally regardless of
tenant config — the operator kill switch.

### What this closes, and does not

Closes: replay of a token exfiltrated via logs, traces, a poisoned tool
response, or a compromised sidecar that cannot reach the private key.

Does **not** close:
- An attacker with code execution in the agent process. They have the key. No
  PoP scheme fixes that; say it plainly rather than implying otherwise.
- A malicious agent acting within its own permissions.
- Anything if the private key is written to disk beside the token.

Recommend a non-extractable key where the platform offers one (WebCrypto
`extractable: false`, a TPM, a KMS handle). Document it; do not pretend to
enforce it.

---

## 6. Packaging & deploy

- **Deps: none new.** `PyJWT[crypto]>=2.8` and `cryptography` are already in
  `requirements.txt`. RFC 7638 thumbprints are ~20 lines over `hashlib`.
- **`Dockerfile.admin`:** if the config endpoint lands in a new module it MUST be
  added to the COPY allowlist, or the admin image crash-loops at boot. Enforced
  by `tests/test_admin_dockerfile_imports.py`. Highest-risk packaging item here.
- **Images:** data plane and admin plane both rebuild.
- **Env:** `SHIELD_TOKEN_BINDING` (default `off`).

---

## 7. Failure modes & edge cases

| case | behaviour |
| --- | --- |
| No `cnf`, `mode=off`/`optional` | accepted, `bound=False` |
| No `cnf`, `mode=required` | reject `binding_required` |
| `cnf` present, no proof | reject in `optional` and `required` — a bound token without a proof is the exact theft case |
| Proof `alg` is `none` or HMAC | reject before any verification |
| `jwk` in header is a **private** key | reject; accept only public key members |
| Thumbprint mismatch | reject `binding_proof_invalid` |
| `htu` behind a proxy | canonicalise from `X-Forwarded-Proto`/`Host` **only when `core/proxy_trust.py` says the hop is trusted**, else the raw URL. Getting this wrong either breaks every deployment behind a load balancer or lets an attacker choose `htu` |
| Clock skew | ±`proof_max_age_s`, default 30 s. Reject future `iat` beyond skew |
| `jti` replayed | reject `binding_replayed` |
| Redis down, `mode=required` | **fail closed** — reject. Replay protection unavailable means the control is unavailable |
| Redis down, `mode=optional` | verify signature and thumbprint, skip replay claim, audit the degradation |
| Huge or deeply nested `jwk` | size cap before parsing |
| Token bound, tenant later set to `off` | proof ignored; token still valid |

Fail-open vs fail-closed: `required` fails closed everywhere, `optional`
degrades and records. That asymmetry is deliberate and must be documented —
`optional` is an observation mode, not a control.

---

## 8. Test plan (Definition of Done)

One test per row in §7, plus:

1. `off` is byte-identical to current behaviour — regression guard.
2. Round trip: mint with a proof, call with a proof, accepted; `bound=True` in the audit.
3. **Theft test** — the headline. Take a valid bound token, present it from a
   context without the private key, assert rejection.
4. Replay: identical proof twice, second rejected.
5. Algorithm confusion: `none`, HS256, and a swapped key all rejected.
6. Thumbprint computed per RFC 7638 against published vectors — canonical JSON,
   required members only, lexicographic order. Easy to get subtly wrong.
7. `htu` correctness behind a trusted proxy and behind an untrusted one.
8. `required` refuses to mint an unbound token.
9. Capability path bound independently of the agent-token path.

Perf: assert p99 added latency < 3 ms with the replay store warm.

Full suite green in a **clean venv**; `pytest` CI gate passes.

---

## 9. Task breakdown (one PR each)

| # | PR | Risk |
| --- | --- | --- |
| 1 | RFC 7638 thumbprint + DPoP proof parser/verifier as a pure module, with published test vectors. No wiring. | low |
| 2 | Generalise the atomic replay claim out of `core/capabilities.py`; `IdentityTuple.bound`/`binding_method`; audit fields. Mode hardwired `off`. | low |
| 3 | Mint accepts a proof or `dpop_jkt` and emits `cnf`. Still `off`. | medium |
| 4 | Verify path + `optional` mode + per-tenant config. | medium |
| 5 | `required` mode, refusal to mint unbound, structured error codes. **First behaviour change** — ship with the perf measurement. | **high** |
| 6 | mTLS variant (`cnf.x5t#S256`) reusing `core/proxy_trust.py`, for edges that terminate client certs. | medium |
| 7 | Admin config endpoint + portal. Check `Dockerfile.admin` COPY. | medium |

PRs 1–2 are inert and make the rest small. PR 5 is the one to review closely.

---

## 10. Open questions

1. **Bind capabilities, agent tokens, or both?** Capabilities already carry a
   single-use nonce, so replay is partly covered; agent tokens have no such
   protection and a 15-minute window. Binding agent tokens first buys more.
2. **Should `optional` be the default for new tenants?** It changes nothing for
   clients that send no proof and starts populating `bound` in the audit.
3. **Does the MCP gateway path need this**, or does it inherit it via the agent
   token? If the gateway forwards a token onward, binding must not be assumed to
   survive that hop.
4. **Key lifecycle is the client's problem — is that acceptable?** Shield never
   sees the private key, which is the point, but it also means Shield cannot tell
   a hardware-backed key from one in a `.env` file.
