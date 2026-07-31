# Spec: identity provenance inside the capability, and per-tool trust requirements

Steps 4 and 5 of the verified-identity plan. Steps 1–3 established *whether* an
identity was verified; these make that fact **travel with the decision** and
**gate the actions that need it**.

## 1. Problem & outcome

A capability token records `user_sub`, `agent_id`, `tool`, `resource` and a
signature. It does **not** record how the identity was established. A cap minted
from a typed `X-User-Role` header is byte-indistinguishable from one minted from
a verified OIDC claim.

Two consequences, and the second is the one that matters in production:

- An auditor holding a capability cannot tell a proven identity from an asserted
  one. It is signed evidence of a claim nobody necessarily checked, so it does
  not support the non-repudiation argument its existence implies.
- Policy cannot require verification. There is no way to say *"prescribing needs
  a proven identity; reading logs does not"*. Today it is all-or-nothing at the
  deployment level via `SHIELD_ROLE_BINDING`, which forces an operator to choose
  between blocking low-risk automation and permitting high-risk actions on a
  header.

**Outcome.** The cap carries provenance, `verify_cap` returns it, and a tool may
declare a minimum trust level that mint refuses to go below.

**Non-goals.**
- Changing how identity is *resolved*. That is `core.identity_resolution`, done.
- Proving the agent's process identity (mTLS/SPIFFE). Separate, and orthogonal.
- Retrofitting provenance onto capabilities already issued. They predate the
  field and must remain verifiable; see §5.

## 2. Plane & latency contract

Data plane. `cap/mint` and `cap/verify` are guard path.

No new I/O. `resolve_identity` already runs at mint (step 3 of the plan), and
the trust requirement is read from the agent registry entry `_decide_authz`
already loads. The added claims are three short strings in a JWT that is already
being signed — measurable in bytes, not round trips.

## 3. Data model

**Capability claims** gain three optional fields:

| Claim | Values | Meaning |
|---|---|---|
| `role_source` | `none`\|`header`\|`body`\|`agent_token`\|`mtls`\|`oidc` | where the role came from |
| `identity_method` | provider name, or `""` | which provider verified the caller |
| `trust_level` | `none`\|`low`\|`medium`\|`high` | strength of the attestation |

`trust_level` is derived, not caller-supplied. Mapping, ordered:

```
oidc with audience enforced, mtls, spiffe   -> high
agent_token, admin_key, tenant_key          -> medium
header, body                                -> low
nothing resolved                            -> none
```

The distinction between `low` and `none` is deliberate: "the caller said
`doctor`" and "no role at all" are different facts and a policy may treat them
differently.

**Registry entry** gains an optional per-tool requirement:

```json
{
  "tools": ["read_logs", "rotate_credential"],
  "tool_trust": {"rotate_credential": "high"}
}
```

Absent means no requirement — every existing entry keeps its current behaviour.

## 4. API / interface

`POST /v1/shield/cap/mint` — request unchanged. Refusal for insufficient trust
uses the existing denial shape, with a reason naming both sides:

```
tool 'rotate_credential' requires trust_level 'high'; this caller resolved to
'low' (role_source=header)
```

Naming the resolved level and its source matters. "Insufficient trust" alone
sends an operator to the policy when the actual fix is usually a misconfigured
issuer.

`POST /v1/shield/cap/verify` — `claims` in the response gains the three fields.
A tool server can therefore make its own decision, which is the point of giving
the tool server a verifiable token at all.

## 5. Security & backward compatibility

**Capabilities issued before this change lack the claims.** `verify_cap`
validates a `required` tuple; adding these to it would reject every in-flight
cap. They are therefore **optional at verification** and default to
`role_source="none"`, `trust_level="none"` when absent.

That default is the safe direction: an old cap reads as *unknown provenance*
rather than as verified. It also means a tool requiring `high` will refuse an
old cap, which is correct — the token genuinely cannot demonstrate what is being
asked of it.

**Minting always populates them.** There is no path that writes a cap without
provenance after this lands, so `none` in a fresh cap means the identity really
was unresolved, not that the field is missing.

**Trust requirements are opt-in per tool.** No `tool_trust` key means unchanged.
An operator raises the bar tool by tool rather than flipping a deployment-wide
switch — which is the failure of `SHIELD_ROLE_BINDING=strict` as the only lever:
it is correct and too blunt to adopt incrementally.

**Interaction with `strict`.** They compose and neither replaces the other.
`strict` says "no verified claim, no role"; `tool_trust` says "this action needs
a strong one". A deployment on `prefer` can still protect its dangerous tools;
a deployment on `strict` still benefits from distinguishing `medium` from
`high`.

**What this does not achieve.** Provenance describes how the *user* identity was
established. It says nothing about which process presented the token — an agent
token is a bearer credential, and a stolen one yields `trust_level=medium`
honestly. Do not read `high` as "this call is trustworthy"; read it as "the
human identity behind this call was verified by a strong method".

## 6. Packaging & deploy

`core/capabilities.py` (claims), `api/routes_agent_auth.py` (mint decision,
verify response). Both already on the data plane; `core/capabilities.py` is
already in the `Dockerfile.admin` COPY list and gains no new imports.

No new pip dependencies. No env flags: the claims are always written, and the
enforcement is per-tool registry config, so a deploy with no config change
writes richer capabilities and behaves identically.

Rebuild both images — the admin plane verifies caps too.

## 7. Failure modes & edge cases

- **Old cap, no requirement** → verifies, provenance reads `none`. Unchanged.
- **Old cap, tool requires `high`** → refused. Correct: it cannot demonstrate
  what is required.
- **`tool_trust` names an unknown level** (typo, e.g. `"higest"`) → treat as
  the strictest level, log a warning. A misspelled requirement must not silently
  become no requirement.
- **`resolve_identity` raises at mint** → `trust_level="none"`; any tool with a
  requirement refuses. Fail closed.
- **Requirement set on a tool the agent does not have** → the existing
  role→tool check refuses first; the trust check never runs. No interaction.
- **Provenance disagrees with the role** (role from `oidc`, agent from
  `header`) → `trust_level` reflects the ROLE's source, since that is what the
  authorization decision used.
- **Clock skew, revocation, replay** → untouched; these claims do not
  participate in those checks.

## 8. Test plan (Definition of Done)

- Mint under each provider → cap carries the expected `role_source`,
  `identity_method`, `trust_level`.
- Header-only mint → `trust_level="low"`, not `none` — the two are distinct
  facts and conflating them loses the distinction the spec exists to create.
- `verify_cap` on a cap **without** the claims → still valid, provenance reads
  `none`. This is the backward-compatibility guard and must fail loudly if the
  claims are ever added to `required`.
- `verify_cap` returns the three fields in `claims` for a tool server to read.
- `tool_trust: high` + header-derived role → mint refused, reason names both the
  required and the resolved level.
- `tool_trust: high` + OIDC-derived role → minted.
- `tool_trust` absent → unchanged for every existing entry (regression guard
  across the current registry shapes).
- Unknown level string → treated as strictest, warning logged.
- `strict` and `tool_trust` together → both enforced, neither masks the other.
- Parity: a tool with no `tool_trust` reaches the same verdict at `cap/mint` and
  `tool/check`, extending the parity matrix from
  `docs/spec-cap-mint-role-enforcement.md`.
- Full suite green in a clean venv; CI `pytest` gate passes.

## 9. Rollout

1. Deploy. Capabilities begin carrying provenance; nothing is enforced yet.
2. Read the audit trail. `trust_level` distribution across real traffic tells
   you which tools are already being called with verified identity and which
   would break — **before** any refusal.
3. Add `tool_trust` to the highest-risk tools first, one at a time.
4. Only then consider `SHIELD_ROLE_BINDING=strict` deployment-wide.

Step 2 is the one not to skip. Turning on a requirement without knowing the
current distribution is how a correct control becomes an outage.
