# Spec: cap/mint enforces role → tool, from the same role source as everything else

## 1. Problem & outcome

`POST /v1/shield/cap/mint` does not enforce role → tool. `_decide_authz`
([api/routes_agent_auth.py:643](https://github.com/sundi133/llm-shield/blob/main/api/routes_agent_auth.py#L643))
builds the permitted set by unioning **every** role's permissions:

```python
allowed_tools = set(agent_entry.get("tools", []) or [])
for perms in (agent_entry.get("role_permissions", {}) or {}).values():
    allowed_tools.update(perms or [])
```

So any tool any role may use is mintable by every caller. Reproduced against
production with `test-oidc-agent`:

```
tool/check  prescribe_medication  role=nurse  ->  DENY rbac_guard
cap/mint    prescribe_medication  role=nurse  ->  MINTED, verified, executed
```

A nurse obtained a signed capability to prescribe and the prescription ran. The
advisory path refused the same call.

This is the wrong way round. `cap/mint` produces a signed, non-repudiable
artifact asserting an action was authorized; it should be at least as strict as
the advisory check, not looser. As it stands the audit trail can contain
cryptographic evidence that a nurse was authorized to prescribe.

**Why it was not caught by the obvious fix.** Scoping to `role_name` fails:
that local is `None` at the point of the tool decision. It is assigned later
from `rbac_enforcer.resolve_role(agent_id)` — the **static RBAC config's**
agent→role map — which returns `None` for any agent registered in the tenant
registry. An attempted fix denied every registry-based agent, including
`test-oidc-agent`, and was reverted.

**The same wrong role source has now caused three separate defects today:**

| Where | Symptom |
|---|---|
| `/guardrails/input` telemetry | every decision recorded no role — "role unavailable" in the console |
| `tool_call_validation` payload guard | invented a role rule that existed nowhere |
| `cap/mint` (this) | role never consulted; capabilities issued regardless |

Each was patched or specced separately. This spec fixes the cause.

**Outcome.** `cap/mint` resolves the caller's role through
`core.identity_resolution.resolve_identity` — the seam `rbac_guard` and the
tool path already use — and refuses to mint a capability for a tool that role
is not granted.

**Non-goals.**
- Changing `rbac_guard`, `tool/check`, or the role matrix semantics. They are
  correct; this makes `cap/mint` agree with them.
- Merging the check and the mint into one call. Worth doing for latency
  (~1.5-6s + ~1.8s today) but it is a separate change.
- Retiring `rbac_enforcer.resolve_role`. Static RBAC remains for deployments
  that use it; it stops being the *only* source.

## 2. Plane & latency contract

Data plane. `cap/mint` is guard path.

`resolve_identity` reads headers and already-verified request state. No new
network calls and no Redis round-trip beyond the agent-entry load `_decide_authz`
already performs. The registry lookup is unchanged.

## 3. Data model

No new keys. Reads the existing `role_permissions` map on the agent registry
entry — the same structure `rbac_guard` reads and the portal renders.

## 4. API / interface

`POST /v1/shield/cap/mint` — unchanged request and response. A mint refused for
role reasons returns the existing denial shape, with a reason naming the role:

```
tenant policy does not permit agent 'X' acting as role 'nurse' to use tool 'Y'
```

Internal: `_decide_authz` takes the resolved role rather than deriving it, and
the tool decision moves after role resolution instead of before it.

## 5. Security & backward compatibility

Permitted set becomes `agent.tools ∩ role_permissions[role]` when a role map
exists, rather than the union across roles.

| Case | Today | After |
|---|---|---|
| registry agent, role granted | mint | mint |
| registry agent, role **not** granted | **mint** | **refuse** |
| registry agent, no `role_permissions` | mint if in `tools` | unchanged |
| static-RBAC agent | mint | unchanged — static path still runs |
| no role resolvable, role map exists | mint | **refuse** |

Rows two and five are the behaviour change, and both are tightening. That will
break any caller currently relying on the union — which is the vulnerability, so
the break is the point. `SHIELD_CAP_MINT_ROLE_UNION=1` restores the old
behaviour for an operator who needs to stage the rollout, defaulting off.

The empty-role case must refuse rather than fall back to the union, or omitting
`X-User-Role` becomes the bypass.

A malicious caller gains nothing new: they can still assert a role in a header,
exactly as they can at `tool/check`. Role *binding* — making an asserted role
provable — is `SHIELD_ROLE_BINDING` and out of scope here. This spec closes
"the role is ignored entirely", not "the role is self-asserted".

## 6. Packaging & deploy

No new modules; `core.identity_resolution` is already imported on this plane.
No `Dockerfile.admin` change, no new pip dependencies. Rebuild the data plane.
One optional env flag, default off, so a deploy with no config change is the
fix.

## 7. Failure modes & edge cases

- **`resolve_identity` raises** → treat as no role → refuse when a role map
  exists. Fail closed: this endpoint mints authority.
- **Role present, absent from `role_permissions`** → empty grant → refuse. An
  unknown role gets nothing, not everything.
- **`role_permissions` empty or absent** → agent's own `tools` list governs,
  unchanged, so agents without a role map keep working.
- **`tools` empty but `role_permissions` populated** → use the role's grants;
  do not treat an empty base list as "deny all" and break existing entries.
- **Static-RBAC agent with no registry entry** → unchanged path.
- **Registry unavailable** → existing behaviour, not widened here.

## 8. Test plan (Definition of Done)

- nurse + `prescribe_medication` → refused; doctor + same → minted. This is the
  reported case and must be a test, not a manual check.
- Unknown role → refused.
- No role resolvable, role map present → refused.
- No `role_permissions` configured → unchanged (regression guard for every
  existing agent).
- Registry-based agent (`resolve_role` returns `None`) → still works when the
  role is granted. This is what the reverted attempt broke.
- Static-RBAC agent → unchanged.
- `SHIELD_CAP_MINT_ROLE_UNION=1` → old behaviour, warning logged.
- Denial reason names the role.
- Parity test: for a matrix of (role, tool), `cap/mint` and `tool/check` agree.
  Divergence between them is the whole defect, and only a paired test keeps them
  honest as either side changes.
- Full suite green in a clean venv; CI `pytest` gate passes.
