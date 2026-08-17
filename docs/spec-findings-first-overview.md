# Spec: Findings-first Overview

Status: **DRAFT — awaiting approval.** Not implemented.

## 1. Problem & outcome

The portal's Overview tab — the first screen anyone sees — shows *Top Triggered
Guardrails* and *Tool Activity*: how much traffic was processed. Shield already
computes, one tab away, the things a reader actually needs to act on: agents
running that nobody registered, agents with no owner, grants nobody has used,
components that changed after approval, and controls that are switched off.

The result is a product that knows something true about the customer's system
and does not say it on the front page. Every number below already exists; none
of them is on Overview.

**Outcome.** Within one screen of signing in, an administrator sees a ranked
list of findings with counts, each linking to the tab that explains it, and can
tell at a glance which enforcement controls are off.

**Success condition.** On a tenant with a shadow agent, an unowned agent, an
unused grant and a drifted component, Overview names all four with correct
counts, and each row navigates to the existing tab. On a clean tenant it says so
rather than rendering four zeroes.

### Non-goals
- No new detection. Every finding is an existing computation, re-presented.
- No changes to what any detector considers a finding.
- Not a redesign of the other 19 tabs (that is worth doing; it is not this).
- No enforcement changes. Nothing is turned on by this feature.
- No new persistence. Nothing is written.

## 2. Plane & latency contract

**Plane:** admin (CPU portal) only. `static/tenant.html` plus one handler in
`api/routes_tenant_self.py`.

**Guard path:** not touched. This adds no read, write, or import to
`/guardrails/*`, `cap/mint`, or `tools/call`. **Off hot path, no guarded-traffic
impact.**

The one risk worth naming: §4's posture endpoint reads process environment for
enforcement modes. That is a local `os.environ` read on an admin route, not a
store read, and it runs only when the portal asks. It cannot reach the data
plane.

## 3. Data model

**No new Redis keys. No new writes. No TTLs.** Every finding is derived at read
time from keys that already exist:

| Finding | Existing source |
|---|---|
| Shadow agents | `unregistered:{tenant_id}` (via `/v1/governance/agents`) |
| Unowned agents | `agents:{tenant_id}` (via `/v1/governance/agents/unowned`) |
| Unused grants | `granted_tools` vs `recent_tools_used`, both already in the `/v1/governance/agents` response |
| Component drift | AIBOM snapshot vs current (via `/v1/tenant/me/aibom/drift`) |
| Controls off | process environment, read per request |

**Tenant scoping.** Unchanged. Every source endpoint already resolves tenant via
`get_tenant_from_api_key(request)` or `_require_tenant(request)`, which now also
accepts a portal session. No new cross-tenant surface is introduced because no
new query is introduced.

## 4. API / interface

### 4.1 Extend `GET /v1/tenant/me/key-scope` → add `GET /v1/tenant/me/posture`

`/me/key-scope` already reports one control:

```json
{"scope": "admin", "registry_write": true, "enforcement": "warn"}
```

Its docstring says enforcement reporting was added early so "the portal does not
need a second round trip when it does" — this is that round trip arriving. A new
sibling endpoint rather than a change to `key-scope`, because `key-scope` answers
"what may *this key* do" and posture answers "what is *this deployment*
enforcing". Overloading the first would make a per-credential answer look
deployment-wide.

```
GET /v1/tenant/me/posture        (admin plane; X-API-Key or portal session)

200 {
  "controls": [
    {"id": "registry_write",  "env": "SHIELD_REGISTRY_WRITE_SCOPE",
     "mode": "off", "enforcing": false, "next": "warn"},
    {"id": "auto_revoke",     "env": "SHIELD_ENABLE_AUTO_REVOKE",
     "mode": "off", "enforcing": false, "next": "on"},
    {"id": "agent_token_pop", "env": "SHIELD_AGENT_TOKEN_POP",
     "mode": "off", "enforcing": false, "next": "optional"},
    {"id": "role_binding",    "env": "SHIELD_ROLE_BINDING",
     "mode": "off", "enforcing": false, "next": "prefer"},
    {"id": "portal_sso",      "env": "SHIELD_PORTAL_REQUIRE_SSO",
     "mode": "off", "enforcing": false, "next": "on"}
  ],
  "off_count": 5
}
```

`next` is the following rung on that control's documented ladder, never a jump
to full enforcement — the portal must not invite anyone to skip `warn`.

**Reads the process, never the request.** A caller cannot influence the reported
posture. Values outside a control's known set normalise to the safe reading
(`off`), matching how `key-scope` already handles an unrecognised mode.

**Deliberately reports the data plane's controls from the admin plane.** In a
split deployment these are separate processes with separate environments, so the
admin plane can report a value the guardrail server does not have. §7 covers
this; it is the sharpest edge in this spec.

### 4.2 Overview tab (frontend)

No new endpoint. Overview calls three existing ones — `/v1/governance/agents`,
`/v1/governance/agents/unowned`, `/v1/tenant/me/aibom/drift` — plus §4.1, and
renders a findings list. Unused grants are computed client-side by diffing
`granted_tools` against `recent_tools_used` in the response Overview already has,
so there is no per-agent fan-out.

Existing Overview content (Top Triggered Guardrails, Tool Activity) moves down
the page rather than being deleted.

## 5. Security & backward compatibility

**Default behavior: additive.** A new read-only endpoint and a re-ordered tab.
No existing endpoint changes shape. No enforcement default changes. Nothing
breaks if this ships and nobody looks at it.

**Authz.** `/me/posture` requires the same tenant authentication as every other
`/me/*` route (API key or portal session). It exposes **no secrets** — control
names and modes only, never tokens, keys, or issuer configuration.

**What a malicious caller learns.** That a tenant's deployment has, say,
auto-revoke off. That is a real disclosure and worth stating plainly: it tells an
authenticated attacker which controls will not stop them. Judged acceptable
because the caller is already authenticated to that tenant, and the same facts
are inferable by observing whether actions are refused. If we later decide
otherwise, the mitigation is to gate `/me/posture` behind `is_admin` rather than
any tenant credential — noted, not done.

**No escape hatch needed**: no behavior-changing default.

## 6. Packaging & deploy

- **No new module.** §4.1 extends `api/routes_tenant_self.py`, already in the
  `Dockerfile.admin` COPY list. **No Dockerfile change.**
- **No new dependency.** `os` and the existing FastAPI imports only. No
  `requirements*.txt` change.
- **No new env flags.** This reads existing ones; it introduces none.
- **Rebuild:** admin image only. The data plane is untouched.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Clean tenant, no findings | Overview says so explicitly. Not four zeroes — an empty state that reads as "we looked" |
| A source endpoint 500s or times out | That row renders "unavailable", the rest still render. One failing finding must not blank the page |
| Redis down | Governance/AIBOM endpoints already degrade; Overview shows their degraded answer and **does not** claim zero findings. Reporting "0 shadow agents" during an outage is the dangerous failure and is explicitly excluded |
| No AIBOM snapshot taken | Drift row prompts to take a baseline instead of showing 0 — 0 drift with no baseline is meaningless |
| Very large tenant (1000s of agents) | Counts only on Overview; lists stay on their own tabs. Client-side unused-grant diff is over one response already fetched |
| Split deployment | `/me/posture` reports the **admin** process's environment. Response is labelled as such; §8 pins it |
| Unknown env value | Normalises to `off` — same convention as `key-scope` |

**Fail-open vs fail-closed:** the *display* fails open (a broken row does not
break the page), but it fails **loudly** — never silently as zero. This is a
reporting surface; a false "all clear" is worse than a visible error. This is the
same failure the LangChain demo had, where every error rendered as
`(no response)`.

## 8. Test plan (Definition of Done)

**`tests/test_posture_endpoint.py`** (new)
- every control reported, with `mode` reflecting its env var
- unset env → `off`, `enforcing: false`
- unknown value (`SHIELD_ROLE_BINDING=banana`) → normalises to `off`
- `next` is the following rung, never `enforce` from `off`
- `off_count` matches the controls listed
- no secret-shaped value in the response (assert no `sk-`, key, token, or issuer)
- requires tenant auth; unauthenticated → 401/403
- portal session authenticates it, not just an API key

**Regression guards**
- source-level: `/me/posture` reads `os.environ`, never `request` — a test that
  greps the handler, so a later refactor can't make posture caller-influenced
- guard-path spy: existing read-counting assertions still pass unchanged,
  proving no guard-path coupling was added
- `tests/test_admin_dockerfile_imports.py` passes (no new module, but the
  guard should stay green)

**Frontend** — not unit-tested (no JS harness in this repo). Verified by hand
against a seeded tenant covering: all four findings present; none present; one
endpoint failing; no AIBOM baseline. Recorded in the PR description, since an
untested frontend claim is exactly the class of thing that shipped broken before.

**Definition of done:** full suite green in a clean venv
(`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`),
CI `pytest` gate passes.

## 9. Task breakdown (proposed PRs)

1. **`GET /v1/tenant/me/posture`** — endpoint + `tests/test_posture_endpoint.py`.
   Backend only, no UI. Independently reviewable and independently useful (it is
   also the answer to "what is this deployment enforcing?" for a support call).
2. **Overview findings list** — frontend only, consuming §4.1 plus the three
   existing endpoints. No backend change, so it cannot regress the API.
3. *(Optional, separate)* Empty-state and baseline prompt polish, if (2) shows
   the empty case needs more than a sentence.

Two PRs, in that order; (2) depends on (1). Neither touches the data plane.

## 10. Open decisions

1. **Should `/me/posture` require `is_admin`** rather than any tenant credential?
   §5 argues the disclosure is acceptable; the conservative choice is admin-only.
   Cheap now, breaking later.
2. **Split deployments** — is reporting only the admin process's environment
   acceptable for v1? The alternative is having the data plane publish its own
   posture and the admin plane fetch it, which is a real feature and probably its
   own spec.
3. **Does Overview keep the activity panels at all**, or do they move to
   `guardrail-metrics` entirely? This spec keeps them below the findings; deleting
   them is defensible and is a product call rather than a technical one.
