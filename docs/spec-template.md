---
title: Spec Template (how we build)
layout: default
nav_order: 23
permalink: /spec-template/
description: Spec-first workflow for Shield — write the spec before any code. The template encodes the repo's hard invariants (planes, latency, packaging, deps, tests) so features can't repeat past incidents.
---

# Spec template — how we build
{: .no_toc }

We build spec-first, not vibe-coded. Write the spec **before** prompting an agent
or writing code. The agent (or you) executes scoped tasks against the spec; you
review with PR rigor and ship only when tests pass. This template bakes in the
invariants that caused past production incidents, so each one is a checklist item.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## The workflow
1. **Spec first** — fill the template below. You may draft it with AI, but *you* own it, before any file changes.
2. **Scope into tasks** — one PR = one small, constrained, reviewable task. No "build me X" prompts.
3. **Review with PR rigor** — read the diff; if you can't explain a function, it doesn't merge.
4. **Test relentlessly** — tests you specified (not skimmed); full suite green in a **clean venv**; CI gate passes.

## Copy this spec

```markdown
# Spec: <feature name>

## 1. Problem & outcome
- What it does, for whom, observable success condition.
- Non-goals (explicitly out of scope).

## 2. Plane & latency contract
- Plane: data (GPU/vLLM) or admin (CPU portal)? Both?
- Touches the GUARD PATH (/guardrails/*, cap/mint, tools/call)?
  - Yes -> latency budget + justification.
  - No  -> state "off hot path, no guarded-traffic impact."

## 3. Data model
- Redis keys (exact), value shapes, TTLs.
- Tenant scoping: how tenant_id resolves; cross-tenant isolation argument.

## 4. API / interface
- Endpoints: method, path, request/response shape, status codes.
- Auth header(s); which plane(s) mount the router.

## 5. Security & backward compatibility
- Default behavior: opt-in, or does it change existing behavior?
- If it changes defaults -> migration path + escape-hatch env flag.
- Authz: who may call it; what a malicious caller can/can't do.

## 6. Packaging & deploy
- New module imported by admin_app.py -> add to Dockerfile.admin COPY list.
- New pip dep -> requirements.txt (runtime) AND requirements-test.txt;
  add to requirements-admin.txt if the admin plane uses it.
- Env flags, rollout steps, which image(s) to rebuild.

## 7. Failure modes & edge cases
- Empty/null/huge inputs, Redis down, model slow, missing optional module,
  concurrent writes.
- Fail-open vs fail-closed decision, stated explicitly.

## 8. Test plan (Definition of Done)
- Unit tests: happy path + every edge case in §7.
- Regression guard for drift-prone couplings (e.g. Dockerfile <-> imports).
- Full suite green in a clean venv; CI "pytest" gate passes.
```

## Repo invariants (each one is a past incident)
Every spec must satisfy these — they're enforced in review and by the PR template:

- **Off the hot path.** Governance/portal/analytics features must not add latency to `cap/mint` / `tools/call` / `/guardrails/*`.
- **Admin image is a curated allowlist.** Any new module `admin_app.py` imports must be added to `Dockerfile.admin` (it copies files individually). Guarded by `tests/test_admin_dockerfile_imports.py`.
- **Declare dependencies.** New pip imports go in `requirements.txt` (runtime) and `requirements-test.txt` (CI); a local venv can hide a missing dep — validate in a **clean venv**.
- **Secure by default, but non-breaking.** Behavior-changing defaults must be opt-in or shipped with an escape-hatch env flag and a migration note.
- **Clean-venv test run** before trusting green; CI `pytest` gate must pass.
- **Don't strand companion fixes.** If a change needs a dep/Dockerfile/CI update to pass, put them in the *same* PR.

## Scoping: bad vs good
- Bad (vibe): *"Add agent governance."* — agent invents the data model, plane, and API.
- Good (agentic): *"Add `GET /v1/governance/agents` on the admin plane, read-only over `agents:{tenant}` + `unregistered:{tenant}` + `agent_auth_stats`, no guard-path writes. Response `{count, registered_count, shadow_count, agents:[...]}`. Tenant via `X-API-Key`. Tests for registered + shadow + empty. Per the spec."*
