---
name: spec
description: >-
  Write a spec for a Shield feature BEFORE coding (spec-first / agentic
  engineering, not vibe coding). Use when the user wants to build, design, or
  scope a feature/endpoint/change, or types /spec. Produces a filled spec from
  docs/spec-template.md, enforces the repo invariants, and pauses for approval
  before any implementation.
---

# Spec-first workflow for LLM Shield

When this skill runs, **do not write feature code yet.** Produce a spec and stop
for approval. Steps:

1. **Read the template** at `docs/spec-template.md` and the invariants in
   `CLAUDE.md`. Use them as the structure and the hard checklist.

2. **Fill the spec** for the requested feature. Sections (all required):
   1. Problem & outcome (+ non-goals)
   2. Plane & latency contract — data (GPU) vs admin (CPU); does it touch the
      guard path (`/guardrails/*`, `cap/mint`, `tools/call`)?
   3. Data model — exact Redis keys, shapes, TTLs, tenant scoping
   4. API / interface — endpoints, request/response, auth header, which plane mounts it
   5. Security & backward compatibility — default behavior; opt-in vs breaking; escape-hatch flag + migration if defaults change
   6. Packaging & deploy — `Dockerfile.admin` COPY for new admin imports; new deps → `requirements.txt` + `requirements-test.txt` (+ admin); env flags; which image to rebuild
   7. Failure modes & edge cases — empty/null/huge, Redis down, model slow, missing optional module, concurrency; fail-open vs fail-closed
   8. Test plan (Definition of Done) — unit tests per edge case; regression guard for drift-prone couplings; clean-venv green; CI passes

3. **Investigate before asserting.** Read the relevant code (routes, storage,
   Dockerfiles, requirements) to fill the spec with real key names, planes, and
   call sites — don't guess. Ask the user only the decisions you genuinely can't
   infer (e.g., opt-in vs breaking default, which plane).

4. **Flag invariant risks explicitly** in the spec: if the feature adds an admin
   import, a new dependency, a default change, or anything on the hot path, call
   it out with the mitigation.

5. **Scope into tasks** — propose the PR breakdown (one small, reviewable task
   each), in order.

6. **Pause for approval.** Present the spec + task breakdown and ask the user to
   confirm or adjust. Implement only after approval, one scoped task per PR, with
   tests, and verify the full suite in a clean venv.
