---
title: "Spec: Tool policy editor"
layout: default
nav_exclude: true
permalink: /specs/tool-policy-editor/
description: Replace the raw JSON on the Tool Policies screen with a form for the default policy and for each tool, with ready-made protections to tick and custom rules as an editable list.
---

# Spec: Tool policy editor

> Status: **APPROVED** 2026-10-04. Tasks 1 and 2 implemented; see the notes at the end.

## 1. Problem & outcome

**Problem.** The Tool Policies screen (`static/tenant.html`) is where ops set
the rules every MCP tool call and result is checked against. The **default
policy (all tools)** is a raw JSON textarea (`loadGlobalDataPolicy`,
`saveGlobalDataPolicy`); the per-tool **Configure** modal (`openDataPolicyModal`)
is a partial form whose rules are one multi-line textarea per role. Ops have to
write JSON, know field names, and know traps the screen does not explain:

- a secret pattern with `severity: critical` always **blocks the whole result**,
  whatever action it says (`core/dlp/floor.py: resolve_action`);
- a pattern's replacement is inserted **literally** (no `\1`);
- the pattern preview runs in the browser with JavaScript regex, but the server
  uses Python's `regex` module, so a preview can disagree with enforcement
  (JavaScript rejects `(?i)`, for example).

**Outcome.** One editor, used for both the default policy and each tool:

```
┌ Default policy (all tools) ─────────────────────────── [On] ┐
│ Ready-made protections                    [Tick recommended] │
│  Tool calls     ☑ Command injection (T21)   ☑ SQL injection (T22)   ...
│  Tool results   ☑ Injected instructions (T2) ☑ Unsafe HTML/script (T25) ...
│  Secrets        ☑ AWS keys  ☑ GitHub tokens  ☑ Private keys  ...
│ Your rules                                                    │
│  Tool calls     [ BLOCK sending email outside acme.com     ] 🗑│
│                 + Add rule                                    │
│  Tool results   + Add rule                                    │
│  Secret patterns  name | pattern | replace with | on    + Add │
│ Try it  [ paste a tool call or result ]  →  allowed / blocked │
│ ▸ Advanced: edit as JSON                                      │
│                                                      [ Save ] │
└───────────────────────────────────────────────────────────────┘
```

- Each ready-made protection shows a plain name and its threat number;
  expanding it shows the exact rule text.
- Custom rules are one line each, added and removed individually.
- **Try it** runs the real server engine (§4), so what it shows is what will
  happen.
- JSON stays under **Advanced** for anyone who wants it; both views edit the
  same policy.

**Non-goals.** No change to how policies are evaluated on the guard path, to
the stored policy format, or to the fail-open behaviour of the model-judged
rules (a separate change). No new roles UI: the default policy applies to
everyone (role `*`); the per-tool modal keeps its existing per-role cards and
each card gets this editor.

## 2. Plane & latency contract

- **Admin plane** (portal + existing `/v1/data-policies/*` routes, mounted on
  both planes). The guard path keeps reading the same stored policies:
  **off hot path, no guarded-traffic latency impact.**
- "Try it" calls the server on demand from the portal only.

## 3. Data model

**No change to the stored policy.** The editor reads and writes the existing
shape (`GlobalDataPolicy` / `ToolDataPolicy`: `role_policies[].input_rules`,
`output_rules`, `sanitization_rules[]`). A ready-made protection is stored as
its rule text, which starts with its tag (`[T21 Command injection] ...`); the
editor recognises a rule as ticked when a stored rule starts with that tag.
Editing a ready-made rule's text turns it into a custom rule.

**Library** (`core/policy_library.py`, code, versioned): each entry has `id`
(`T21`), `name`, `threats`, `side` (`call` | `result` | `secret`),
`recommended` (bool), and either `rule` (text) or `pattern`
(`regex`, `replacement`), seeded from the 37 rules and patterns already
validated for the default policy. Secret patterns are saved as
`severity: high, action: redact` so they never trip the critical-blocks trap.

## 4. API

- `GET /v1/data-policies/library` → the library. Auth as the other
  `/v1/data-policies/*` routes.
- `POST /v1/data-policies/try` body `{"policy": {...}, "tool_name": "...",
  "arguments": {...}}` or `{"policy": {...}, "tool_name": "...", "result": "..."}`
  → runs the same functions the guard path runs (`evaluate_payload_policy_llm`
  for a call; `core.dlp.floor.evaluate` plus the sanitizer's model pass for a
  result) against the **unsaved** policy and returns
  `{"decision": "allowed" | "blocked" | "redacted", "reason", "sanitized"}`.
  Nothing is stored. Same limits as the existing
  `/v1/data-policies/preview-sanitization` (the tenant quota; neither endpoint
  has its own rate limit).

## 5. Security & backward compatibility

- **Additive.** Existing policies load into the form unchanged; a policy the
  form cannot represent (fields it does not show) is saved back with those
  fields intact, and the editor says "also contains advanced settings".
- Saving a default policy that blocks keeps the existing confirmation.
- Severity is not shown for secret patterns; a "block the whole result"
  checkbox sets it explicitly when wanted.

## 6. Packaging & deploy

- **New module `core/policy_library.py`, imported by
  `api/routes_data_policies.py`, which `admin_app.py` imports: add it to
  `Dockerfile.admin`'s COPY list** (guarded by
  `tests/test_admin_dockerfile_imports.py`). Same PR as the module.
- No new dependencies, no env flags. Rebuild admin and data-plane images.

## 7. Failure modes & edge cases

- Library unavailable: the form still works with custom rules only.
- "Try it" model call fails: shows "could not be checked; on the live path this
  call would currently be ALLOWED (model rules fail open)". Honest about today's
  behaviour.
- A custom pattern that does not compile on the server: rejected at save with
  the server's message (`_reject_invalid_floor`), shown next to the row.
- Very long rule text: capped at 1,000 characters per rule.

## 8. Test plan (Definition of Done)

- Library: every entry validates through `GlobalDataPolicy` and
  `_reject_invalid_floor`; every secret pattern redacts a realistic sample and
  leaves clean text alone (the checks run by hand for the current default
  policy, made permanent); no pattern is `critical`.
- `try`: a call that should be blocked is blocked, a clean call is allowed, a
  result with a secret comes back redacted; the unsaved policy is used and
  nothing is stored.
- Round trip: load a policy, tick/untick, add/remove custom rules, save;
  stored JSON equals what the Advanced view shows; unknown fields preserved.
- Portal wiring test for both editors and both endpoints.
- `tests/test_admin_dockerfile_imports.py` green; full suite green in a clean
  venv.

## Tasks (one PR each, in order)

1. **Library and try endpoint**: `core/policy_library.py`, `GET /library`,
   `POST /try`, `Dockerfile.admin` COPY, tests.
2. **Default policy editor**: replace the JSON textarea with the form (library
   ticks, custom rule lists, secret pattern rows, Try it, Advanced JSON).
3. **Per-tool editor**: the Configure modal's role cards use the same editor.

## Task 1 notes (as built)

- **Library ids are side-qualified** (`call.T21`, `result.T2-T3-T42`,
  `secret.aws_access_key`), not bare `T21`: several threat numbers have both a
  call rule and a result rule. Each entry also carries its `tag`, the prefix the
  editor matches stored rules on. 37 entries, 36 recommended; `call.T12`
  (exfiltration) is not recommended because its text needs your domains
  (`"needs": "<your-domains>"`).
- **One change on a live-path function, opt-in:** `evaluate_payload_policy_llm`
  gained a keyword-only `raise_errors=False`. With the default it still returns
  None when the model fails (fail open, unchanged; pinned by
  `test_live_traffic_still_fails_open`). The dry run passes `True` so a model
  failure reads "not checked", never "allowed".
- **The result dry run reuses the live sanitizer** through a subclass that reads
  the policy under test instead of the store, and calls `_check_inner` so the
  taint-recording wrapper never runs.
- Found while building, not changed here: `POST /v1/data-policies/validate`
  evaluates patterns with the stdlib `re` module and `re.sub`, a third regex
  behaviour next to the enforcing `regex` engine and the portal's JavaScript.

## Task 2 notes (as built)

- The default-policy card is the form (`peMount('gdp-editor', 'gdp', ...)` in
  `static/tenant.html`); the raw JSON textarea is gone, JSON lives under
  Advanced. State and rendering are pure functions (`peStateFrom`,
  `pePolicyFrom`, `peValidate`, `peRenderHtml`) tested under node
  (`tests/test_tool_policy_editor_portal.py`); the editor id and wiring are
  ready for the per-tool modal (task 3).
- The form starts from the whole stored policy and replaces only what it edits,
  so allowlist, thresholds, exact-match lists, compliance framework,
  sanitization intent and other roles' rules survive a save; the card says when
  a policy carries them.
- A stored custom pattern with `severity: critical` is saved back as
  `severity: high` with `action: block`: it still blocks, explicitly, and
  unticking "block whole result" now actually stops blocking.
- A policy in `sanitization_mode: "ai"` that gains secret patterns is switched
  to `"both"`, since `"ai"` skips the patterns entirely.
- Verified in the portal (local admin app, tenant `bank-co`): tick recommended,
  the domain rule's field, a custom rule, Try it (result with secrets came back
  "Not checked" with both secrets redacted, as no model was running), save,
  reload: the form rebuilt from the stored policy matches. Note for local runs:
  data-policy storage needs Redis (no in-memory fallback), so saving fails with
  "Redis connection not available" without one; this predates the editor.
