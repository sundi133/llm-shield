# Spec: guardrails honor each tenant's own settings

Status: **implemented** on branch `fix/guardrail-per-request-settings`.
Found while writing docs/specs/policy-scopes.md (its task 0b).

## 0. Migration note (read before deploying)

**Behavior change on the guard path.** Five guardrails ignored the settings a
tenant saved and always used the server's own values. They now use the
tenant's. A tenant that saved its own `patterns`, `max_chars`, `max_tokens`,
`min_polarity`, `max_requests` or `extra_patterns` gets them enforced, which
can block traffic that passed before. That is the fix, but it is a live change.

Nothing changes for a tenant that didn't set a value: a setting the tenant left
out still reads the server's value, exactly as before.

Before deploying:

1. Find the affected tenants: those whose `input_guardrails` name one of the
   five guardrails below **with a non-empty `settings`** that differs from the
   server's. Their traffic is what changes.
2. For a tenant whose saved values were never tested, set its `policy_mode` to
   `monitor` first, review the would-be blocks, then go back to `enforce`.
3. If live traffic breaks, set `SHIELD_GUARDRAIL_SETTINGS_SERVER_ONLY=1` to
   restore the previous behavior for every tenant while you investigate. Read
   live, so no restart is needed. Prefer moving one tenant to `monitor` over
   leaving the flag on.

| Env flag | Default | Effect |
|---|---|---|
| `SHIELD_GUARDRAIL_SETTINGS_SERVER_ONLY` | unset (tenant settings honored) | `1`/`true`/`yes`/`on`: every tenant gets the server's settings for these five guardrails, as before this change. |

The rate limiter's counters are also now kept per tenant (see section 3); every
counter starts from zero once on deploy, which can only let more through for at
most one window.

## 1. Problem & outcome

`regex_pattern`, `length_limit`, `sentiment`, `rate_limiter` and
`system_prompt_leak` copied `self.settings` in `__init__`. The registry builds
one shared instance of each at startup, outside any request, so that copy was
always the server's config (`config/default.yaml` or `CONFIG_PATH`). A tenant's
values were stored, shown in the portal, and silently ignored, on
`/guardrails/*`, the chat proxies, and in team policies.

| Guardrail | Ignored tenant settings |
|---|---|
| `regex_pattern` | `patterns` |
| `length_limit` | `max_chars`, `max_tokens`, `encoding` |
| `sentiment` | `min_polarity`, `action` |
| `rate_limiter` | `max_requests`, `window_seconds` |
| `system_prompt_leak` | `extra_patterns` (built-in patterns always applied) |

Outcome: each check reads its settings for the current request. Two tenants
with different values get different results.

Non-goals: changing any guardrail's semantics (sentiment still takes its action
from `settings.action`, the rate limiter still always blocks); other guardrails,
which already read per request.

## 2. Plane & latency contract

Data plane, guard path. A settings read per check is a dict lookup on the
request's config. Compiled regexes are cached by their exact settings (bounded
at 512 distinct sets, like `keyword_blocklist`'s automaton cache), and tiktoken
encoders by name, so nothing compiles per request.

## 3. Design

- `BaseGuardrail.setting(key, default)`: the tenant's value if the tenant's
  settings contain `key`, else the server's value, else `default`. The fallback
  is what keeps this non-breaking: the code defaults differ from
  `default.yaml` (rate_limiter: 100 requests per minute in code, 10,000,000 on
  the server), so an empty tenant row must keep reading the server's value.
- A key the tenant set explicitly wins, including an empty list
  (`patterns: []` means no patterns for that tenant).
- `rate_limiter` keys its counter by tenant as well as client
  (`rate_limit:{tenant}:{client}`). With per-tenant limits, two tenants'
  `anonymous` callers or a shared agent name must not spend one budget.
- A test walks every `__init__` under `guardrails/` and fails if one reads
  `self.settings` or `self.configured_action`, so the bug can't come back
  in a new guardrail.

## 4. Failure modes

| Case | Behavior |
|---|---|
| Invalid regex in a tenant's patterns | Skipped with a warning, as before; the valid ones still apply |
| Unknown tiktoken `encoding` | Token counting off for that encoding (warned once); character limit still applies |
| tiktoken or textblob not installed | As before: token counting off / sentiment passes |
| No tenant request (server-wide config) | The server's values, as before |

## 5. Test plan

`tests/test_guardrail_per_request_settings.py`: for each guardrail, two tenants
with different values get different results; a tenant row without the key keeps
the server's value (including the rate limiter's 10,000,000); an explicit empty
list wins; per-tenant rate budgets; built-in prompt-leak patterns always apply;
compiled once per pattern set; end to end through `run_tenant_pipeline`; the
escape hatch, read live; the `__init__` tripwire. Against the code before this
fix, 13 of these fail.
