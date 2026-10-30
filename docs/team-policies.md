---
title: Team policies (policy scopes)
layout: default
nav_order: 76
permalink: /team-policies/
description: "Give each team inside one tenant its own input and output guardrails, picked by a request header you choose, on top of a global policy no team can weaken. Works for header values you don't know in advance."
---

# Team policies
{: .no_toc }

One customer usually has many teams. Team policies let you keep one **global**
policy for the whole tenant and add a **local** policy per team, chosen by a
request header you already send, such as `X-Org-Id` or `X-Team-Id`.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## How it works

1. You name the header (or headers) that identify a team.
2. Each guarded request's header value picks a **team rule**: by exact value
   (`team-a`) or by pattern (`eng-*`).
3. Shield runs the global policy **plus** that rule's additions.

A team policy can only make things stricter:

| A team can | A team cannot |
|---|---|
| Add guardrails | Turn off a guardrail the global policy has on |
| Raise an action (warn to block) | Lower an action (block to warn) |
| Add keywords, patterns, blocked topics | Remove a global keyword or pattern |
| Narrow allowed languages, topics or domains | Widen them |
| Change a guardrail's settings, if you mark the global guardrail `delegable` | Change settings you haven't delegated |

So no header value, real or made up, ever gets less protection than the
global policy. That matters because a header is whatever the caller sends.

Team policies apply to `/guardrails/input`, `/guardrails/output`,
`/guardrails/file`, the OpenAI-compatible proxy, the gateway proxy and agent
chat. Tool calls and MCP are not affected.

## Set it up in the portal

Open **Input & Output Guardrails**. The **Editing policy for** bar sits above
your guardrails.

1. **Name your header.** Click **Team settings**, enter the header (for
   example `X-Org-Id`), turn on **Apply team policies to live traffic**, and save. The badge
   next to **Editing policy for** changes to **Live**.
   You don't need any rules yet.
2. **Watch what arrives.** Send traffic as usual. **Discovered values** lists
   every value seen on your header, how many requests carried it, and which
   policy it gets today.
3. **Create a rule.** Click **Create rule** next to a value, or **+ New team rule**.
   Enter a team name and the header values its requests carry, then
   **Create team rule**. You can add a pattern such as `eng-*` afterwards to
   cover teams that don't exist yet.
4. **Edit the team's guardrails.** The page shows the same guardrail cards:
   - rows marked **Global** come from the global policy; you can pick a
     stricter action or add to their lists, nothing else;
   - **+ Add guardrail** adds one for this team only.
5. **Save Changes** saves the selected team. **Global** takes you
   back to the global policy, which works exactly as before.
6. **Try it.** Enter a header value to see which policy a request would get.
   It reflects a save immediately; live traffic picks changes up within a
   minute.

**Other values** is the policy for any value no rule matches, including
values you have never seen. Leave it empty to give them the global policy.

## Header values you don't know in advance

You don't have to list your teams up front:

- **Discovered values** shows every value as soon as traffic carries it.
- **Patterns** (`eng-*`, `*-prod`) match values that appear later.
- **Other values** gives brand-new teams a sensible baseline on their first
  request.

Values are compared after trimming spaces and lowercasing, so `TeamA`,
` teama ` and `teama` are the same team.

## Changing the header name

Rules belong to values, not to a header name, so renaming a header loses
nothing:

1. In **Team settings**, list the new header first and keep the old one:
   `X-Team-Id, X-Org-Id`. The first header present on a request wins.
2. Move your clients to the new header.
3. **Discovered values** shows which header each value arrived on. When the old
   header stops appearing, remove it.

## Stop one team from using another's policy

Because a header is set by the caller, any app holding your tenant key could
claim any team. The global policy still applies to all of them, but a team
could pick another team's rule. To prevent that, give each team its own API
key and **lock** it to that team:

1. Create a key per team on the **API keys** page, labelled with the team.
2. On **Input & Output Guardrails**, find the **Team keys** card.
3. Next to the team's key, enter the teams it may claim (for example `team-a`,
   or a pattern such as `eng-*`) and click **Lock**.

A locked key that claims another team gets `403 policy_scope_not_allowed`. A
key locked to exactly one team gets that team when it sends no header.
**Unlock** lets it claim any team again. Keys created together with the
workspace can't be locked; the card says so.

The same over the API (the path ends with the key's first 12 characters):

```bash
curl -X PUT "$SHIELD/v1/tenant/me/policy-scopes/key-bindings/sk-acme-team" \
  -H "X-API-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"allowed": ["team-a"]}'
```

If the header is added by your own gateway rather than by apps, you don't need
to lock keys.

## Behind LiteLLM or an AI gateway

When a gateway calls Shield's LiteLLM guardrail route
(`/beta/litellm_basic_guardrail_api`), your callers' headers don't reach
Shield as headers. The gateway copies them into the request body as
`request_headers`. Shield looks there too, on that route only:

1. In **Team settings**, enter the header your callers send, exactly as it
   appears in `request_headers` (for example `x-tf-api-key-id`). Upper or
   lower case doesn't matter.
2. Make sure the gateway forwards the header's value. LiteLLM sends
   `"[present]"` instead of the value for headers it isn't told to forward;
   list yours under the guardrail's `extra_headers`:

   ```yaml
           extra_headers: [x-tf-api-key-id]
   ```

   Shield treats `"[present]"` as no header, so until this is set every call
   gets the **When no team header is sent** behaviour.
3. Send a request through the gateway and check **Discovered values**. The
   value appears under your header name.

If a request carries the header both as a real header and in the body, the
real header is used. Other routes, such as `/guardrails/input`, read real
headers only.

When the gateway fills the header in itself (for example from the
authenticated gateway key, as `x-tf-api-key-id` is), check that it overwrites
a value a client sends rather than passing it through. Otherwise a client
could pick another team's rule (never anything weaker than the global
policy); lock keys as described above if you can't rule that out.

**Upgrading:** before this release, team headers inside `request_headers`
were ignored and those calls got the global policy. Now they get their team's
policy, which can only add to the global one. To keep the old behaviour, set
`SHIELD_POLICY_SCOPE_BODY_HEADERS=off`.

## What a request sees

Each response from `/guardrails/input`, `/guardrails/output` and
`/guardrails/file` names the policy that ran:

```json
"policy_scope": {"rule": "team-a", "value": "teama", "header": "X-Org-Id"}
```

Every covered response also carries the header `X-Shield-Policy-Scope: team-a`,
including the chat proxies. `rule` is `global` when no header was sent and
`unmatched` when the unmatched policy applied. The same field is in the audit
log. Tenants that don't use team policies see no change.

| Situation | Result |
|---|---|
| No team header | Global policy, or `403 policy_scope_required` if you chose **Refuse the request** |
| Header sent twice with different values, or with characters outside letters, digits and `. _ - : @ /` | Treated as invalid: the unmatched policy, or global if you have none |
| A change saved in the portal | Live traffic within a minute; **Try it** at once |

## API

Everything in the portal is available over the API, with the tenant's key or a
portal session. Writes need the same permission as editing the global policy.

| Method and path | Purpose |
|---|---|
| `GET /v1/tenant/me/policy-scopes` | Current settings and rules, plus warnings for rules a later global change made stale |
| `PUT /v1/tenant/me/policy-scopes/settings` | Headers, missing-header behavior, unmatched policy, on or off |
| `PUT /v1/tenant/me/policy-scopes/rules/{rule_id}` | Create or replace a team rule |
| `DELETE /v1/tenant/me/policy-scopes/rules/{rule_id}` | Delete a team rule |
| `PUT` / `DELETE /v1/tenant/me/policy-scopes/key-bindings/{key_prefix}` | Bind a key to teams, or unbind it |
| `POST /v1/tenant/me/policy-scopes/preview` | Which rule a set of headers lands in, and the policy it would run |
| `GET /v1/tenant/me/policy-scopes/discovered` | Values seen in the last 30 days |

A rule that would weaken the global policy is refused with `422` and a list of
every reason. Send `expected_version` from your last read to get `409` instead
of overwriting someone else's change.

```bash
curl -X PUT "$SHIELD/v1/tenant/me/policy-scopes/rules/engineering" \
  -H "X-API-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"match": {"glob": ["eng-*"]},
       "input_guardrails": {"keyword_blocklist": {"enabled": true, "action": "block",
                            "settings": {"keywords": ["payroll"]}}}}'
```

Platform operators have the same routes under
`/v1/admin/tenants/{tenant_id}/policy-scopes`.

## Limits

| Limit | Value |
|---|---|
| Team rules | 200 |
| Exact values per rule | 20 |
| Patterns, all rules together | 100 |
| Team headers | 5 (credential headers such as `Authorization` and `X-API-Key` are refused) |
| Discovered values kept | 2,000 per tenant for 30 days; further new values are counted as `(overflow)` |

## For operators

| Environment variable | Effect |
|---|---|
| `SHIELD_DISABLE_POLICY_SCOPES=1` | Every tenant gets its global policy only. Takes effect without a restart. |
| `SHIELD_POLICY_SCOPE_DISCOVERY=off` | Stop recording discovered values. |
| `SHIELD_POLICY_SCOPE_FLUSH_SECONDS` | How often discovered values are written to Redis (default 15). |
| `SHIELD_POLICY_SCOPE_BODY_HEADERS=off` | Don't read team headers from `request_headers` in LiteLLM guardrail calls; real headers only. Takes effect without a restart. |

Selecting a team adds a few microseconds to a guarded request (about 2.5 µs
median, 6 µs p99, measured with 200 rules), with no network or database call,
and nothing measurable for tenants that don't use team policies.
On the LiteLLM route, a tenant with team policies also pays for reading the
team header from the body: about 0.1 ms median, 0.2 ms p99 for a 100 KB body.
The guardrails a team adds cost what they always cost: a custom LLM policy adds
an LLM call to that team's requests.
