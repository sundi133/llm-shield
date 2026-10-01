---
title: LiteLLM guardrail (config only)
layout: default
nav_order: 30
permalink: /litellm-generic-guardrail/
description: Put Votal Shield in front of every model behind a LiteLLM proxy with a few lines of config. Uses LiteLLM's Generic Guardrail API, so there is no plugin code to install.
---

# LiteLLM guardrail, config only
{: .no_toc }

Add Shield to a LiteLLM proxy by editing its config. Shield implements
LiteLLM's Generic Guardrail API, so LiteLLM calls Shield directly before and
after each model call. There is no plugin file to copy into your LiteLLM image.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Set it up

1. Get a Shield tenant API key from the portal and set it where LiteLLM runs:

   ```bash
   export VOTAL_API_KEY=<your tenant key>
   ```

2. Add the guardrail to your LiteLLM config:

   ```yaml
   guardrails:
     - guardrail_name: votal-shield
       litellm_params:
         guardrail: generic_guardrail_api
         mode: [pre_call, post_call]
         api_base: https://api.guardrails.votal.ai
         api_key: os.environ/VOTAL_API_KEY
         default_on: true
   ```

3. Restart LiteLLM.

`api_base` is your Shield data plane address. LiteLLM adds
`/beta/litellm_basic_guardrail_api` to it. A complete example with every
option below is in `config/litellm_generic_guardrail.example.yaml`.

In the LiteLLM UI, choose **Generic Guardrail API** when adding a guardrail and
enter the same values.

## What Shield checks

| When | What | Result |
|---|---|---|
| Before the model call (`pre_call`) | The new user message, with earlier turns as context | Blocked prompts never reach the model |
| Before the model call, in an agent loop | The results of the tools the model just called | Your tool data policy applies. A redacted result is what the model sees |
| After the model call (`post_call`) | The model's response | Blocked, or returned with sensitive data redacted |
| After the model call | Each tool call the model asks for | Blocked when your tool policy denies it |

Your tenant's policy decides, exactly as it does when you call Shield
directly. A tenant in monitor mode records what would have been blocked and
blocks nothing.

Shield does not re-check the whole conversation on every turn. LiteLLM sends
the full history each time; Shield checks what is new since the model last
replied. Your system prompt is not checked.

## What your users see

A blocked request returns an error from LiteLLM with Shield's reason:

```json
{"error": {"message": "Blocked by Votal Shield: keyword_blocklist: Blocked keyword(s) detected: ...",
           "type": "invalid_request_error", "code": "400"}}
```

A redacted response looks like any other response, with the sensitive value
replaced:

```json
{"choices": [{"message": {"role": "assistant",
              "content": "You can reach Alice at [REDACTED] for the report."}}]}
```

## Identify the agent and the user's role

Tool authorization in Shield is by agent and role. LiteLLM hides client headers
from guardrails unless you list them, so add:

```yaml
        extra_headers: [x-agent-key, x-user-role]
```

Clients then send `x-agent-key` (the agent's name in your Shield registry) and
`x-user-role` on their requests to LiteLLM.

- Without `x-agent-key`, tool data policies and guardrails still run, but
  role-based tool authorization does not.
- A role sent by a client is a claim, not proof. If your Shield uses role
  binding in `strict_proxy` mode (`SHIELD_ROLE_BINDING`), it accepts the role
  only when LiteLLM also proves it is your proxy. Add the shared secret
  (Shield's `SHIELD_TRUSTED_PROXY_SECRET`) as a static header:

  ```yaml
          headers:
            X-Shield-Proxy-Token: "<the shared secret>"
  ```

  LiteLLM reads `os.environ/` only for `api_key` and `api_base`. Values under
  `headers` are sent as written, so keep a config that contains one out of
  source control.

Shield records the LiteLLM user, team, key alias, model and call id with each
call, so you can trace a decision back to the LiteLLM request.

## Streaming

By default LiteLLM checks a streamed response every 5 chunks and can only stop
the stream. Text that Shield would redact has already reached the client.

To redact streamed text, add:

```yaml
        streaming_transform_mode: incremental_diff
```

LiteLLM then holds each piece of the stream until Shield has checked it and
sends Shield's version.

Each check is a full Shield pass over the text so far. To make fewer checks:

| Setting | Effect |
|---|---|
| `streaming_sampling_rate: 20` | Check every 20 chunks instead of every 5 |
| `streaming_end_of_stream_only: true` | Check once, at the end. Cheapest, but the text has already been streamed when Shield sees it |

## If Shield is unavailable

LiteLLM decides, not Shield. The defaults block the request:

| Setting | Default | Meaning |
|---|---|---|
| `unreachable_fallback` | `fail_closed` | Shield cannot be reached: block. `fail_open` lets the request through |
| `fail_on_error` | `true` | Shield returned an error: block. `false` lets the request through |

Shield never answers "allowed" when a check fails. It returns an error and
LiteLLM applies these settings.

## Several tenants

One guardrail entry uses one Shield tenant key. For several tenants, add one
entry per tenant, each with its own key, and attach each to the right LiteLLM
keys or teams. The tenant cannot be chosen by anything in a request.

## Shield on RunPod

When Shield runs on RunPod with your own model, RunPod needs its bearer token
as well as the tenant key:

```yaml
        api_base: https://<your-pod>.proxy.runpod.net
        api_key: os.environ/VOTAL_API_KEY
        headers:
          Authorization: "Bearer <your RunPod token>"
```

The header value is sent as written (see the note on `headers` above).

## Limits

- **Prompts are blocked, not redacted.** Shield redacts responses and tool
  results. A prompt policy set to "redact" blocks the prompt through LiteLLM,
  because passing it unchanged would leak what the policy meant to remove. To
  let such prompts through instead, set `SHIELD_LITELLM_UNREDACTABLE=pass` on
  Shield.
- **Tool calls are allowed or blocked,** never rewritten.
- **Images and tool definitions are not checked.**
- **Indirect prompt injection in tool results** is checked by Shield's
  [MCP gateway]({{ "/litellm-mcp-gateway/" | relative_url }}), not by this integration. Use both for
  agents that call tools.
- LiteLLM marks this API as beta. This page was checked against LiteLLM
  1.103.2.

## Or use the plugin

Shield also ships a LiteLLM plugin, `votal_guardrail.py`. Use it when you need
one of these:

| | Config only (this page) | Plugin |
|---|---|---|
| Setup | LiteLLM config | plugin file in your LiteLLM image |
| Hosted LiteLLM, LiteLLM UI | yes | no |
| Shield tenant | one per guardrail entry | chosen per request |
| Verified agent tokens, delegated user tokens | no | yes |
| Redacted responses | yes | no |

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every request fails with "Generic Guardrail API failed" and a 401 | `VOTAL_API_KEY` is missing or is not a tenant key, and Shield requires one |
| Your tenant's policy does not seem to apply | The key is not a tenant key. Unless Shield requires a key, it then applies its default policy |
| The same, with a 404 | `api_base` points at the portal, not the Shield data plane, or Shield is older than this feature |
| Nothing is ever blocked | The tenant is in monitor mode, or `default_on` is off and clients are not sending `"guardrails": ["votal-shield"]` |
| Tool calls are never denied | `x-agent-key` is not in `extra_headers`, or clients do not send it |
| Streamed responses are not redacted | `streaming_transform_mode: incremental_diff` is not set |
