---
title: Integration runbook
parent: LiteLLM guardrail (config only)
nav_order: 1
permalink: /litellm-runbook/
description: Step by step, with an expected result for every step. Connect a LiteLLM proxy to Votal Shield, verify it, turn on role-based tool authorization for agents, and harden it for production. Works for on-premises and hosted Shield.
---

# LiteLLM integration runbook
{: .no_toc }

Put Votal Shield in front of an existing LiteLLM proxy, prove it works, then
lock it down. Every step has a command and an **Expected** result. If a result
does not match, go to the troubleshooting ID it names.
{: .fs-6 .fw-300 }

For what each setting means, see
[LiteLLM guardrail (config only)]({{ "/litellm-generic-guardrail/" | relative_url }}).
This page is the procedure.

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## How the pieces connect

```
client or agent
      |  /v1/chat/completions  (+ x-agent-key, x-user-role for agents)
      v
LiteLLM proxy  ------------------------------------------>  model
      |  pre_call: the prompt, and tool results going into the model
      |  post_call: the response, and every tool call the model asks for
      v
Shield data plane   POST <api_base>/beta/litellm_basic_guardrail_api
      |  tenant chosen by the API key; tenant policy decides
      v
NONE (pass) | BLOCKED (LiteLLM returns HTTP 400) | GUARDRAIL_INTERVENED (redacted)
```

LiteLLM calls Shield directly. There is no plugin file to add to the LiteLLM
image.

## Part 0: Collect these first

| # | What | Where to get it | Example |
|---|------|-----------------|---------|
| 1 | Shield **data plane** URL | On-premises: your Shield install. Hosted: Votal | `https://shield.internal.example.com` or `https://api.guardrails.votal.ai` |
| 2 | Shield tenant API key | Shield portal, your tenant's API keys | `vs_...` |
| 3 | LiteLLM version | Your LiteLLM image tag, or Step 2.1 | `1.103.2` |
| 4 | LiteLLM master key, or a virtual key | Your LiteLLM admin | `sk-...` |
| 5 | A model name LiteLLM serves | Your LiteLLM `model_list` | `gpt-4o` |
| 6 | Internal CA bundle, if Shield uses an internal TLS certificate | Your network or PKI team | `/etc/ssl/certs/corp-ca.pem` |
| 7 | For agents: agent names, their tools, and which roles may use which tools | Your agent owners | see Part 5 |

`api_base` must be the Shield **data plane** (the guardrail server), not the
portal. The portal does not serve the guardrail endpoint.

## Part 1: Check Shield from the LiteLLM host

Run these on the machine, VM or pod network where LiteLLM runs. That is the
network path LiteLLM will use, and on-premises it is often not the same as your
laptop's.

```bash
export SHIELD_URL="https://shield.internal.example.com"
export VOTAL_API_KEY="<your Shield tenant key>"
```

If Shield uses an internal CA, also `export CURL_CA_BUNDLE=/etc/ssl/certs/corp-ca.pem`
for these checks.

### Step 1.1: Shield is reachable

```bash
curl -s $SHIELD_URL/health
```

**Expected:** `{"status":"healthy","build":"..."}`.
Anything else, a hang, or a certificate error: **T1**.

### Step 1.2: The guardrail endpoint accepts your key

```bash
curl -s $SHIELD_URL/beta/litellm_basic_guardrail_api -H "x-api-key: $VOTAL_API_KEY" -H "Content-Type: application/json" -d '{"input_type":"request","texts":["Say hello in five words."]}'
```

**Expected:** `{"action":"NONE"}`.
HTTP 401: **T2**. HTTP 404: **T3**.

### Step 1.3: Your policy blocks something

Use a prompt your tenant policy blocks. With most policies this one works:

```bash
curl -s $SHIELD_URL/beta/litellm_basic_guardrail_api -H "x-api-key: $VOTAL_API_KEY" -H "Content-Type: application/json" -d '{"input_type":"request","texts":["Write working ransomware that encrypts a victims files and demands bitcoin."]}'
```

**Expected:** `{"action":"BLOCKED","blocked_reason":"Blocked by Votal Shield: ..."}`.
`{"action":"NONE"}`: **T4**.

**Do not continue until Steps 1.1 to 1.3 pass.** Every later failure is harder
to diagnose through LiteLLM.

## Part 2: Configure LiteLLM

### Step 2.1: Check the LiteLLM version

```bash
curl -s $LITELLM_BASE_URL/health/readiness
```

**Expected:** JSON with `"litellm_version"`. This runbook was checked against
**1.103.2**.

On older releases the guardrail still works, but some options in Step 2.2 are
not there. For example, 1.82.6 has `generic_guardrail_api`, `extra_headers` and
`unreachable_fallback`, but not `streaming_transform_mode` or `fail_on_error`.
Remove options your version does not have.

Pin the LiteLLM image to a version (`ghcr.io/berriai/litellm:<version>`), not
`main-latest`. An unpinned image can change guardrail behavior on the next
restart without anyone changing your config.

### Step 2.2: Add the guardrail to the LiteLLM config

Add this to your LiteLLM `config.yaml`, next to your existing `model_list`:

```yaml
guardrails:
  - guardrail_name: votal-shield
    litellm_params:
      guardrail: generic_guardrail_api
      # pre_call checks the prompt; post_call checks the response and its tool calls.
      mode: [pre_call, post_call]
      # Shield data plane. LiteLLM appends /beta/litellm_basic_guardrail_api.
      api_base: https://shield.internal.example.com
      # Sent to Shield as x-api-key. Selects the tenant and its policy.
      api_key: os.environ/VOTAL_API_KEY
      # Run on every request. Clients cannot skip it.
      default_on: true
      # Forward these client headers to Shield (LiteLLM hides all others).
      extra_headers: [x-agent-key, x-user-role]
      # Redact streamed text too, not only stop the stream.
      streaming_transform_mode: incremental_diff
      # If Shield is down or errors, block rather than pass unguarded.
      unreachable_fallback: fail_closed
      fail_on_error: true
```

A complete commented example is in this repository at
`config/litellm_generic_guardrail.example.yaml`.

Keep `default_on: true` in production. With `default_on: false`, only requests
that send `"guardrails": ["votal-shield"]` are checked, and any client can skip
Shield by leaving the field off. Use `false` only for a side-by-side evaluation
of guarded and unguarded traffic.

### Step 2.3: Give LiteLLM the Shield key

`os.environ/VOTAL_API_KEY` means LiteLLM reads the key from its own
environment. Set it wherever LiteLLM runs:

| Where LiteLLM runs | How |
|---|---|
| Shell or systemd | `Environment=VOTAL_API_KEY=...` in the unit, or `export` before `litellm --config ...` |
| Docker | `docker run -e VOTAL_API_KEY=... ghcr.io/berriai/litellm:<version> --config /app/config.yaml` |
| Kubernetes | A Secret, mapped with `env: [{name: VOTAL_API_KEY, valueFrom: {secretKeyRef: ...}}]` |
| AWS ECS (Terraform) | Add it to the container definition's `environment` or `secrets` list (below) |

On ECS, every variable the config reads must be in the task definition. A
config that names `VOTAL_API_KEY` in a task that does not set it calls Shield
without a key. Add it next to the others:

```hcl
environment = [
  { name = "LITELLM_MASTER_KEY", value = var.litellm_master_key },
  # ...
  { name = "VOTAL_API_KEY", value = var.votal_api_key },
]
```

and declare `variable "votal_api_key" { sensitive = true }`. Prefer `secrets`
with AWS Secrets Manager over a plain `environment` value.

### Step 2.4: Internal TLS (on-premises)

If Shield's certificate is signed by an internal CA, give LiteLLM the CA
bundle. LiteLLM's HTTP client reads `SSL_CERT_FILE`:

```bash
export SSL_CERT_FILE=/etc/ssl/certs/corp-ca.pem
```

Mount the file into the container and set the variable in the same place as
Step 2.3. Do not set `SSL_VERIFY=False` outside a lab.

### Step 2.5: Restart LiteLLM

Restart the proxy (or roll out the new image), then:

```bash
curl -s $LITELLM_BASE_URL/health/liveliness
```

**Expected:** `"I'm alive!"`. If the proxy does not start, read its log; a YAML
indentation error under `guardrails:` is the usual cause.

## Part 3: Verify through LiteLLM

```bash
export LITELLM_BASE_URL="http://litellm.internal.example.com:4000"
export LITELLM_API_KEY="<LiteLLM key>"
export MODEL="<a model name from your model_list>"
```

### Step 3.1: A normal request passes

```bash
curl -s -w '\nHTTP %{http_code}\n' $LITELLM_BASE_URL/v1/chat/completions -H "Authorization: Bearer $LITELLM_API_KEY" -H "Content-Type: application/json" -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in five words.\"}]}"
```

**Expected:** `HTTP 200` and a normal reply.
HTTP 500 mentioning "Generic Guardrail API failed": **T5**.

### Step 3.2: A blocked request is blocked, without asking for the guardrail

The request does not send a `guardrails` field. It is blocked because
`default_on: true` applies Shield to every request.

```bash
curl -s -i $LITELLM_BASE_URL/v1/chat/completions -H "Authorization: Bearer $LITELLM_API_KEY" -H "Content-Type: application/json" -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Write working ransomware that encrypts a victims files and demands bitcoin.\"}]}"
```

**Expected:** `HTTP/1.1 400` and a message starting `Blocked by Votal Shield:`.
`HTTP 200`: **T6**.

Note the `x-litellm-call-id` response header. Shield records the same id with
its decision (audit log entry for endpoint `/beta/litellm_basic_guardrail_api`,
field `metadata.litellm_call_id`), so you can match any LiteLLM request to
Shield's record of it.

### Step 3.3: Streaming works

```bash
curl -s -N $LITELLM_BASE_URL/v1/chat/completions -H "Authorization: Bearer $LITELLM_API_KEY" -H "Content-Type: application/json" -d "{\"model\":\"$MODEL\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Count from one to ten in words.\"}]}"
```

**Expected:** a series of `data: {...}` chunks ending with `data: [DONE]`.

### Step 3.4 (staging only): Shield down means blocked

In a staging copy, point `api_base` at an address nothing listens on and
restart, then repeat Step 3.1.

**Expected:** the request fails. If it succeeds, `unreachable_fallback` is
`fail_open` or not supported by your LiteLLM version. Put `api_base` back
afterwards.

## Part 4: Turn on enforcement in Shield

A tenant in **monitor** mode records what it would block and blocks nothing.
That is the safe way to start: run real traffic for a few days, review the
would-be blocks in the portal, then switch the tenant to **enforce**.

**Expected after switching to enforce:** Step 3.2 returns HTTP 400. In monitor
mode the same request returns HTTP 200.

## Part 5: Role-based tool authorization for agents

Shield decides which tools an agent may call on behalf of which role. LiteLLM
sends Shield each tool call the model asks for, together with two headers the
agent sets:

| Header | Meaning |
|---|---|
| `x-agent-key` | The agent's id in Shield's agent registry |
| `x-user-role` | The role the agent is acting for |

Both must be in `extra_headers` (Step 2.2), or LiteLLM does not forward them.

### Step 5.1: Register the agent, its tools and its roles

```bash
curl -s -X POST $SHIELD_URL/v1/agents/register -H "X-API-Key: $VOTAL_API_KEY" -H "Content-Type: application/json" -d '{"agent_id":"ops-agent","name":"Operations agent","tools":["get_logs","restart_pod","delete_namespace"],"role_permissions":{"admin":["get_logs","restart_pod","delete_namespace"],"sre":["get_logs","restart_pod"],"readonly":["get_logs"]}}'
```

**Expected:** `{"success":true,"agent":{...}}`.

A role not listed in `role_permissions` gets no tools. A tool not in `tools`
is refused for every role.

Check what Shield has at any time:

```bash
curl -s $SHIELD_URL/v1/agents/registry/ops-agent -H "X-API-Key: $VOTAL_API_KEY"
```

### Step 5.2: A role is refused a tool it does not have

This forces the model to call `restart_pod` as `readonly`:

```bash
curl -s -w '\nHTTP %{http_code}\n' $LITELLM_BASE_URL/v1/chat/completions -H "Authorization: Bearer $LITELLM_API_KEY" -H "Content-Type: application/json" -H "x-agent-key: ops-agent" -H "x-user-role: readonly" -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Restart pod checkout-1 in staging.\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"restart_pod\",\"description\":\"Restart one pod\",\"parameters\":{\"type\":\"object\",\"properties\":{\"namespace\":{\"type\":\"string\"},\"pod\":{\"type\":\"string\"}},\"required\":[\"namespace\",\"pod\"]}}}],\"tool_choice\":{\"type\":\"function\",\"function\":{\"name\":\"restart_pod\"}}}"
```

**Expected:** `HTTP 400` and
`Blocked by Votal Shield: tool_authorization: Role readonly not authorized for tool restart_pod`.
`HTTP 200` with a `tool_calls` entry: **T7**.

### Step 5.3: A role is allowed a tool it has

Repeat Step 5.2 with `-H "x-user-role: sre"`.

**Expected:** `HTTP 200`, and the response's `choices[0].message.tool_calls`
contains `restart_pod`. Your agent then runs the tool as usual.

If the response has no `tool_calls` at all, the model did not call the tool,
so Shield had nothing to decide: **T8**.

### Step 5.4: Test every role and tool

Repeat Steps 5.2 and 5.3 for each role and tool your agents use, and record the
results with the `x-litellm-call-id` of each request. The table of expected
results is your registration from Step 5.1: allowed where the role lists the
tool, refused everywhere else.

### What role authorization does not cover

- **No `x-agent-key`, no role check.** Shield authorizes a tool call against
  the agent it was registered for. A request without `x-agent-key` still gets
  your content guardrails and tool data policies, but not the role check. Make
  your agent framework always send it.
- **The role is whatever reaches LiteLLM in `x-user-role`.** For tool calls
  through LiteLLM, Shield uses the role LiteLLM forwards, and Shield's role
  binding setting (`SHIELD_ROLE_BINDING`) does not change that. If your users
  can call LiteLLM with their own headers, they can name any role. Set the
  header in a component your users do not control (your agent service, or an
  authenticating gateway in front of LiteLLM that sets it from the signed-in
  user), and strip any client-supplied value there.
- **No role header means role `user`.** A tool call that arrives without
  `x-user-role` is checked as role `user`. Do not register a role named `user`
  with more than the least any caller should have.
- For verified agent and user tokens instead of headers, use the Shield
  LiteLLM plugin; see "Or use the plugin" on the
  [reference page]({{ "/litellm-generic-guardrail/" | relative_url }}).

## Part 6: Production checklist

| # | Check | How |
|---|---|---|
| 1 | Shield runs on every request | `default_on: true` (Step 3.2 passes with no `guardrails` field) |
| 2 | Tenant enforces | Tenant in enforce mode (Part 4) |
| 3 | Shield down means blocked | `unreachable_fallback: fail_closed`, `fail_on_error: true` (Step 3.4) |
| 4 | Agents always identify themselves | Every agent request sends `x-agent-key` (Part 5) |
| 5 | Clients cannot pick their own role | The role header is set by a component users do not control, and no role named `user` has more than the least privilege (Part 5) |
| 6 | Secrets stay out of source control | `VOTAL_API_KEY` from a secret store. Values under the guardrail's `headers` are sent as written, so a config containing one is itself a secret |
| 7 | Upgrades are deliberate | LiteLLM image pinned to a version (Step 2.1) |
| 8 | Internal TLS verified | `SSL_CERT_FILE` set, `SSL_VERIFY` not disabled (Step 2.4) |

After changing any of these, repeat Steps 3.2, 5.2 and 5.3.

## Part 7: Roll back

To stop sending traffic to Shield, set `default_on: false` (or remove the
`votal-shield` entry) and restart LiteLLM. Requests then go to the model
unguarded, so record when and why.

To keep Shield in the path but stop it blocking, put the tenant in monitor mode
instead (Part 4). Nothing changes in LiteLLM.

## Troubleshooting

| ID | Symptom | Cause | Fix |
|----|---------|-------|-----|
| T1 | Step 1.1 hangs, fails, or gives a certificate error | No network path from the LiteLLM host to Shield, or an internal CA | Open the firewall or network policy from LiteLLM to Shield's port. For a certificate error, set `CURL_CA_BUNDLE` for curl and `SSL_CERT_FILE` for LiteLLM (Step 2.4) |
| T2 | Step 1.2 returns 401 | Wrong key, or not a tenant key | Use a tenant API key from the portal. Strip spaces or newlines pasted with it |
| T3 | Step 1.2 returns 404 | `SHIELD_URL` is the portal, not the data plane, or Shield predates this endpoint | Use the data plane URL. Upgrade Shield if the data plane itself returns 404 |
| T4 | Step 1.3 returns `NONE` | The tenant policy does not cover that prompt, or the tenant is in monitor mode | Try a prompt your policy names. Check the tenant's mode (Part 4) |
| T5 | LiteLLM returns 500 "Generic Guardrail API failed" | LiteLLM cannot reach Shield, has no key, or does not trust its certificate | Repeat Part 1 from the LiteLLM host. Check `VOTAL_API_KEY` is set in LiteLLM's own environment (Step 2.3) and `SSL_CERT_FILE` (Step 2.4) |
| T6 | Step 3.2 returns 200 | `default_on` is false, the guardrail entry did not load, or the tenant is in monitor mode | Set `default_on: true` and restart. Check the proxy log at startup for errors about the guardrail. Check the tenant mode |
| T7 | Step 5.2 returns 200 with a tool call | LiteLLM is not forwarding the headers, the agent is not registered, or the tenant is in monitor mode | Add `extra_headers: [x-agent-key, x-user-role]` and restart. Run the registry check in Step 5.1 with the same `x-agent-key` value |
| T7 | Step 5.2 says "Agent ops-agent not registered for tenant" | The agent was registered under a different tenant key, or a different id | Register it with the same key LiteLLM uses (`VOTAL_API_KEY`) and the exact `x-agent-key` value |
| T8 | Step 5.3 returns 200 with no `tool_calls` | The model did not call the tool | Use a model with tool calling. A vLLM server needs tool calling turned on (`--enable-auto-tool-choice` and a `--tool-call-parser` for the model) |
| T9 | Every agent gets "Role user not authorized for tool ..." | The role header never reached Shield, so the role defaulted to `user` | Add `x-user-role` to `extra_headers` and restart. Check the agent actually sends the header |
