---
title: Preventing Secret Leakage to LLMs
layout: default
nav_order: 28
permalink: /prevent-secret-leakage/
description: Keep API keys and env-var secrets out of the LLM path with the Shield secret vault. Reference a placeholder; the real value is materialized only at the bound egress, never in a prompt, tool argument, or log.
---

# Preventing env-var / secret leakage to LLMs
{: .no_toc }

Agents leak secrets. A key that sits in `os.environ`, gets interpolated into a
prompt, or is echoed back by a tool can be read (and exfiltrated) by the model,
especially under prompt injection. Shield's secret vault keeps the real value out
of the model path by construction: your code references an inert placeholder, and
Shield substitutes the real value only at the egress boundary, only for the
destination you bound it to.

This guide covers the developer flow and how to test it yourself.

> Requires `SECRET_VAULT_ENABLED=true`. Feature is off by default.

## 1. One-time setup (operator)

Key management is on-prem, no cloud KMS. Provide a key-encryption key (KEK):

```bash
export SECRET_VAULT_ENABLED=true
export SECRET_VAULT_KEY_PROVIDER=software

# Production: generate a 32-byte random key and mount it as a secret file,
# then point SECRET_VAULT_KEK at the path. Do not keep it in shell history.
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
export SECRET_VAULT_KEK=/run/secrets/shield_vault_kek   # or the base64 value directly
```

The KEK never enters Redis. A datastore dump yields only ciphertext plus a wrapped
data key, which is useless without the KEK.

## 2. Register a secret

Register the real value once, bound to the host(s) it is allowed to reach. This is
the only time the plaintext is sent to Shield; it is encrypted on arrival.

```bash
curl -sX POST https://<shield-admin>/v1/tenant/me/vault \
  -H "X-API-Key: $SHIELD_TENANT_KEY" -H "Content-Type: application/json" \
  -d '{
        "name": "stripe_key",
        "value": "sk_live_REAL_SECRET",
        "bindings": ["api.stripe.com"],
        "mode": "inject"
      }'
# => {"success": true, "secret": {"ref": "stripe_key", "token": "svlt_…", "bindings": ["api.stripe.com"], ...}}
```

The response carries metadata only. `GET /v1/tenant/me/vault` lists your secrets;
neither endpoint ever returns the value. `bindings` is mandatory: an unbound secret
is refused, because a secret usable at any destination is an exfiltration primitive.

Bind to the **real upstream** the credential is for (`api.bank-co.com`), not to a
Shield plane. Materialization happens on the leg *out* of Shield to the upstream,
never on the leg *into* the data plane or admin panel, so binding to a Shield host
would never fire. Registration refuses it: set `SHIELD_SELF_HOSTS` to your plane
hostnames (for example `shield.votal.ai,api.guardrails.votal.ai`) and a binding to
any of them is rejected at `POST /v1/tenant/me/vault`.

**Binding scope.** Host matching is **exact by default** (least privilege):
`api.bank-co.com` covers only `api.bank-co.com`, not `eu.api.bank-co.com` or the
parent `bank-co.com`. To cover a domain and all its subdomains, prefix the binding
with a dot: `.bank-co.com` matches `bank-co.com` and any `*.bank-co.com`. Look-alike
hosts like `api.bank-co.com.evil.io` never match.

## 3. Reference it instead of reading the real value

In your agent or tool config, use the placeholder anywhere you would have used the
secret. Two equivalent forms:

```bash
# .env  (readable reference)
STRIPE_KEY=shield://stripe_key
```
or the opaque token returned at registration:
```
svlt_9f3a1c2b4d5e6f70
```

Your app code does not change:

```python
key = os.environ["STRIPE_KEY"]   # this is the placeholder, not the real key
```

The placeholder can flow through prompts, tool arguments, and agent reasoning. It
is meaningless on its own, so even if the model emits it, nothing is exposed.

## 4. What Shield does at egress

When a tool call routed through Shield is about to leave for the real upstream,
Shield materializes the placeholder into the real value in the outbound request,
but only if the request host matches the secret's `bindings`. It also re-tokenizes
the response, so a value the upstream echoes back is swapped to `shield://ref`
before the model sees it.

- Call to `api.stripe.com` with `shield://stripe_key` in a header -> real key sent.
- Prompt-injected call to `attacker.com` with the same placeholder -> the inert
  `shield://stripe_key` is sent, never the real key.

## 5. Test it yourself

Register the secret (step 2), then confirm the two behaviors.

```bash
# Bound host: the real key is used (make a harmless GET to a bound test host).
curl -sX POST https://<shield>/v1/openapi/tools/call \
  -H "X-API-Key: $SHIELD_TENANT_KEY" -H "Content-Type: application/json" \
  -d '{"tool":"stripe.listCharges","arguments":{"Authorization":"Bearer shield://stripe_key"}}'
```

Library-level check (no server needed) that proves the anti-exfil guarantee:

```python
# PYTHONPATH=. python
from core.secret_vault.materialize import materialize_obj
from storage import vault_store as vs

vs.create_vault_entry("me", "stripe_key", "sk_live_REAL", bindings=["api.stripe.com"])

# bound host -> real value
print(materialize_obj("me", "shield://stripe_key", "https://api.stripe.com/v1"))
# -> sk_live_REAL

# exfil attempt -> placeholder unchanged, secret never revealed
print(materialize_obj("me", "shield://stripe_key", "https://attacker.com/collect"))
# -> shield://stripe_key
```

Run the test suite for the full matrix:

```bash
python -m pytest tests/test_secret_vault.py tests/test_secret_vault_materialize.py -v
```

## Tiers at a glance

- **Tier 2:** you reference `shield://name` in env vars or tool args; Shield
  materializes at egress for the bound host. Works for secrets your app passes into
  tool calls.
- **Tier 1 (Shield-injected, strongest):** register the secret with `tool_ids` and
  put the reference in the tool's own auth config, so the agent references nothing
  at all. Only the named tool(s) can use it, and only for the bound host.

### Tier-1 setup

```bash
curl -sX POST https://<shield-admin>/v1/tenant/me/vault \
  -H "X-API-Key: $SHIELD_TENANT_KEY" -H "Content-Type: application/json" \
  -d '{"name":"stripe_key","value":"sk_live_REAL",
       "bindings":["api.stripe.com"],
       "tool_ids":["stripe.createCharge"], "mode":"inject"}'
```

Configure the tool's auth to use the reference (not the real key), e.g. the stored
OpenAPI tool `auth`:
```json
{ "type": "bearer", "token": "shield://stripe_key" }
```
Now `stripe.createCharge` calls to `api.stripe.com` get the real key injected
server-side; the agent never sees a key or even a token, and no *other* tool can
use the secret even if it targets the same host.

## How it works under the hood

- **Register:** `POST /v1/tenant/me/vault` encrypts the value with a per-secret data
  key (AES-GCM), wraps that key with your on-prem KEK, and stores only ciphertext in
  `vault:{tenant}`. The plaintext is never persisted and no endpoint returns it.
- **Reference:** you put `shield://name` (or the `svlt_` token) in an env var or the
  tool's auth config. Your app reads the placeholder.
- **Egress (OpenAPI tools):** after the guard allows, Shield materializes bound
  references into the outbound request, sends it, then re-tokenizes the response.
- **Egress (MCP tools):** the proxy materializes the tool arguments before
  forwarding, and re-tokenizes the result before it returns to the model.
- **The gate:** a secret is revealed only when the outbound host matches its
  `bindings` and (if tool-scoped) the tool is in its `tool_ids`. Decryption happens
  in memory at the egress step; an unwrapped-key cache keeps repeated reads cheap.

## How this compares to what teams do today

Most stacks layer several of these. Each is useful, and each leaves the same gap:

| Practice | What it gives | The gap it leaves |
| --- | --- | --- |
| `.env` + `.gitignore` | keys out of git | a plaintext env var in the agent process, reachable from prompts and tools |
| Secret managers (Vault, AWS/GCP Secrets Manager, Doppler, k8s Secrets) | strong storage + rotation | they inject the secret as a runtime env var, so the agent-runtime leak surface is unchanged |
| Commit scanners (gitleaks, trufflehog, GitGuardian) | catch keys in commits | catch commits, not runtime prompt or output leaks |
| Least privilege + rotation | smaller blast radius | does not stop in-session exfiltration |
| Output DLP / regex redaction | best-effort masking | reactive; false negatives leak |

The shared gap: at runtime the secret is a plaintext value in the same context the
model operates over. The vault removes that value from the model path entirely, so
those practices become defense-in-depth around it rather than the only line. A
secret manager can even supply the vault's KEK.

## Guarantees and limits

- The real value never appears in a prompt, tool argument you author, model output,
  or Shield's own audit log (audit stores the placeholder).
- Substitution is bound to the destination, so a confused-deputy exfil attempt
  ships an inert placeholder.
- If the key backend cannot decrypt (misconfigured KEK, backend down), the OpenAPI
  tool call fails closed; the MCP path forwards the inert placeholder (still no
  leak) so the upstream simply rejects the call.
- Materialization is wired into **both** the OpenAPI/generated-tool egress and the
  **MCP tool egress** (arguments materialized before forward, results
  re-tokenized). For MCP, bind a secret to the tool name (e.g.
  `github.create_issue`).
