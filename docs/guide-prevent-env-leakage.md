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

## The risk, and how the vault removes it

The danger is not any single call. It is that the secret lives inside the process
the model can act over, so every tool and every trace is a way out. The vault
moves the secret out of the process: the env holds only a reference, and the real
key is materialized only on the bound egress.

<style>
.vd { max-width:100%; overflow-x:auto; margin:1rem 0 .3rem; }
.vd svg { min-width:600px; height:auto; display:block; }
.vd .h { font-size:15px; font-weight:600; fill:#1f2430; }
.vd .t { font-size:13px; fill:#1f2430; }
.vd .s { font-size:11.5px; fill:#5b616e; }
.vd-cap { font-size:13px; color:#5b616e; margin:0 0 1.6rem; }
</style>

<div class="vd">
<svg width="100%" viewBox="0 0 680 350" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Without Shield the Stripe key is in the process and can leak">
<defs>
<marker id="d1ad" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#d1493f"/></marker>
<marker id="d1aa" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#4f46e5"/></marker>
</defs>
<text class="h" x="20" y="26">Without Shield: the key is in the process</text>
<text class="s" x="20" y="45">the secret lives in the agent process, so every tool and trace is a way out</text>
<rect x="20" y="96" width="150" height="56" rx="8" fill="#ffffff" stroke="#b6bcc8"/>
<text class="t" x="95" y="120" text-anchor="middle">untrusted input</text>
<text class="s" x="95" y="138" text-anchor="middle">ticket, web, email</text>
<line x1="170" y1="124" x2="212" y2="124" stroke="#d1493f" marker-end="url(#d1ad)"/>
<text class="s" x="191" y="116" text-anchor="middle" fill="#d1493f">injection</text>
<rect x="214" y="72" width="252" height="216" rx="10" fill="#f4f5f8" stroke="#b6bcc8"/>
<text class="s" x="226" y="90" fill="#6b7280">agent process</text>
<rect x="228" y="98" width="224" height="42" rx="7" fill="#ffffff" stroke="#d1493f" stroke-width="1.5"/>
<text class="t" x="340" y="116" text-anchor="middle">os.environ</text>
<text class="s" x="340" y="132" text-anchor="middle" fill="#d1493f">STRIPE_KEY = sk_live_…</text>
<rect x="228" y="150" width="224" height="30" rx="7" fill="#ffffff" stroke="#b6bcc8"/>
<text class="s" x="340" y="169" text-anchor="middle">the LLM picks which tool to call</text>
<rect x="228" y="190" width="108" height="42" rx="7" fill="#ffffff" stroke="#b6bcc8"/>
<text class="t" x="282" y="208" text-anchor="middle">create_charge</text>
<text class="s" x="282" y="223" text-anchor="middle">payment</text>
<rect x="344" y="190" width="108" height="42" rx="7" fill="#ffffff" stroke="#b6bcc8"/>
<text class="t" x="398" y="208" text-anchor="middle">http / shell</text>
<text class="s" x="398" y="223" text-anchor="middle">general</text>
<text class="s" x="340" y="256" text-anchor="middle" fill="#6b7280">every tool can read the whole process</text>
<rect x="506" y="90" width="154" height="44" rx="8" fill="#ffffff" stroke="#d1493f" stroke-width="1.5"/>
<text class="t" x="583" y="110" text-anchor="middle">attacker.io</text>
<text class="s" x="583" y="126" text-anchor="middle" fill="#d1493f">gets sk_live_…</text>
<rect x="506" y="150" width="154" height="44" rx="8" fill="#ffffff" stroke="#d1493f" stroke-width="1.5"/>
<text class="t" x="583" y="170" text-anchor="middle">trace store</text>
<text class="s" x="583" y="186" text-anchor="middle" fill="#d1493f">LangSmith, logs</text>
<rect x="506" y="212" width="154" height="44" rx="8" fill="#ffffff" stroke="#4f46e5"/>
<text class="t" x="583" y="232" text-anchor="middle">api.stripe.com</text>
<text class="s" x="583" y="248" text-anchor="middle" fill="#4f46e5">legit charge</text>
<line x1="466" y1="150" x2="504" y2="115" stroke="#d1493f" marker-end="url(#d1ad)"/>
<text class="s" x="486" y="146" text-anchor="middle" fill="#d1493f">1</text>
<line x1="466" y1="172" x2="504" y2="172" stroke="#d1493f" marker-end="url(#d1ad)"/>
<text class="s" x="486" y="166" text-anchor="middle" fill="#d1493f">2</text>
<line x1="466" y1="210" x2="504" y2="232" stroke="#4f46e5" marker-end="url(#d1aa)"/>
<text class="s" x="20" y="312">1  prompt injection steers the general tool to exfiltrate the key.</text>
<text class="s" x="20" y="332">2  tracing captures the tool headers, so the key lands in a third-party store (no attacker needed).</text>
</svg>
</div>
<p class="vd-cap">The setup everyone builds: the key sits in <code>os.environ</code>, so a general tool (via injection) or your tracing can read it. The two red arrows are leaks.</p>

<div class="vd">
<svg width="100%" viewBox="0 0 680 384" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="With Shield the env holds only a placeholder and the leaks go inert">
<defs>
<marker id="d2ad" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#d1493f"/></marker>
<marker id="d2ag" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#1f9d63"/></marker>
<marker id="d2aa" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#4f46e5"/></marker>
</defs>
<text class="h" x="20" y="26">With Shield: the key is out of the process</text>
<text class="s" x="20" y="45">the env holds only a reference; the real key appears only on the bound egress</text>
<rect x="20" y="96" width="150" height="56" rx="8" fill="#ffffff" stroke="#b6bcc8"/>
<text class="t" x="95" y="120" text-anchor="middle">untrusted input</text>
<text class="s" x="95" y="138" text-anchor="middle">ticket, web, email</text>
<line x1="170" y1="124" x2="212" y2="124" stroke="#d1493f" marker-end="url(#d2ad)"/>
<text class="s" x="191" y="116" text-anchor="middle" fill="#d1493f">injection</text>
<rect x="214" y="72" width="252" height="180" rx="10" fill="#f4f5f8" stroke="#b6bcc8"/>
<text class="s" x="226" y="90" fill="#6b7280">agent process</text>
<rect x="228" y="98" width="224" height="42" rx="7" fill="#ffffff" stroke="#1f9d63" stroke-width="1.5"/>
<text class="t" x="340" y="116" text-anchor="middle">os.environ</text>
<text class="s" x="340" y="132" text-anchor="middle" fill="#1f9d63">STRIPE_KEY = shield://stripe_key</text>
<rect x="228" y="150" width="224" height="28" rx="7" fill="#ffffff" stroke="#b6bcc8"/>
<text class="s" x="340" y="168" text-anchor="middle">the LLM picks which tool to call</text>
<rect x="228" y="186" width="108" height="40" rx="7" fill="#ffffff" stroke="#b6bcc8"/>
<text class="t" x="282" y="204" text-anchor="middle">create_charge</text>
<text class="s" x="282" y="218" text-anchor="middle">payment</text>
<rect x="344" y="186" width="108" height="40" rx="7" fill="#ffffff" stroke="#b6bcc8"/>
<text class="t" x="398" y="204" text-anchor="middle">http / shell</text>
<text class="s" x="398" y="218" text-anchor="middle">general</text>
<text class="s" x="340" y="244" text-anchor="middle" fill="#6b7280">tools now read only a placeholder</text>
<rect x="506" y="90" width="154" height="44" rx="8" fill="#ffffff" stroke="#1f9d63" stroke-width="1.5"/>
<text class="t" x="583" y="110" text-anchor="middle">attacker.io</text>
<text class="s" x="583" y="126" text-anchor="middle" fill="#1f9d63">gets shield://… inert</text>
<rect x="506" y="150" width="154" height="44" rx="8" fill="#ffffff" stroke="#1f9d63" stroke-width="1.5"/>
<text class="t" x="583" y="170" text-anchor="middle">trace store</text>
<text class="s" x="583" y="186" text-anchor="middle" fill="#1f9d63">logs shield://… inert</text>
<line x1="466" y1="150" x2="504" y2="114" stroke="#1f9d63" marker-end="url(#d2ag)"/>
<text class="s" x="487" y="146" text-anchor="middle" fill="#1f9d63">&#10003;</text>
<line x1="466" y1="172" x2="504" y2="172" stroke="#1f9d63" marker-end="url(#d2ag)"/>
<text class="s" x="487" y="166" text-anchor="middle" fill="#1f9d63">&#10003;</text>
<line x1="294" y1="252" x2="294" y2="298" stroke="#4f46e5" marker-end="url(#d2aa)"/>
<text class="s" x="302" y="278" fill="#6b7280">via Shield</text>
<rect x="214" y="300" width="164" height="48" rx="8" fill="#ffffff" stroke="#4f46e5"/>
<text class="t" x="296" y="320" text-anchor="middle">Shield egress</text>
<text class="s" x="296" y="336" text-anchor="middle">materialize at bound host</text>
<line x1="378" y1="324" x2="428" y2="324" stroke="#4f46e5" marker-end="url(#d2aa)"/>
<text class="s" x="403" y="316" text-anchor="middle" fill="#4f46e5">real key</text>
<rect x="430" y="300" width="164" height="48" rx="8" fill="#ffffff" stroke="#4f46e5"/>
<text class="t" x="512" y="320" text-anchor="middle">api.stripe.com</text>
<text class="s" x="512" y="336" text-anchor="middle" fill="#4f46e5">real sk_live_… (only here)</text>
<text class="s" x="20" y="372">injection still fires and tracing still logs, but both capture only the inert placeholder.</text>
</svg>
</div>
<p class="vd-cap">Same attack surface, same injection, same tracing. The crown-jewel chip is out of the process, so every red arrow turns green and the real key exists only on the one egress to Stripe.</p>

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
