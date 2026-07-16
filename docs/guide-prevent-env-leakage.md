# Preventing env-var / secret leakage to LLMs

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

- **Tier 2 (this guide):** you reference `shield://name` in env vars or tool args;
  Shield materializes at egress. Works for secrets your app passes into tool calls.
- **Tier 1 (Shield-injected):** bind a secret to a `tool_id` and Shield attaches it
  server-side; the agent references nothing at all. Strongest option where Shield
  proxies the upstream.

## Guarantees and limits

- The real value never appears in a prompt, tool argument you author, model output,
  or Shield's own audit log (audit stores the placeholder).
- Substitution is bound to the destination, so a confused-deputy exfil attempt
  ships an inert placeholder.
- If the key backend cannot decrypt (misconfigured KEK, backend down), the tool
  call fails closed rather than sending a blank credential.
- Materialization is wired into the OpenAPI/generated-tool egress today. MCP tool
  egress uses the same `materialize_request` helper and is wired next.
