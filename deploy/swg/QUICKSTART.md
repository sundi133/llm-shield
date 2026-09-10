# Run it on your own machine

The whole gateway on your laptop in about ten minutes, most of which is Docker
building the image. You get a proxy that intercepts your traffic to AI
providers, screens each prompt against real policy, and blocks the ones that
violate it.

You need **Docker Desktop running** and **git**. Nothing else.

---

## 1. Get the code

Use this branch, not `main`. It carries fixes without which the proxy image
does not build correctly on Windows and does not run correctly anywhere with no
bind mounts.

```bash
git clone https://github.com/sundi133/llm-shield.git
cd llm-shield
git checkout feat/swg-railway-testbed
```

## 2. Make an interception certificate

The proxy has to present its own certificate for the sites it inspects, so it
needs a certificate authority. This one is yours, it stays on your machine, and
it is throwaway.

```bash
mkdir -p deploy/swg/ssl
openssl req -new -newkey rsa:2048 -sha256 -days 30 -nodes -x509 \
  -extensions v3_ca -keyout deploy/swg/ssl/ca.pem -out deploy/swg/ssl/ca.pem \
  -subj "/CN=Shield local test CA"
```

On Windows, run that in **Git Bash** with `MSYS_NO_PATHCONV=1` in front of
`openssl`, or Git Bash rewrites the `/CN=...` into a file path and the command
fails with a confusing error about name format.

The file must end up holding **both** the certificate and its private key. That
command produces both. Do not run `openssl x509` on it afterwards, which would
silently drop the key.

## 3. Point it at a tenant

```bash
echo "bank-co-key" > deploy/swg/shield_api_key.txt
```

That is the demo tenant. The gateway fetches its real policy from
`api.guardrails.votal.ai` at startup.

## 4. Start it

```bash
SHIELD_ICAP_MODE=enforce SHIELD_ICAP_REDACT_FALLBACK=block \
  docker compose -f docker-compose.swg.yml up -d --build
```

Both variables matter:

- `SHIELD_ICAP_MODE=enforce` — the default is `monitor`, which reports what it
  would have blocked and blocks nothing. That is the right default for a real
  rollout and the wrong one for seeing it work.
- `SHIELD_ICAP_REDACT_FALLBACK=block` — this tenant's rules are all redaction
  rules, which v1 cannot perform, so without this it loads four rules and
  enforces none of them.

First build takes a few minutes. Later starts are seconds.

## 5. Check it actually armed

```bash
curl -s http://127.0.0.1:8081/healthz
```

```json
{"mode":"enforce","tenant_id":"bankco","rules":4,"blocking_rules":3,
 "shield_reachable":true,"enforcing_anything":true}
```

**Read `enforcing_anything`, not `rules`.** A policy can load rules and enforce
none of them, and that is the failure most likely to fool you: everything looks
healthy and nothing is being blocked.

## 6. Send a prompt through it

Two requests, identical except for the content.

```bash
# extract the certificate on its own, for curl to trust
openssl x509 -in deploy/swg/ssl/ca.pem -out /tmp/ca-cert.pem

# harmless: expect 401, which is Anthropic answering, so it got through
curl -s -o /dev/null -w '%{http_code}\n' --ssl-no-revoke \
  --proxy http://127.0.0.1:3128 --cacert /tmp/ca-cert.pem \
  -H 'content-type: application/json' \
  -d '{"model":"claude-opus-4","messages":[{"role":"user","content":"what is the weather in Paris"}]}' \
  https://api.anthropic.com/v1/messages

# with a customer email: expect 403
curl -s --ssl-no-revoke \
  --proxy http://127.0.0.1:3128 --cacert /tmp/ca-cert.pem \
  -H 'content-type: application/json' \
  -d '{"model":"claude-opus-4","messages":[{"role":"user","content":"email john.doe@bankco.com about his account"}]}' \
  https://api.anthropic.com/v1/messages
```

```
401
{"error":"Blocked by your organization's AI policy. Prompt contained data
matching policy: email-mask.","rule_id":"email-mask","reference":"d890a0c4-..."}
```

`--ssl-no-revoke` is needed on Windows only, where curl uses schannel and
refuses a certificate it cannot check a revocation list for. On macOS and Linux
drop it.

## 7. The part worth seeing

A site that is not an AI provider is never decrypted at all, so your own
certificate is neither needed nor accepted there:

```bash
openssl s_client -proxy 127.0.0.1:3128 -connect api.anthropic.com:443 \
  -servername api.anthropic.com </dev/null 2>/dev/null | grep ^issuer=
openssl s_client -proxy 127.0.0.1:3128 -connect www.wikipedia.org:443 \
  -servername www.wikipedia.org </dev/null 2>/dev/null | grep ^issuer=
```

```
issuer=CN=Shield local test CA          <- yours. This one is inspected.
issuer=C=US, O=Let's Encrypt, CN=...    <- the real one. Never decrypted.
```

Banking, payroll and identity providers are on that same never-inspect list.

## 8. What it recorded

```bash
docker compose -f docker-compose.swg.yml logs shield-icap | grep "icap txn" | tail -2
docker compose -f docker-compose.swg.yml logs | grep -c "john.doe@bankco.com"
```

The second command returns `0`. The destination, the rule that fired and a
reference are recorded. The prompt never is.

## 9. Stop and clean up

```bash
docker compose -f docker-compose.swg.yml down -v
rm -f deploy/swg/ssl/ca.pem deploy/swg/shield_api_key.txt
```

Deleting the CA matters. While it exists, anything that trusts it can have its
traffic to those sites read.

---

## If something goes wrong

| Symptom | Cause |
|---|---|
| `rules: 0` in step 5 | Key not read. Check `deploy/swg/shield_api_key.txt` exists and has no stray characters |
| `enforcing_anything: false` | You skipped `SHIELD_ICAP_REDACT_FALLBACK=block` in step 4 |
| Both requests return 403 in step 6 | Not a verdict. Squid cannot reach the screening service, so it is failing closed. `docker compose -f docker-compose.swg.yml restart squid` |
| `curl` certificate errors | You passed `ca.pem` rather than the extracted `/tmp/ca-cert.pem`, or you are on Windows without `--ssl-no-revoke` |
| Squid container restart loop, `no such file or directory` | You are on `main` rather than the branch. `main` lacks the line-ending fix and the shebang breaks on a Windows checkout |
| Nothing blocks, everything returns 401 | You are in `monitor` mode. Check step 4 |

## What this is not

A test environment on one machine. Nothing is protecting anyone's traffic: it
only inspects what you deliberately send through `127.0.0.1:3128`.

Also, this tenant's policy blocks **email addresses**. Credit card numbers and
API keys are not in its ruleset and will pass straight through. That is a
property of this demo tenant's policy, not of the gateway.
