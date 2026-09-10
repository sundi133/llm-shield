# Try the gateway yourself

Ten minutes, no install beyond the Railway CLI, nothing to configure. You get a
shell inside the deployment and send prompts through the proxy with `curl`.

You need access to the `votal-swg-testbed` project in Railway.

---

## Setup, once

```bash
git clone https://github.com/sundi133/llm-shield.git
cd llm-shield && git checkout feat/swg-railway-testbed
./deploy/swg/railway/setup-access.sh
```

That installs nothing on the deployment. It registers your SSH key with
Railway, trusts Railway's host key, and links the project. Re-running it is
safe.

If the Railway CLI is missing it will tell you, and stop:

```
npm i -g @railway/cli            # or: brew install railway
winget install Railway.RailwayCLI    # Windows
```

## Get a shell inside the deployment

```bash
railway ssh -s demo-client
```

`demo-client` is a small Alpine container in the project with `curl` in it. It
holds no secrets and is not part of the gateway. Everything below runs in that
shell.

Nothing in this project has a public address, which is why you need a shell
inside it rather than a URL. That is the design.

---

## 1. Is there real policy, and is it armed

```bash
curl -s http://shield-icap.railway.internal:8081/healthz
```

```json
{"mode":"enforce","tenant_id":"bankco","bundle_version":"931b5e95...",
 "rules":4,"blocking_rules":3,"shield_reachable":true,
 "enforcing_anything":true}
```

That policy came from `api.guardrails.votal.ai` at startup. It is not a mock.

**Read `enforcing_anything`, not `rules`.** A tenant can load four rules and
enforce none of them, if every rule is a redaction the gateway cannot perform.
That is the failure most likely to fool you: the numbers look healthy and
nothing is being blocked.

## 2. A harmless prompt

```bash
curl -sk -x http://squid.railway.internal:3128 \
  -H 'content-type: application/json' \
  -d '{"model":"claude-opus-4","messages":[{"role":"user","content":"what is the weather in Paris"}]}' \
  https://api.anthropic.com/v1/messages
```

```json
{"type":"error","error":{"type":"authentication_error",
 "message":"x-api-key header is required"}}
```

That error is **Anthropic answering.** There is no API key on this testbed, so
reaching them at all is the proof the prompt went through untouched.

`-k` is there because this throwaway container does not have the proxy's
certificate installed. Step 4 is where that becomes the point rather than a
detail.

## 3. The same request with customer data in it

One word different. Nothing about the route changes.

```bash
curl -sk -x http://squid.railway.internal:3128 \
  -H 'content-type: application/json' \
  -d '{"model":"claude-opus-4","messages":[{"role":"user","content":"email john.doe@bankco.com about his account"}]}' \
  https://api.anthropic.com/v1/messages
```

```json
{"error":"Blocked by your organization's AI policy. Prompt contained data
 matching policy: email-mask.","rule_id":"email-mask","severity":"medium",
 "reference":"d890a0c4-..."}
```

Blocked before it left the network. The user gets a readable reason instead of
a broken page, and a reference support can trace.

**Only email addresses block for this tenant.** Credit card numbers and API keys
are not in bankco's ruleset and will go straight through. That is this demo
tenant's policy, not a limit of the gateway.

## 4. What gets decrypted, and what never does

```bash
for h in api.anthropic.com www.wikipedia.org; do
  echo "== $h"
  echo | openssl s_client -proxy squid.railway.internal:3128 \
    -connect $h:443 -servername $h 2>/dev/null | grep ^issuer=
done
```

```
== api.anthropic.com
issuer=CN=Votal SWG Railway testbed        <- ours. Decrypted and screened.
== www.wikipedia.org
issuer=C=US, O=Let's Encrypt, CN=YE2       <- real. Never decrypted.
```

The proxy looks at the destination before decrypting anything and chooses. AI
providers are inspected. Banking, payroll and identity providers are on a
never-inspect list applied before any decryption happens, so that traffic is a
tunnel we could not read if we wanted to.

## 5. What was recorded

Leave the shell (`exit`) and run:

```bash
railway logs -s shield-icap | grep "icap txn" | tail -2
railway logs -s shield-icap | grep -c "john.doe@bankco.com"
```

```
icap txn=96c5dc16... decision=allow host=api.anthropic.com provider=anthropic
icap txn=d890a0c4... decision=block host=api.anthropic.com rule=email-mask
0
```

The reference in the user's error message is the transaction id in the log.
Support can trace any decision without anyone reading what was typed. The
blocked address appears zero times.

Railway's log view lags a few seconds. If the newest lines are missing, wait and
re-run rather than concluding nothing was recorded.

---

## If something looks wrong

| What you see | What it means |
|---|---|
| Both requests return **500** | Not a verdict. Squid cannot reach the screening service and is failing closed, which is correct behaviour. Fix: `railway redeploy -s squid -y` |
| `enforcing_anything: false` | Policy loaded but nothing can block. The tenant's rules are all redactions |
| `Host key verification failed` | Re-run `setup-access.sh` |
| `No linked project found` | `railway link --project votal-swg-testbed` |

## What this is and is not

It is a test environment. No staff traffic runs through it, and nothing here is
protecting anyone today.

Putting real users behind it means the proxy somewhere their machines can reach
on a private network, plus the certificate and proxy settings pushed to each
device. That is a separate piece of work.

There is also a GCP version, written and tested, waiting on a company GCP
project: `deploy/swg/gcp/deploy-mode-a.sh`. Railway covers clients who already
run a web gateway. GCP covers those who do not.
