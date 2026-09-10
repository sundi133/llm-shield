# Demoing it by hand

`demo.sh` runs all of this in one go. Type it out instead when you want the
audience to see each step happen, or when a script that prints its own
conclusions feels too much like a recording.

Every command runs inside the adapter container, because nothing in the project
is reachable from outside. That is worth saying out loud: it is the design, not
an inconvenience.

The container is `python:3.12-slim`, so there is no `curl`. Python and `openssl`
are what you have.

---

## Before the meeting

Run step 2 once. If it returns **500**, Squid has lost its connection to the
screening service, which happens when the adapter restarts under it. Sixty
seconds to fix:

```bash
railway redeploy -s squid -y
```

That is fail-closed behaviour working correctly, but mid-demo it reads as an
outage. Get it out of the way first.

Optionally open a second terminal streaming the log, so decisions appear as you
make them:

```bash
railway logs -s shield-icap
```

---

## 1. It has real policy, and the policy is armed

```bash
railway ssh -s shield-icap "python -c \"import urllib.request as u; print(u.urlopen('http://[::1]:8081/healthz').read().decode())\""
```

```json
{"mode": "enforce", "tenant_id": "bankco", "bundle_version": "931b5e95...",
 "rules": 4, "blocking_rules": 3, "shield_reachable": true,
 "enforcing_anything": true}
```

**Say:** this pulled the tenant's real policy from production, not a mock.

**Point at `enforcing_anything`,** not `rules`. A policy can load four rules and
enforce none of them, if every rule is a redaction the gateway cannot perform.
That is exactly what this tenant did before it was configured, and it is the
failure an operator is most likely to miss: the console looks healthy and
nothing is being blocked.

---

## 2. A harmless prompt goes through

```bash
railway ssh -s shield-icap "python -c \"
import http.client, ssl, json
c = http.client.HTTPSConnection('squid.railway.internal', 3128, context=ssl._create_unverified_context(), timeout=45)
c.set_tunnel('api.anthropic.com', 443)
c.request('POST', '/v1/messages', json.dumps({'model':'claude-opus-4','messages':[{'role':'user','content':'what is the weather in Paris'}]}), {'content-type':'application/json'})
r = c.getresponse(); print('HTTP', r.status, '->', r.read().decode()[:110])
\""
```

```
HTTP 401 -> {"type":"error","error":{"type":"authentication_error", ...
```

**Say:** 401 is Anthropic answering. We have no API key on this testbed, so
reaching them at all is the proof the prompt was forwarded untouched. The
gateway did not get in the way.

---

## 3. A prompt with customer data does not

Same command, one word changed. Say that out loud, because it is the whole
point: nothing about the route changed, only the content.

```bash
railway ssh -s shield-icap "python -c \"
import http.client, ssl, json
c = http.client.HTTPSConnection('squid.railway.internal', 3128, context=ssl._create_unverified_context(), timeout=45)
c.set_tunnel('api.anthropic.com', 443)
c.request('POST', '/v1/messages', json.dumps({'model':'claude-opus-4','messages':[{'role':'user','content':'email john.doe@bankco.com about his account'}]}), {'content-type':'application/json'})
r = c.getresponse(); print('HTTP', r.status); print(r.read().decode()[:260])
\""
```

```
HTTP 403
{"error":"Blocked by your organization's AI policy. Prompt contained data
matching policy: email-mask.", "rule_id":"email-mask", "severity":"medium",
"reference":"3d6da83f-..."}
```

**Say:** blocked before it left the network. The user gets a readable reason
rather than a broken page, and a reference they can quote to the help desk.

**Only the email example blocks.** This tenant's policy covers email addresses.
Credit card numbers and AWS keys are not in its ruleset and will sail through,
so do not improvise new examples live.

---

## 4. The best one: what we can and cannot read

This is the question a works council or a security reviewer actually asks, and
the answer is visible in one command.

```bash
for h in api.anthropic.com www.wikipedia.org; do
  echo "== $h"
  railway ssh -s shield-icap "sh -c 'echo | openssl s_client -proxy squid.railway.internal:3128 -connect $h:443 -servername $h 2>/dev/null | grep ^issuer='"
done
```

```
== api.anthropic.com
issuer=CN=Votal SWG Railway testbed        <- our certificate. We decrypt this.
== www.wikipedia.org
issuer=C=US, O=Let's Encrypt, CN=YE2       <- the real one. We never touched it.
```

**Say:** the proxy looks at the destination *before* decrypting anything and
chooses. AI providers are decrypted and screened. Everything else, banking,
payroll, identity providers, is a blind tunnel we could not read if we wanted
to. That distinction is enforced twice: once in the browser configuration, and
again in the proxy before any decryption happens.

---

## 5. What was recorded, and what was not

```bash
railway logs -s shield-icap | grep "icap txn" | tail -2
```

```
icap txn=a62f073d... decision=allow host=api.anthropic.com provider=anthropic parsed=True
icap txn=fcc9344c... decision=block host=api.anthropic.com provider=anthropic rule=email-mask
```

Then the part worth pausing on:

```bash
railway logs -s shield-icap | grep -c "john.doe@bankco.com"
```

```
0
```

**Say:** we record that a decision happened, the destination, and which rule
fired. We never record the prompt. The reference in the user's error message is
how support traces a decision without anyone reading what was typed.

Railway's log view lags a few seconds, so if the newest lines are missing, wait
and re-run rather than concluding nothing was recorded.

---

## If he asks

**"Is this protecting our staff right now?"** No. It is a test environment.
Putting real users behind it needs the proxy somewhere their machines can
reach, on the office network or behind VPN, plus the certificate and proxy
settings pushed to each device. Different piece of work.

**"What if the proxy goes down?"** AI access stops for anyone behind it. That
is deliberate: the alternative is traffic passing uninspected, which defeats
the point. It is one setting if a customer wants the opposite.

**"Can someone get around it?"** Yes, if they want to. A personal laptop, a
phone hotspot, a browser we do not manage. This is a control against accidental
leakage by ordinary staff, which is the actual way AI data loss happens. Making
it mandatory means blocking outbound traffic to AI providers from anything
except the proxy, which is a network change, not a proxy setting.

**"Why not serverless / why a VM?"** Neither half speaks HTTP. The proxy handles
raw TCP tunnels and the screening service speaks ICAP on its own port. Cloud
Run and Lambda only accept HTTP, so they cannot host either. It also sits inline
on every prompt, so a cold start would be a stalled request.
