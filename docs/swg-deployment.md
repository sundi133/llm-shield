---
title: Deploy Shield at your web gateway
layout: default
nav_order: 62
permalink: /swg-deployment/
description: Install shield-icap so prompts leaving your network for AI services are screened against your DLP policy, either behind the Secure Web Gateway you already run or with a bundled Squid.
---

# Deploy Shield at your web gateway

`shield-icap` screens prompts on their way out of your network. When a prompt
violates your DLP policy it is blocked before it reaches the AI provider, and
the user sees a readable reason instead of a broken page.

It speaks ICAP (RFC 3507), so it plugs into the gateway you already run rather
than asking you to install a second one.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Try it locally first

Before touching a gateway, prove the adapter blocks what you expect. This
needs no tenant key, no CA and no Squid: a stub stands in for Shield, and a
probe script sends ICAP requests the way a gateway would.

**Terminal 1**, the stub Shield. It serves a policy bundle with one secret
pattern and one blocked term:

```bash
python -u deploy/swg/dev/fake_shield.py
```

**Terminal 2**, the adapter, pointed at the stub and set to enforce:

```bash
SHIELD_API_BASE=http://127.0.0.1:9099 SHIELD_API_KEY=dev-key \
SHIELD_ICAP_MODE=enforce SHIELD_ICAP_ALLOWED_CLIENTS=127.0.0.0/8 \
python -m icap
```

Confirm it loaded policy. `rules: 0` means it did not, and an adapter with no
rules blocks nothing:

```bash
curl -s http://127.0.0.1:8081/healthz
```

**Terminal 3**, send prompts:

```bash
python deploy/swg/dev/icap_probe.py 1344 "what is the weather in Paris"
python deploy/swg/dev/icap_probe.py 1344 "deploy with AKIAIOSFODNN7EXAMPLE please"
python deploy/swg/dev/icap_probe.py 1344 "summarise Project Titan for me"
python deploy/swg/dev/icap_probe.py 1344 "AKIAIOSFODNN7EXAMPLE" www.wikipedia.org
```

Expected:

```
  prompt : 'what is the weather in Paris'
  verdict: ICAP/1.0 204 No Content            <- forwarded

  prompt : 'deploy with AKIAIOSFODNN7EXAMPLE please'
  verdict: ICAP/1.0 200 OK                    <- blocked
  reason : Prompt contained data matching policy: aws-secret-key
  ref    : 88caea55-f7de-4a21-99e2-e90c1bb8bf5e

  prompt : 'summarise Project Titan for me'
  verdict: ICAP/1.0 200 OK
  reason : Prompt contained a blocked term: project titan

  prompt : 'AKIAIOSFODNN7EXAMPLE'             <- same secret, non-AI host
  verdict: ICAP/1.0 204 No Content            <- never inspected
```

The last one is the important one. The same credential is forwarded untouched
because Wikipedia is not on the inspected list. Traffic outside that list is
never read.

Two things to check while you are here. Set `SHIELD_ICAP_MODE=monitor` and
re-run the blocking cases: they should all return 204 while still logging
`decision=would_block`, which is what a real rollout looks like on day one.
And read the adapter's log: it records the destination, the rule and a
reference, and never the prompt.

---

## Point it at the real data plane

Drop `SHIELD_API_BASE` (the default is already correct) and supply a real
tenant key:

```bash
SHIELD_API_KEY=<your tenant key> SHIELD_ICAP_MODE=monitor python -m icap
```

Confirm policy loaded from production, not from a stub:

```bash
curl -s http://127.0.0.1:8081/healthz
```

`bundle_version` should be a hash and `rules` should be non-zero. If `rules` is
0 the tenant has no sanitization rules configured yet, and the adapter will
block nothing no matter what mode it is in.

Use `https`. The endpoint answers 301 on plain HTTP, and a tenant key must
never traverse plaintext, so `SHIELD_API_BASE=http://...` is upgraded to
`https://` with a warning rather than followed.

---

## Testing chatgpt.com

`chatgpt.com` is a separate domain from `openai.com`, and it is where most
ChatGPT usage in an enterprise actually happens. It is inspected by default,
and it needs no special configuration, but its request body is shaped
differently from the OpenAI API: roles live under `author`, and text lives
under `content.parts`.

To see a real prompt blocked in a browser you need the full Mode A stack,
because the traffic is TLS and the adapter only ever receives what Squid
decrypts for it:

1. Bring up the stack and trust the CA on your test machine (below).
2. Point the browser at the PAC file.
3. Open `chatgpt.com`, send a prompt containing a value your policy blocks.

To check the parsing alone, without any of that, capture the request body from
your browser's dev tools (Network tab, the POST to `/backend-api/conversation`,
Copy as `Request payload`) and feed it in:

```bash
python -m icap extract body.json chatgpt.com /backend-api/conversation
```

```
  provider   : openai
  parsed     : True   (False means Tier 2 is skipped)
  turns      : 1
  last_user  : 'my key is AKIAIOSFODNN7EXAMPLE'
```

This is the fastest way to onboard any provider not listed here. The command
exits non-zero, so it can go in a check, when either the body yields no text
at all or the shape was recognised but unreadable. The second case is the one
that matters: DLP still sweeps whatever string leaves it can salvage, but the
extraction needs a case adding in `icap/extract.py`.

Two hosts to add if your fleet uses them, since neither shares a domain with
its vendor's API: `copilot.microsoft.com` and `githubcopilot.com` are covered,
but Copilot embedded in Microsoft 365 rides on `*.office.com` and is not.
Inspecting all of Microsoft 365 is a much larger decision than inspecting an
AI vendor, which is why it is not on by default.

---

## Which mode do you need?

Run the pre-flight first. It takes a few seconds and it decides everything
else.

```bash
docker run --rm --pid=host shield-icap preflight
```

```
shield-icap pre-flight

  api.openai.com                   intercepted by Zscaler
  api.anthropic.com                intercepted by Zscaler

  forwarding client: Zscaler

Existing inspection detected: Zscaler

  -> Mode B (ICAP only). Point that gateway's ICAP service at
     icap://<this-host>:1344/screen.
  -> Do NOT install a second root CA. A second MITM means two
     forged chains, two bypass lists, and twice the debugging.
```

| | Mode B | Mode A |
|---|---|---|
| When | You already run a gateway | You do not |
| Adds a root CA | No | Yes |
| Endpoint changes | None | CA plus PAC by MDM or GPO |
| Effort | Hours | Days, plus security sign-off |

If you run Zscaler, Netskope, Blue Coat, Cisco WSA, Forcepoint or Palo Alto,
you want Mode B. Your traffic is already decrypted, and adding a second
interception point buys nothing.

---

## Mode B: behind the gateway you already have

### 1. Run the adapter

Put it where the gateway can reach it with low latency, ideally the same
region or datacenter. ICAP is synchronous.

```bash
docker run -d --name shield-icap \
  -p 1344:1344 -p 8081:8081 \
  -e SHIELD_API_KEY_FILE=/run/secrets/shield_api_key \
  -e SHIELD_ICAP_MODE=monitor \
  -e SHIELD_ICAP_ALLOWED_CLIENTS=10.0.0.0/8 \
  --read-only --user 65532 \
  shield-icap
```

Set `SHIELD_ICAP_ALLOWED_CLIENTS` to the gateway's subnet. Port 1344 accepts
content for screening and returns a verdict, so anyone who can reach it can
probe your DLP patterns.

### 2. Point the gateway at it

Add an ICAP service in your gateway's own console:

| Setting | Value |
|---|---|
| Service URL | `icap://<host>:1344/screen` |
| Method | REQMOD |
| Preview size | 4096 |
| On failure | match `SHIELD_ICAP_FAIL_OPEN` |

### 3. Scope it to AI destinations

Restrict the ICAP service to AI hosts in the gateway's policy, so the adapter
never receives anything else. This is a privacy control as much as a
performance one, and it is the sentence your works council will read.

---

## Mode A: bundled Squid

Only when there is no existing gateway.

### 1. Generate the CA

The private key is generated by you and never leaves your infrastructure. No
key is shipped in the image.

```bash
openssl req -new -newkey rsa:4096 -sha256 -days 1825 -nodes -x509 \
  -extensions v3_ca -keyout ca.pem -out ca.pem \
  -subj "/CN=Example Corp Internal Inspection"
```

### 2. Start the stack

```bash
docker compose -f docker-compose.swg.yml up -d
```

### 3. Distribute the CA

Push `ca.pem` to the system trust store by MDM or GPO. Three things are
routinely forgotten here, and each one produces confusing breakage:

- **Firefox** does not use the system trust store. Push
  `security.enterprise_roots.enabled = true`.
- **Command line tools** do not either. Push `REQUESTS_CA_BUNDLE`,
  `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` as machine environment variables,
  or every Python and Node script on the fleet starts failing TLS.
- **QUIC** bypasses the proxy entirely. Push `QuicAllowed = false`.

### 4. Push the PAC file

The adapter generates it from your policy and serves it at
`http://<host>:8081/proxy.pac`. Preview exactly what the fleet will get:

```bash
docker run --rm shield-icap pac
```

Only AI hosts are routed to the proxy. Everything else returns `DIRECT` and is
never decrypted. Banking, payroll and identity providers are on a bypass list
that is applied twice: once in the PAC, and again in Squid's `peek` step
before any decryption happens.

Deploy the PAC with the Chrome `ProxySettings` policy on Windows, or a
`com.apple.SystemConfiguration` payload on macOS.

---

## Verify

```bash
curl -s http://<host>:8081/healthz
```

```json
{"ok": true, "mode": "monitor", "screen": "async",
 "bundle_version": "a1b2c3d4", "rules": 12, "shield_reachable": true}
```

`rules: 0` means no policy loaded, and an adapter with no rules blocks nothing.
Check `shield_reachable` and your tenant key before going further.

Then send a canary: a prompt containing a deliberately planted fake credential.
In monitor mode it is reported as *would have blocked* and still forwarded.

---

## Roll out

Follow the same three moves as any other Shield policy, described in
[policy-lifecycle](/policy-lifecycle/).

1. **Monitor.** The default. Nothing is blocked and everything is reported.
2. **Review** what would have blocked. This is where false positives surface,
   while they are still free.
3. **Enforce.** Set `SHIELD_ICAP_MODE=enforce`, on a canary group first.

An operator who cannot safely try enforce will stay in monitor forever, so do
step 3 on a small group early rather than perfecting step 2.

---

## What it does when things break

| Situation | Behavior |
|---|---|
| Shield unreachable at boot | No rules load, so nothing is blocked. Browsing is unaffected. |
| Shield goes down after loading | The last policy keeps enforcing, indefinitely. Stale policy beats no policy. |
| Adapter is down | Squid's `bypass=off` blocks; set `bypass=on` for fail-open. Keep it consistent with `SHIELD_ICAP_FAIL_OPEN`. |
| Body is larger than 1 MiB | Forwarded unscreened and logged. Nothing is blocked on the basis of something that was not read. |
| A pattern in your policy will not compile | Dropped with a warning. The rest of the policy still arms. |

The adapter never writes prompt content to its own logs. Only the destination,
the rule that fired and a correlation reference. Users who are blocked get that
reference, so a help desk can find the decision from one string.

---

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SHIELD_API_KEY` / `_FILE` | required | Tenant key. Prefer the file form. |
| `SHIELD_ICAP_MODE` | `monitor` | `monitor` or `enforce` |
| `SHIELD_ICAP_ALLOWED_CLIENTS` | all | CIDRs allowed to reach port 1344 |
| `SHIELD_ICAP_AI_HOSTS` | built in | Destinations to inspect |
| `SHIELD_ICAP_BYPASS_HOSTS` | built in | Never inspected |
| `SHIELD_ICAP_SYNC_SCREEN` | `0` | Inline Tier 2. Adds 14 to 20 seconds per prompt. |
| `SHIELD_ICAP_FAIL_OPEN` | `0` | Only applies in sync mode |
| `SHIELD_ICAP_REDACT_FALLBACK` | `pass` | How to treat a `redact` rule, since v1 does not rewrite bodies |
| `SHIELD_ICAP_MAX_BODY` | `1048576` | Bodies above this are forwarded unscreened |
| `SHIELD_ICAP_BUNDLE_POLL_S` | `300` | Policy refresh interval |

---

## Scaling

The adapter is stateless, so run two or more replicas behind whatever your
gateway uses to reach them. Rule evaluation is CPU bound on bodies under 1 MiB,
so start at 2 vCPU per replica and measure. The `ISTag` header changes when
your policy changes, which correctly invalidates gateway side caching.
