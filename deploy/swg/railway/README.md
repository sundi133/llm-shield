# Mode A on Railway, private only

A testbed. Squid and `shield-icap` run as two Railway services talking to each
other over Railway's private network, with **nothing publicly reachable**.

It exists to answer one question: does the stack run on Railway. It is not a
deployment for real users, and the reason is in the next section.

---

## Read this before enabling a TCP Proxy on Squid

Do not. `squid.conf` decides who may use the proxy purely by source address:

```
acl localnet src 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 fe80::/10
http_access allow localnet
http_access deny all
```

There is no `auth_param` anywhere in that file, so source address is the only
control there is. Put it behind Railway's TCP Proxy and Squid stops seeing the
real caller: every connection arrives from Railway's proxy. Two outcomes, both
wrong:

- that address matches one of those ranges, so **every person on the internet
  matches `localnet`** and we have published an open relay, or
- it does not, so **everything is denied** and the proxy does nothing.

Neither is "working", and an open proxy is found and abused quickly. The same
applies to `SHIELD_ICAP_ALLOWED_CLIENTS` on the adapter: it checks the TCP peer
(`icap/server.py`), which behind a TCP proxy is Railway, not the caller.

So: keep both services private. If a public endpoint is ever needed, the
adapter already supports mutual TLS (`SHIELD_ICAP_TLS_CERT`, `_KEY`,
`_CLIENT_CA`) and that, not an IP allowlist, is the control that works. Squid
would need `auth_param` added, which is a change to a security-critical file
and wants its own spec.

---

## Two services, one project

| Service | Build | Networking |
|---|---|---|
| `shield-icap` | `Dockerfile.icap` | Private only. No public domain, no TCP proxy |
| `squid` | `deploy/swg/Dockerfile.squid` | Private only. No public domain, no TCP proxy |

### shield-icap

Variables:

```
RAILWAY_DOCKERFILE_PATH = Dockerfile.icap
SHIELD_API_KEY          = <tenant key>        # Railway secret, not plaintext
SHIELD_ICAP_MODE        = monitor
SHIELD_ICAP_PORT        = 1344
SHIELD_ICAP_HEALTH_PORT = 8081
```

Leave `SHIELD_ICAP_ALLOWED_CLIENTS` unset. On a private network it adds
nothing, and setting it to a plausible-looking CIDR invites the belief that it
is protecting something.

### squid

Variables:

```
RAILWAY_DOCKERFILE_PATH = deploy/swg/Dockerfile.squid
SHIELD_ICAP_ENDPOINT    = shield-icap.railway.internal:1344
```

`SHIELD_ICAP_ENDPOINT` is the one Railway-specific setting. `squid.conf` ships
`icap://shield-icap:1344/screen`, which resolves by container name under
docker-compose and on the GCP instances but not here, because Railway addresses
services as `<service>.railway.internal`. The entrypoint substitutes it at boot
and defaults to the old value, so nothing else changes.

Squid also needs the CA and a volume:

- **CA**: mount or write the operator-generated `ca.pem` to
  `/etc/squid/ssl/ca.pem`. The entrypoint exits with `FATAL: no CA` without it,
  which is correct: a proxy that starts without a CA cannot bump anything and
  would pass everything through unread.
- **Volume**: mount one at `/var/spool/squid`. That holds `ssl_db`, the forged
  certificate database. Without it, every restart regenerates every
  certificate.

For this testbed the CA is a throwaway. Generate it, use it, delete it:

```bash
openssl req -new -newkey rsa:4096 -sha256 -days 30 -nodes -x509 \
  -extensions v3_ca -keyout ca.pem -out ca.pem \
  -subj "/CN=Votal SWG Railway testbed (throwaway)"
```

---

## Verifying it

Everything is private, so the test has to run inside the project. Add a
throwaway third service (any image with `curl` and `python`) and from its shell:

```bash
# 1. Did policy load? rules: 0 means nothing will ever block, whatever the mode.
curl -s http://shield-icap.railway.internal:8081/healthz

# 2. Does Squid intercept and does ICAP block?
curl -x http://squid.railway.internal:3128 --cacert /path/ca.pem \
  -H 'content-type: application/json' \
  -d '{"model":"claude-opus-4","messages":[{"role":"user",
       "content":"deploy with AKIAIOSFODNN7EXAMPLE please"}]}' \
  https://api.anthropic.com/v1/messages
```

Expected: HTTP 403 with a Shield block reason, in enforce mode. In monitor mode
the request is forwarded and the decision is logged as `would_block`.

Then confirm the two controls, which are the parts worth demonstrating:

```bash
# A non-AI host must be spliced, never decrypted: this succeeds with the REAL
# certificate, so --cacert is not needed and must not be.
curl -x http://squid.railway.internal:3128 https://www.wikipedia.org/ -o /dev/null -w '%{http_code}\n'

# The adapter must not log prompt text. Only destination, rule and reference.
# Search the service logs for the secret above. Finding it is a bug.
```

---

## Known unknowns

Two things this configuration assumes and does not prove. Check them on the
first run rather than trusting them:

**Railway private networking is IPv6-only.** Squid supports IPv6, and line 23
of `squid.conf` already covers IPv6 private space with `fc00::/7`, so internal
clients should match `localnet` unchanged. Not verified.

**ICAP over that network.** `icap_service` pointing at an IPv6
`.railway.internal` name is the specific combination that has never been run
here. If Squid cannot reach the adapter it will fail closed, because
`squid.conf` ships `bypass=off`. That is the correct failure, and it looks like
total AI outage for anything behind the proxy, so recognise it: check the Squid
logs for the ICAP service being marked down before assuming a policy problem.

---

## What this does not give you

Real users behind the proxy. Their laptops would have to reach Squid from
outside Railway's private network, which is the exposure the first section
rules out.

Screening Votal's own staff means Squid somewhere their machines can reach on a
private range, an office network or behind VPN, plus the CA and PAC pushed to
each device. `deploy/swg/mdm/` has the endpoint half of that. It is worth doing
and it is a different piece of work.
