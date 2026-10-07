---
title: Public SWG for laptops — deploy & verify runbook
description: Stand up the public, mTLS-authenticated Mode A SWG on GCP for a roaming laptop fleet, verify it with a live handshake, roll it out by MDM, and switch monitor->enforce.
---

# Public SWG for laptops — runbook

Deploys a public, authenticated SWG a roaming laptop fleet reaches over the
internet. Spec: `docs/spec-swg-public-proxy.md`. Script:
`deploy/swg/gcp/deploy-public.sh`.

Three controls make a public interception proxy safe:
1. **mTLS** — every laptop presents an MDM-issued client certificate; no cert,
   no connection. This is enforced by **nginx**, not Squid (see below).
2. **AI-only** — Squid tunnels only AI hosts (`squid.public.conf`), so it is
   not a general relay.
3. **ICAP private** — port 1344 is never exposed; it stays on the docker bridge.

**Two tiers.** Squid cannot both terminate the device's TLS and `ssl-bump` on a
forward-mode port (`FATAL: ssl-bump on https_port requires intercept`). So the
front is split: **nginx** (`nginx-mtls.conf`, stream module) listens on `:8443`,
*requires* and verifies the device client cert (`ssl_verify_client on`), and
forwards the decrypted forward-proxy bytes to **Squid** (`squid.public.conf`,
plaintext `http_port 3128`, bridge-only), which bumps AI hosts and calls ICAP.

> It starts in **monitor** and must NOT go to enforce until the verification
> gate below passes. The mTLS config is verified by a live handshake, not by
> this document.

## 0. Prerequisites

- `gcloud` authenticated (`gcloud auth login`), a GCP project (`votal-ai`).
- A **DNS name** you will point at the VM (e.g. `swg.votal.ai`).
- The **tenant key** (adds to Secret Manager as `shield-api-key`).
- The **device-issuing CA certificate** — the CA your MDM uses to sign device
  client certs (adds as `swg-client-ca-pem`). For a first test, generate a
  throwaway one (step 2c) and replace it with the real MDM CA for rollout.
- `openssl`.

## 1. Deploy

Run from the branch checkout (the worktree, if that is where the branch lives):

```bash
cd deploy/swg/gcp
export PROJECT_ID=votal-ai
export SHIELD_PROXY_PUBLIC_HOST=swg.votal.ai
./deploy-public.sh
```

The script checks secrets first and stops when one is missing. Add them and
re-run the same command each time:

a. Tenant key:
```bash
printf %s '<TENANT_KEY>' | gcloud secrets versions add shield-api-key --data-file=-
```
b. Interception CA: generated automatically on the next run (5y, stored in
   `swg-ca-pem` — it holds a private key; restrict access).
c. Device-issuing CA. Real rollout: export your MDM's issuing CA cert and add
   it. First test: a throwaway CA —
```bash
openssl req -new -newkey rsa:4096 -sha256 -days 365 -nodes -x509 \
  -subj "/CN=Test Device CA" -keyout test-device-ca.key -out test-device-ca.pem
gcloud secrets versions add swg-client-ca-pem --data-file=test-device-ca.pem
```

The final run builds both images (via `cloudbuild.yaml`), creates the service
account, firewall (8443 + 8081 open; SSH via IAP only; **1344 never**), and the
VM, then prints the external IP and the PAC URL.

## 2. Verify (the gate — before enforce)

```bash
IP=$(gcloud compute instances describe shield-swg-public --zone us-west1-a \
      --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
curl -s http://$IP:8081/healthz        # mode, rules, enforcing_anything
gcloud compute ssh shield-swg-public --zone us-west1-a --tunnel-through-iap \
  --command "sudo docker ps --format '{{.Names}} {{.Status}}'"
```
All three — `shield-nginx`, `shield-squid`, `shield-icap` — must be `Up`.
`shield-squid` running = its `squid -k parse` passed (config valid);
`shield-nginx` running = the stream config loaded and the server cert signed.
If one is missing/restarting: `sudo docker logs <name>`.

**mTLS handshake** — mint a client cert from the device CA and run three checks:
```bash
openssl req -new -newkey rsa:2048 -nodes -keyout device.key -out device.csr -subj "/CN=test-laptop-01"
openssl x509 -req -in device.csr -CA test-device-ca.pem -CAkey test-device-ca.key -CAcreateserial -days 90 -out device.crt
gcloud secrets versions access latest --secret=swg-ca-pem > interception-ca.pem

# valid cert + AI host -> CONNECT succeeds, request is bumped + screened
curl --proxy https://swg.votal.ai:8443 --proxy-cacert interception-ca.pem \
  --proxy-cert device.crt --proxy-key device.key --resolve swg.votal.ai:8443:$IP \
  --cacert interception-ca.pem -sv -o /dev/null https://claude.ai 2>&1 | grep -i "CONNECT\|200 connection\|Forbidden"

# NO client cert -> expect failure (000)
curl --proxy https://swg.votal.ai:8443 --proxy-cacert interception-ca.pem \
  --resolve swg.votal.ai:8443:$IP -s -o /dev/null -w "%{http_code}\n" https://claude.ai

# valid cert + NON-AI host -> expect blocked (000/403, TCP_DENIED in squid log)
curl --proxy https://swg.votal.ai:8443 --proxy-cacert interception-ca.pem \
  --proxy-cert device.crt --proxy-key device.key --resolve swg.votal.ai:8443:$IP \
  -s -o /dev/null -w "%{http_code}\n" https://www.google.com
```

**Reading the result — do NOT expect `200` from the AI host.** claude.ai,
chatgpt.com etc. reject a header-less `curl` with their own `403`
(Cloudflare/anti-bot). That `403` is the *origin's*, and it proves the proxy
worked: Squid established the tunnel and forwarded to the real server. The
signals that matter are in the logs, not curl's exit code:

```bash
gcloud compute ssh shield-swg-public --zone us-west1-a --tunnel-through-iap \
  --command "sudo docker logs shield-squid 2>&1 | tail -5; echo ---; sudo docker logs shield-icap 2>&1 | grep 'icap txn' | tail -5"
```
Pass = you see, for the AI host: squid `CONNECT claude.ai:443 ... HIER_DIRECT`
(tunnel built) and `GET https://claude.ai/ ... HIER_DIRECT` (bumped + forwarded),
**and** an icap line `txn=... host=claude.ai method=GET` (ICAP inspected the
decrypted request). For the non-AI host: squid `TCP_DENIED ... CONNECT
www.google.com` (not a relay). For no-cert: curl `000` (nginx dropped it).

If the no-cert test returns anything but a failure, nginx is accepting without a
cert — confirm `ssl_verify_client on` (not `optional`) in `nginx-mtls.conf`.

**See a prompt actually screened.** A bare `GET /` has no body, so ICAP logs
`decision=skip reason=no_body`. To exercise a real prompt, POST a body through
the proxy — ICAP screens the request body before it leaves (reqmod precache),
regardless of whether the origin would accept the request:
```bash
curl --proxy https://swg.votal.ai:8443 --proxy-cacert interception-ca.pem \
  --proxy-cert device.crt --proxy-key device.key --resolve swg.votal.ai:8443:$IP \
  --cacert interception-ca.pem -s -o /dev/null -X POST https://api.anthropic.com/v1/messages \
  -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"<text that trips a tenant rule>"}]}'
# then: sudo docker logs shield-icap | grep 'icap txn' | tail -1
# monitor mode logs the decision (skip/flag); enforce mode blocks it.
```
Best end-to-end check is a real browser routed through the PAC (step 3): a chat
message is a POST with the prompt in the body, so ICAP screens the real thing
and the decision lands in Telemetry.

## 3. Roll out by MDM

Push to every managed laptop (`deploy/swg/mdm/`):
- the **interception CA** cert, trusted in the system store
  (`gcloud secrets versions access latest --secret=swg-ca-pem > interception-ca.pem`);
- a per-device **client cert + key** from your MDM issuing CA (SCEP/ACME, short
  TTL) — this is what authenticates the laptop;
- the **PAC** `http://swg.votal.ai:8081/proxy.pac`.

Verify on a device: a bumped AI site shows a cert chaining to the interception
CA, non-AI browsing is DIRECT, and a blocked prompt returns 403 and appears in
Telemetry (Source = coding-agent is Claude Code; chat prompts show under the
tenant's input telemetry).

## 4. Monitor -> enforce

Only after the gate passes and a pilot group looks right:
```bash
cd deploy/swg/gcp
SHIELD_ICAP_MODE=enforce ./deploy-public.sh      # re-runs, resets the VM
# add SHIELD_ICAP_SYNC_SCREEN=1 to block on the server's Tier 2 verdicts (+latency)
```

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `gcloud builds submit ... unrecognized arguments: -f` | old script; `--tag` cannot pick a Dockerfile. Fixed: builds via `cloudbuild.yaml`. |
| Secret `NOT_FOUND` on `versions add` | the secret is created by the script's first run; run `./deploy-public.sh` once, then add the version. |
| `shield-squid` not running | config parse failure — `sudo docker logs shield-squid`; a bad bump/ICAP directive shows here. |
| `shield-nginx` not running | `sudo docker logs shield-nginx`. `unknown directive "stream"` = the image lacks the stream module (use `nginx:stable`, which has it static); `cannot load certificate` = server-cert signing failed in the startup script. |
| No-cert curl returns 200 | nginx accepting without a cert — set `ssl_verify_client on` (not `optional`) in `nginx-mtls.conf`. |
| Every AI site shows a cert error on a device | interception CA not trusted on that device (MDM step 3). |
| `environment` tag warning on `votal-ai` | GCP org-policy nudge; usually harmless. If VM/firewall creation *fails* for it, add an `environment` tag/label. |
| `/healthz` shows `rules:0`, `tenant_id:null`, `shield_reachable:null` | icap can't read the tenant key: the file is root-owned but icap runs as uid 65532, so it reads empty ("SHIELD_API_KEY is not set" in `docker logs shield-icap`). Fixed in the script (`chown -R 65532:65532 /var/shield/secrets`); on an old VM: `sudo chown -R 65532:65532 /var/shield/secrets && sudo docker restart shield-icap`. |
| AI works but nothing blocked | still in monitor, or policy has no blocking rule — check `/healthz` `enforcing_anything` (needs `rules>0` first). |

## 6. Limits (state them plainly)

- A user who removes the MDM profile, uses an unmanaged browser/VM, or tethers
  is **not** screened. This is managed-path defense, not containment.
- Request-side only: the prompt is screened, not the model's response (RESPMOD
  is a non-goal in v1).
- `8443` is public **by design**; the client certificate is the allow-list.
