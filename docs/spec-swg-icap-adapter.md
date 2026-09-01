---
title: "Spec: SWG ICAP adapter (shield-icap)"
layout: default
nav_order: 61
permalink: /spec-swg-icap-adapter/
description: Inline prompt and DLP enforcement for enterprise web traffic via an ICAP adapter in front of api.guardrails.votal.ai, shipped either behind the customer's existing Secure Web Gateway or bundled with Squid.
---

# Spec: SWG ICAP adapter (`shield-icap`)

Status: APPROVED. Tasks 1-5 implemented on `feat/swg-icap-adapter`.
Operator-facing guide: [swg-deployment](/swg-deployment/). Task 6 (redaction,
multipart, RESPMOD, extension/ICAP de-duplication) remains a separate spec.

---

## 1. Problem & outcome

Enterprises already decrypt employee web traffic at a Secure Web Gateway
(Zscaler, Netskope, Blue Coat, Cisco WSA, Forcepoint). Today Shield can only see
prompts if the customer installs the browser extension. That leaves out every
managed fleet where a browser extension is not the preferred control point, and
it ignores the fact that the customer already has a decryption point we can plug
into.

**Outcome.** A customer-hosted container, `shield-icap`, that speaks ICAP
(RFC 3507) to the customer's SWG and enforces Shield policy on prompts leaving
the enterprise for AI services. When a DLP rule is violated, the prompt is
blocked before it reaches the AI provider and the user sees a readable reason.

**Observable success condition.** With `shield-icap` deployed behind Squid, a
`POST` to `api.anthropic.com` whose body contains a value matching the tenant's
DLP rules receives an HTTP 403 with a Shield block reason, the prompt never
reaches the provider, and the decision appears in tenant telemetry with
`destination=api.anthropic.com`.

### Non-goals

- Building an SWG. We integrate with one, or bundle Squid unmodified.
- TLS interception logic. The SWG or Squid does that; we receive plaintext.
- Response scanning (ICAP RESPMOD). Request-side only in v1.
- Vendor-specific partner APIs (Zscaler inline, Netskope Cloud Exchange).
  Separate spec, separate business-development timeline.
- Prompt redaction/rewriting. See §5, deferred to a follow-up task.
- Replacing the browser extension. Complementary; see §7 double-counting.

---

## 2. Plane & latency contract

`shield-icap` is **a new customer-hosted edge artifact**, not a new Shield plane.
It is a *client* of the data plane over the public internet
(`https://api.guardrails.votal.ai`). It imports nothing from `admin_app.py`, adds
no route to `core/app.py`, and adds no dependency to the existing images.

**Does it touch the guard path?** It *calls* `/guardrails/input`. It does not
add latency *to* `/guardrails/input`, `cap/mint` or `tools/call` for any other
caller. No change to `core/`, no change to `api/routes_classify.py`.

**But it is inline on the customer's own hot path**, and that is the hard
constraint of this spec:

> `managed_schema.json` documents that a cloud text screen measures **14 to 20
> seconds**. An ICAP transaction that takes 14 seconds will hit the SWG's ICAP
> timeout, and even if it does not, it adds 14 seconds to every prompt the user
> sends.

This is the single biggest risk in the feature, and it drives the two-tier
design:

| Tier | Runs where | Latency | Decides |
|---|---|---|---|
| **Tier 1: local DLP** | in `shield-icap`, from the cached edge bundle | sub-millisecond | secrets, PII, keyword blocklist. Blocks inline. |
| **Tier 2: server screen** | `POST /guardrails/input` | 14-20s (cloud) | injection, jailbreak, topic. **Async by default in v1.** |

Tier 1 uses the existing bundle at `GET /v1/edge/policy-bundle`
(`api/routes_edge.py`), which already ships tenant regex
sanitization rules plus keyword blocklists with ETag caching. That endpoint was
built for the browser extension and is reused verbatim. No server change needed.

**Latency budget for the ICAP transaction: p99 under 50ms.** Achieved because
the default path never blocks on Tier 2.

`SHIELD_ICAP_SYNC_SCREEN=1` makes Tier 2 synchronous for customers who accept
the latency. Off by default.

---

## 3. Data model

`shield-icap` holds **no Redis keys of its own** and no persistent state. It is
horizontally scalable and restart-safe.

In-process state only:

| Item | Shape | TTL / invalidation |
|---|---|---|
| `bundle` | `{version, rules:[{id, regex, action, severity, replacement}], blocklists:[str]}` | refreshed every `SHIELD_ICAP_BUNDLE_POLL_S` (default 300s) via `GET /v1/edge/policy-bundle` with `If-None-Match`; 304 keeps the cached copy |
| `compiled` | `tuple[Rule, ...]` of compiled `regex` patterns, built once per bundle version | replaced atomically on version change |
| `istag` | `ISTag: "<bundle.version>"` returned on every ICAP response | changes when the bundle version changes, invalidating SWG-side caching |

**Tenant scoping.** One `shield-icap` deployment serves exactly one tenant. The
tenant is fixed by `SHIELD_API_KEY` at container start and is never taken from
the inspected traffic. Cross-tenant isolation is therefore structural: the
adapter has no way to name another tenant. Multi-tenant MSP deployments run one
container per tenant.

**Attribution.** The SWG's authenticated user is forwarded, when present, from
the `X-Authenticated-User` ICAP header (Squid, Blue Coat and WSA all emit some
form of this) into the existing `X-Device-Id` header on the Shield call, and the
inspected `Host` goes into `X-Shield-Destination`. Both are already read by
`api/routes_classify.py:219`; no server change.

---

## 4. API / interface

### 4.1 ICAP surface (what the SWG talks to)

Listens on `0.0.0.0:1344`.

**`OPTIONS icap://host:1344/screen`**

```
ICAP/1.0 200 OK
Methods: REQMOD
Service: Votal Shield 1.0
ISTag: "<bundle version>"
Allow: 204
Preview: 4096
Transfer-Preview: *
Transfer-Ignore: jpg,jpeg,png,gif,css,js,woff,woff2,svg,ico,mp4
Options-TTL: 300
Encapsulated: null-body=0
```

**`REQMOD icap://host:1344/screen`** with an encapsulated HTTP request.

Three possible responses:

| Response | Meaning | When |
|---|---|---|
| `ICAP/1.0 204 No Content` | forward unchanged | not an AI destination, not a POST, no rule hit. The overwhelmingly common case. |
| `ICAP/1.0 200 OK` + encapsulated HTTP 403 | block | a Tier 1 rule with `action: block` matched, or Tier 2 returned `action: block` in sync mode |
| `ICAP/1.0 200 OK` + modified `req-hdr`/`req-body` | rewritten request | **deferred, see §5** |

The 403 body is JSON so a browser or an extension can render it, and plain
enough to read raw:

```json
{
  "error": "blocked_by_votal_shield",
  "reason": "Prompt contained data matching policy: aws-secret-key",
  "rule_id": "aws-secret-key",
  "severity": "critical",
  "destination": "api.anthropic.com",
  "reference": "<uuid>"
}
```

`reference` is the audit correlation id, so a user calling the help desk gives
one string and an operator finds the decision.

### 4.2 Shield calls made by the adapter

| Call | Purpose | Frequency |
|---|---|---|
| `GET https://api.guardrails.votal.ai/v1/edge/policy-bundle` | Tier 1 rules | every 300s, 304 when unchanged |
| `POST https://api.guardrails.votal.ai/guardrails/input` | Tier 2 screen + telemetry | per AI-bound POST |

Headers on both:

```
X-API-Key: <tenant key>
Authorization: Bearer <token>        # only when SHIELD_PROXY_TOKEN is set
X-Device-Id: <SWG authenticated user or client IP>
X-Shield-Destination: <inspected Host>
```

Request body for the screen, matching the existing simple format:

```json
{"message": "<extracted prompt text>", "session_id": "<icap transaction id>"}
```

Response fields consumed: `action` (`pass|log|warn|redact|block`), `safe`,
`guardrail_results[].{guardrail,passed,message}`.

### 4.3 Admin surface

**None.** No new router, no admin-plane mount, no `admin_app.py` import, so
`Dockerfile.admin` is untouched and
`tests/test_admin_dockerfile_imports.py` is unaffected. Decisions surface in the
existing tenant telemetry because `/guardrails/input` already audit-logs them.

### 4.4 Local health surface

`GET :8081/healthz` returns `{"ok": true, "bundle_version": "...", "mode": "monitor|enforce", "shield_reachable": true}`. Used by compose healthchecks and by
the operator verification step in §9.

---

## 5. Security & backward compatibility

**Nothing existing changes.** New standalone artifact, new Dockerfile, new
compose file. Zero diff to `core/`, `api/`, `admin_app.py`, or any existing
image. No default anywhere in Shield changes behavior.

**Default mode is `monitor`.** On first start the adapter answers `204` to
everything and only reports, matching the three-move flow in
[policy-lifecycle](/policy-lifecycle/). An operator flips
`SHIELD_ICAP_MODE=enforce` after reviewing what would have blocked. Shipping
enforce-by-default into an inline path in someone's browser traffic is how you
get uninstalled.

**Fail-closed vs fail-open** is decided in two independent places and both must
be set consistently, which is a documented trap:

| Layer | Setting | Fail-closed | Fail-open |
|---|---|---|---|
| Squid | `icap_service ... bypass=` | `bypass=off` | `bypass=on` |
| Adapter | `SHIELD_ICAP_FAIL_OPEN` | `0` (default) | `1` |

The adapter's own default is fail-closed **for Tier 1 only**, which is safe
because Tier 1 has no network dependency: if the bundle has never loaded, the
adapter has no rules, and it answers `204`. It cannot fail closed on an empty
policy. Tier 2 unreachable in async mode is a logged warning, never a block.

**Redaction is deferred, deliberately.** `/guardrails/input` returns an `action`
of `redact`, but the response carries no rewritten message body for the prompt
path. Rewriting an encapsulated request body also means recomputing
`Content-Length`, handling chunked encoding, and re-serializing provider-specific
JSON, each of which can corrupt a request. v1 therefore maps `redact` to the
tenant's configured `SHIELD_ICAP_REDACT_FALLBACK` (`pass` by default, `block`
opt-in) and logs it. Real redaction is task 5.

**Threat model for the adapter itself.** It sits on decrypted corporate traffic,
so it is a high-value target. Mitigations: no disk writes, no inbound port
except 1344 and 8081 (both bound to the customer's internal network), tenant key
supplied only as a Docker/Kubernetes secret and never logged, prompt bodies
never written to the adapter's own logs (only rule ids and destinations), and
the container runs non-root with a read-only root filesystem.

**A malicious caller who can reach port 1344** can submit arbitrary content for
screening and read the verdict. That leaks the tenant's DLP regex patterns by
oracle. Documented: bind 1344 to the SWG's network only, never to 0.0.0.0 on a
routable interface. `SHIELD_ICAP_ALLOWED_CLIENTS` (CIDR list) enforces this in
the adapter as defense in depth.

---

## 6. Packaging & deploy

New files, none of them touching an existing image:

| File | Purpose |
|---|---|
| `icap/server.py` | ICAP protocol (OPTIONS, REQMOD, Preview, chunked bodies) |
| `icap/extract.py` | provider body parsers: OpenAI, Anthropic, Google, generic |
| `icap/policy.py` | bundle fetch/cache, Tier 1 evaluation |
| `icap/shield.py` | `/guardrails/input` client, async queue |
| `Dockerfile.icap` | adapter image, non-root, read-only rootfs |
| `requirements-icap.txt` | adapter deps only |
| `docker-compose.swg.yml` | mode A: Squid + adapter |
| `deploy/swg/squid.conf` | peek/splice + ICAP wiring |
| `deploy/swg/pac.js.tmpl` | PAC template rendered from the AI-host list |
| `tests/test_icap_*.py` | see §8 |

**Dependency declaration.** The adapter needs `httpx` and `regex`, and nothing
else. ICAP itself is implemented directly on `asyncio` rather than pulling a
third-party ICAP library, because the available ones are unmaintained and the
subset we need (OPTIONS, REQMOD, Preview, 204) is small.
`requirements-icap.txt` lists both explicitly so the image does not inherit the
full runtime set.

`regex` is not a style preference over stdlib `re`. Tier 1 evaluates
tenant-authored patterns inline on employee browsing, so a catastrophic pattern
has to be *bounded*, not merely noticed. Measured during task 3:

- stdlib `re` has no match timeout and holds the GIL for the whole match, so an
  `asyncio.wait_for` around it cannot fire until the match it was meant to bound
  has already completed. The guard reads as protection and is not.
- `regex` supports a per-match `timeout=` that self-terminates, and releases the
  GIL while matching, so other in-flight transactions keep running.

`tests/test_icap_policy.py` imports `icap.policy`, so `regex` is declared in
`requirements-test.txt` as well. It had been reaching the local venv only
transitively, which is the exact drift the "declare dependencies" invariant
exists for. Verified in a clean venv that the image's whole dependency set is
`httpx` and `regex` plus their transitives.

**`Dockerfile.admin` is not modified.** No new module is imported by
`admin_app.py`. Called out explicitly because the invariant exists.

**Images to rebuild:** `shield-icap` only. Nothing existing is rebuilt.

**Env flags:**

| Var | Default | Meaning |
|---|---|---|
| `SHIELD_API_BASE` | `https://api.guardrails.votal.ai` | data plane |
| `SHIELD_API_KEY` | required | tenant key, secret-mounted |
| `SHIELD_PROXY_TOKEN` | unset | bearer for a fronting proxy (RunPod topology) |
| `SHIELD_ICAP_MODE` | `monitor` | `monitor` or `enforce` |
| `SHIELD_ICAP_FAIL_OPEN` | `0` | behavior when Tier 2 required and unreachable |
| `SHIELD_ICAP_SYNC_SCREEN` | `0` | make Tier 2 inline (accepts 14-20s) |
| `SHIELD_ICAP_REDACT_FALLBACK` | `pass` | how to treat `action: redact` in v1 |
| `SHIELD_ICAP_BUNDLE_POLL_S` | `300` | bundle refresh interval |
| `SHIELD_ICAP_ALLOWED_CLIENTS` | `0.0.0.0/0` | CIDR allowlist for port 1344 |
| `SHIELD_ICAP_AI_HOSTS` | built-in list | destinations to inspect |

---

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Empty body / GET / non-AI host | `204` immediately, before any parsing |
| Body larger than `SHIELD_ICAP_MAX_BODY` (default 1 MiB) | `204` plus a `oversize` telemetry event. Do not block what we did not read. |
| Body is not JSON, or is a provider shape we do not parse | fall back to scanning the raw body text with Tier 1 rules; skip Tier 2 |
| Multipart file upload to an AI host | v1: `204` and log as a coverage gap. `/guardrails/file` integration is a follow-up. |
| Bundle never loaded (cold start, Shield unreachable) | no rules, so `204` on everything, `healthz.shield_reachable=false`, loud log. Cannot fail closed on an empty policy. |
| Bundle fetch fails after a successful load | keep serving the last-known-good bundle indefinitely, log at WARN |
| Shield returns 5xx on Tier 2 (async mode) | logged, no effect on traffic |
| Shield returns 5xx on Tier 2 (sync mode) | `SHIELD_ICAP_FAIL_OPEN` decides |
| Tier 2 exceeds deadline (sync mode) | same as 5xx. A timeout is not an approval. |
| SSE / streaming response | RESPMOD not implemented; responses are never intercepted |
| Chunked request body | Preview then full-body pull; must handle `0; ieof` correctly |
| SWG sends `Allow: 204` absent | must return a full 200 echo instead of 204, or Squid stalls |
| Malformed ICAP framing | `ICAP/1.0 400 Bad Request`, connection closed, never a hang |
| Concurrency | stateless per transaction; bundle swap is a single atomic reference assignment |
| Duplicate telemetry when the browser extension is also deployed | both taps report the same prompt. Adapter sets `X-Shield-Source: icap` so telemetry can de-duplicate. Deduplication itself is a follow-up. |
| A tenant regex that will not compile | dropped at bundle load with a warning, the rest of the policy still arms. One bad pattern typed into the portal must not disarm everything else. |
| A tenant regex that backtracks catastrophically | the scan carries a `SHIELD_ICAP_SCAN_TIMEOUT_MS` budget (default 250ms) spanning the whole rule set, enforced inside `regex` so the match terminates. On expiry: allow, and log loudly enough for the operator to find the pattern. A pattern that cannot finish is not a verdict. |
| Redis down | not applicable, the adapter never touches Redis |

**Fail-open vs fail-closed, stated:** the adapter is **fail-open on
availability** (Shield unreachable never breaks the customer's browsing) and
**fail-closed on policy** (a matched `critical` Tier 1 rule blocks, and cannot
be downgraded by a Shield outage because Tier 1 needs no network). This is the
opposite polarity to the MCP gateway, which defaults `SHIELD_GATEWAY_FAIL_OPEN`
to closed, and the difference is deliberate: the gateway sits in front of tool
calls the customer chose to guard, while this sits in front of all of an
employee's browsing.

---

## 8. Test plan (Definition of Done)

Unit tests, no network, no Squid required:

1. `test_icap_options` — OPTIONS advertises `Preview`, `Allow: 204`, `ISTag`; `ISTag` changes when the bundle version changes.
2. `test_icap_reqmod_204` — GET, non-AI host, empty body, oversize body each return exactly `204` and make no Shield call.
3. `test_icap_extract` — prompt extraction from OpenAI `messages[]`, Anthropic `messages[]`, Google `contents[]`, and an unknown shape falling back to raw text.
4. `test_icap_tier1_block` — a body matching a `critical` bundle rule yields a 200 with an encapsulated 403 whose JSON carries `rule_id` and `reference`.
5. `test_icap_monitor_mode` — the same body in `monitor` mode yields `204` and still emits telemetry.
6. `test_icap_bundle_cache` — 304 keeps the previous bundle; a version change swaps the compiled rules; a fetch failure after a good load keeps serving.
7. `test_icap_cold_start` — no bundle ever loaded returns `204` on everything even with `SHIELD_ICAP_FAIL_OPEN=0`. **This is the regression guard for the worst failure: fail-closed on an empty policy would black-hole all corporate browsing.**
8. `test_icap_sync_timeout` — sync mode plus a slow Shield honors `SHIELD_ICAP_FAIL_OPEN` in both positions.
9. `test_icap_chunked_preview` — `0; ieof` and continued-body paths both parse.
10. `test_icap_client_allowlist` — a client outside `SHIELD_ICAP_ALLOWED_CLIENTS` is refused.
11. `test_icap_no_body_logging` — asserts the prompt body never appears in adapter log output.
12. `test_icap_headers` — `X-Device-Id`, `X-Shield-Destination`, `X-Shield-Source` are set on the Shield call.

Integration (marked, not in the default CI gate): `docker compose -f
docker-compose.swg.yml up`, curl through Squid to a stub AI host, assert 403.

**Done means:** all of the above pass, `python -m pytest tests -q` is green in a
**clean venv** (`python -m venv /tmp/x && /tmp/x/bin/pip install -r
requirements-test.txt`), and the CI `pytest` gate passes.

---

## 9. Operator install path

This is what an enterprise operator actually does. Two modes, chosen by a
pre-flight check.

### 9.0 Pre-flight: does the customer already decrypt?

```bash
docker run --rm shield-icap preflight
```

Reports: existing SWG forwarding client detected (`ZscalerClientConnector`,
Netskope `stAgentSvc`), and whether a test TLS handshake to a known host returns
a chain issued by a non-public CA. Output picks the mode:

```
Existing inspection detected: Zscaler
→ Mode B (ICAP only). Do NOT install a second root CA.
```

### 9.1 Mode B: behind an existing SWG (preferred)

No CA, no proxy, no endpoint change. The customer already decrypts.

1. Deploy the container into a subnet the SWG can reach, ideally the same
   region or datacenter, because ICAP is synchronous:

   ```bash
   docker run -d --name shield-icap \
     -p 1344:1344 -p 8081:8081 \
     -e SHIELD_API_KEY_FILE=/run/secrets/shield_key \
     -e SHIELD_ICAP_MODE=monitor \
     -e SHIELD_ICAP_ALLOWED_CLIENTS=10.0.0.0/8 \
     --read-only --user 65532 \
     shield-icap
   ```

2. Point the SWG at it. Blue Coat, Cisco WSA, Forcepoint and Netskope each have
   an ICAP service entry: service URL `icap://<host>:1344/screen`, method
   REQMOD, preview 4096, and the vendor's own "on failure" setting aligned with
   `SHIELD_ICAP_FAIL_OPEN`.

3. Scope it to AI destinations in the SWG's own policy, so the adapter never
   sees unrelated traffic. This is a privacy control as much as a performance
   one, and it is the sentence the customer's works council will read.

Deployment is a Helm chart or a compose file; both ship in `deploy/swg/`.

### 9.2 Mode A: no existing SWG (bundled Squid)

For customers with no gateway. Adds a root CA, which is the part that needs
security sign-off.

1. **Bring up the stack.** `docker compose -f docker-compose.swg.yml up -d`
   starts Squid plus the adapter. Squid generates its CA on first boot into a
   mounted volume; the private key never leaves the customer.

2. **Distribute the CA** via MDM or GPO to the system trust store. Firefox
   additionally needs `security.enterprise_roots.enabled=true`. CLI tooling
   needs `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` pushed
   as machine environment variables, or every `python` script on the fleet
   starts failing TLS.

3. **Push the PAC file**, rendered from tenant policy and served by the adapter
   at `http://<host>:8081/proxy.pac`. Windows via GPO or the Chrome
   `ProxySettings` policy, macOS via a `com.apple.SystemConfiguration` payload.
   The PAC routes only AI hosts to the proxy and returns `DIRECT` for everything
   else, so banking, payroll and HR traffic is never decrypted. Squid's
   `ssl_bump peek` then `splice` enforces the same list a second time, before
   decryption, as defense in depth.

4. **Disable QUIC** by policy (`QuicAllowed=false`), or HTTP/3 bypasses the
   proxy entirely.

### 9.3 Verification, both modes

```bash
curl -s http://<host>:8081/healthz
# {"ok":true,"bundle_version":"a1b2...","mode":"monitor","shield_reachable":true}
```

Then a canary: send a benign prompt to an AI host and confirm it appears in
tenant telemetry with the right `destination`. Then send one containing a
deliberately planted fake credential and confirm it is reported as *would have
blocked* while still in monitor mode.

### 9.4 Rollout

Follow [policy-lifecycle](/policy-lifecycle/) exactly: monitor, review what
would have blocked, then `SHIELD_ICAP_MODE=enforce`. Roll enforce to a canary
group in the SWG policy before the whole fleet. An operator who cannot safely
try enforce will stay in monitor forever.

### 9.5 Sizing and HA

Stateless, so run two or more replicas behind whatever the SWG uses to reach
them. Tier 1 evaluation is regex over a body under 1 MiB, so the adapter is
CPU-bound and cheap: start at 2 vCPU per replica and measure. `ISTag` changes on
policy update, which correctly invalidates SWG-side caching.

---

## 10. Task breakdown (one PR each, in order)

| # | PR | Contents |
|---|---|---|
| 1 | ICAP protocol core | `icap/server.py`, OPTIONS + REQMOD + Preview + 204, `Dockerfile.icap`, `requirements-icap.txt`, tests 1, 2, 9, 10, 11. No Shield calls at all. |
| 2 | Prompt extraction | `icap/extract.py` for OpenAI, Anthropic, Google, generic fallback. Test 3. |
| 3 | Tier 1 DLP enforcement | `icap/policy.py`, bundle fetch/cache against `/v1/edge/policy-bundle`, monitor/enforce, the 403 body. Tests 4, 5, 6, 7. |
| 4 | Tier 2 screen + telemetry | `icap/shield.py`, async `/guardrails/input`, sync opt-in, attribution headers. Tests 8, 12. |
| 5 | Squid bundle + operator docs | `docker-compose.swg.yml`, `deploy/swg/squid.conf`, PAC template, preflight command, §9 as customer-facing docs. Integration test. |
| 6 | *(follow-up, separate spec)* | Redaction, `/guardrails/file` multipart, RESPMOD, extension/ICAP telemetry de-duplication. |

PR 1 is independently valuable and independently testable: it is a conformant
ICAP server that answers 204 to everything, which can be wired into a customer's
SWG to prove the integration path before any policy is enforced.

---

## 11. Invariant risk register

| Invariant | Risk | Mitigation |
|---|---|---|
| Off the hot path | The adapter *calls* the guard path but adds nothing to it. It is however inline on the customer's browsing. | Two-tier design; Tier 2 async by default; p99 target 50ms |
| `Dockerfile.admin` allowlist | None. No `admin_app.py` import. | Stated explicitly; nothing to add |
| Declare dependencies | New image with its own requirements file | `requirements-icap.txt`; clean-venv verification of the test path |
| Secure-by-default, non-breaking | Zero change to any existing default | New artifact only; adapter's own default is `monitor` |
| Self-contained PRs | Dockerfile and requirements land in PR 1 with the code that needs them | Enforced in the breakdown above |
| Never develop on main | Feature branch `feat/swg-icap-adapter` | All six PRs on one branch |
