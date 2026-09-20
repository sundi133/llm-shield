---
title: "Spec: WebSocket inspection"
layout: default
nav_order: 69
permalink: /spec-websocket-inspection/
description: "WebSocket-native AI clients break through the Mode A gateway today and their prompts are never screened. Terminate the upgrade in a WebSocket-aware proxy, screen client-to-server messages with the existing policy, and make the uninspected path explicit where it is not deployed."
---

# Spec: WebSocket inspection

Status: DRAFT, awaiting approval. No feature code written.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

### What happens today

Codex CLI 0.155.1 does not use REST. It opens a WebSocket to
`wss://chatgpt.com/backend-api/codex/responses` and the prompt travels inside
it. Run through the Mode A gateway on 2026-09-20:

```
ERROR codex_api::endpoint::responses_websocket: failed to connect to websocket:
      HTTP error: 405 Method Not Allowed, url: wss://chatgpt.com/backend-api/codex/responses
ERROR: Reconnecting... 2/5
```

and in the adapter log, for the same request:

```
icap txn=18f8892c decision=skip host=chatgpt.com method=GET
     path=/backend-api/codex/responses reason=no_body
icap txn=9dabb388 decision=allow host=chatgpt.com method=POST
     path=/backend-api/codex/analytics-events/events provider=json parsed=False
```

**The only Codex traffic we screened was its analytics.** The prompt was never
visible, and the client broke.

### Why, measured rather than assumed

| Test | Result |
|---|---|
| Handshake direct, HTTP/2 | `405` (WebSocket over h2 needs Extended CONNECT) |
| Handshake direct, forced HTTP/1.1 | **`401`** so the endpoint is healthy and just wants auth |
| Handshake through bumped Squid | `405` (the origin sees a plain GET: `Upgrade`/`Connection` are hop-by-hop and are not forwarded) |
| Same, with upgrades excluded from ICAP adaptation | **still `405`**, so ICAP is not the cause |
| Handshake to a clean WebSocket endpoint through bumped Squid | **`502` from Squid itself** |

`squid.conf` already sets `http_upgrade_request_protocols websocket allow`, added
when ChatGPT's UI broke. That is not sufficient on a bumped connection in Squid
5.7. **This cannot be fixed by configuration**, and ICAP cannot help either:
RFC 3507 adapts HTTP messages, and after a `101` the connection is an opaque
byte tunnel with no callout.

So there are two defects, not one:

1. **Clients break.** A user sees a broken tool and a 405, not a policy message,
   and the audit trail says `skip`, which reads as a network fault.
2. **Prompts are invisible.** Any provider that moves its conversation into a
   socket leaves the DLP path silently, with no error and no log line.

### Outcome

A WebSocket-aware interception path that terminates the upgrade, screens
client-to-server messages against the same tenant policy the ICAP path uses,
forwards what passes, and logs decisions in the existing format. Where it is not
deployed, the behavior becomes an explicit, readable refusal instead of a 405.

Observable success conditions:

1. `codex exec "our margin on this handbag is 62% and the supplier cost is 400
   AED, draft a partner email"` through the gateway is **refused with the policy
   message**, and the log carries `transport=ws decision=block rule=...`.
2. The same request without those figures **completes normally**, with the
   session usable afterwards.
3. With the feature off, a WebSocket client gets a readable refusal naming the
   policy, never a 405.
4. REST screening is byte-for-byte unchanged (existing tests stay green).
5. No prompt text appears in any log.

### Non-goals

- **Server-to-client screening.** The streamed answer is far more data and the
  threat is outbound. Output DLP over WebSockets is a later spec.
- **Frame-level redaction.** v1 blocks or forwards, matching the ICAP path,
  which cannot redact either.
- **HTTP/2 Extended CONNECT** WebSockets (RFC 8441). Clients observed so far
  use HTTP/1.1 upgrades; h2 is a follow-up.
- **Replacing Squid** for non-AI hosts. Splice-before-decrypt stays where it is.
- **Mode B.** When a customer runs Zscaler or Netskope, their gateway owns the
  WebSocket and we receive whatever it hands us.

## 2. Plane & latency contract

**Data plane, CPU only.** A new service, `shield-ws`, alongside Squid and the
ICAP adapter. The admin plane is untouched.

**It is on the guard path** for the hosts routed to it, so:

- **Tier 1 (bundle patterns) runs in-process per message.** No network call.
- **Tier 2 (the guardrail pipeline) is off by default on this path.** Measured
  on 2026-09-20: with sync screening on, browser traffic to an AI host issues
  dozens of requests per page and each waits 0.4 to 4 s on a remote verdict.
  With `bypass=off` upstream they queue, time out, and the client retries; the
  gateway collapsed under its own retry storm (190k connection attempts, host
  ephemeral ports exhausted). A long-lived socket makes this worse, not better.
  Operators may enable it with `SHIELD_WS_SYNC_SCREEN=1` after reading that.
- **Budget: under 5 ms of added latency per screened message** at Tier 1,
  asserted by a test that screens a 64 KB message with the transport stubbed.

Nothing here touches `/guardrails/*`, `cap/mint` or `tools/call`.

## 3. Data model

**No Redis keys, no new persistence.** Policy comes from the bundle the adapter
already fetches (`/v1/edge/policy-bundle`) with the same tenant key, and
verdicts from the same `icap/policy.py`.

### Log line

The existing shape, plus WebSocket fields, so one grep covers both transports:

```
icap txn=<uuid> transport=ws decision=block host=chatgpt.com
     path=/backend-api/codex/responses opcode=text frames=3 msg_bytes=412
     provider=openai parsed=True rule=custom_policy_input
```

`decision` keeps its existing values (`allow`, `block`, `would_block`, `skip`).
New `skip` reasons: `ws_binary`, `ws_oversize`, `ws_compressed`, `ws_unparsed`.

### Close frame

A block ends the socket with a policy close code and a reason the client can
surface:

| Field | Value |
|---|---|
| Code | `4403` (private-use range, chosen to mirror HTTP 403) |
| Reason | `Blocked by your organization's AI policy: <rule> (ref <txn>)` |

**RFC 6455 caps the close reason at 123 bytes**, so the reason is built
reference-first and truncated on a character boundary, never mid-UTF-8.

## 4. API / interface

### New service

`shield-ws`, built on **mitmproxy** with a Shield addon. mitmproxy already
handles CONNECT, certificate generation, HTTP/2, and WebSocket framing
including `permessage-deflate`, and exposes `websocket_message` hooks. Writing
a TLS-intercepting proxy from scratch is a quarter of work for the same result.

| | |
|---|---|
| Listens | `SHIELD_WS_PORT`, default 3129 |
| Health | `SHIELD_WS_HEALTH_PORT`, default 8082, `/healthz` mirroring the adapter's fields plus `ws_sessions`, `ws_messages_screened`, `ws_blocked` |
| CA | the **same** `ca.pem` Squid uses (certificate and key in one file, which is also mitmproxy's format) |
| Admin UI | disabled (`--no-web`), no listener beyond the proxy and health ports |

### Routing

The PAC sends the hosts in `SHIELD_WS_HOSTS` to `shield-ws` and everything else
as it does today. A host routed there gets **both** its REST and its WebSocket
traffic screened by that service, because a PAC selects by host and cannot split
by path. That keeps one proxy per host rather than a rule nobody can reason
about.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SHIELD_WS_ENABLED` | `0` | Master switch. Off means nothing changes |
| `SHIELD_WS_HOSTS` | empty | Hosts routed to `shield-ws`; empty means none |
| `SHIELD_WS_MODE` | `monitor` | `monitor` logs `would_block`; `enforce` closes the socket |
| `SHIELD_WS_SYNC_SCREEN` | `0` | Tier 2 per message. Read §2 first |
| `SHIELD_WS_MAX_MESSAGE` | `1048576` | Assembly cap, matching `SHIELD_ICAP_MAX_BODY` |
| `SHIELD_WS_STRIP_COMPRESSION` | `1` | Remove `Sec-WebSocket-Extensions` at handshake |
| `SHIELD_WS_FAIL_OPEN` | `0` | What an addon error does (see §7) |

### Where the feature is absent

`squid.conf` changes from `http_upgrade_request_protocols websocket allow` to a
**deny with a readable page** (`deny_info`), so a WebSocket client is refused by
policy instead of receiving a 405 from the origin. Operators who prefer working
clients over screened ones set it back to `allow` and accept the gap, documented
in the deployment guide.

## 5. Security & backward compatibility

**Opt-in and non-breaking.** With `SHIELD_WS_ENABLED=0` (the default), no
container starts, the PAC is unchanged, and the ICAP path behaves exactly as it
does today.

**Stripping `permessage-deflate` is deliberate.** Compressed frames with context
takeover are only decodable in sequence with retained state; screening them
means reimplementing that state machine in both directions. Removing the
extension at handshake costs bandwidth and nothing else, and the alternative is
a class of bugs that surfaces as "the policy stopped matching on long
conversations".

**Blocking closes the socket; it never injects content.** Injecting a
provider-shaped error frame gives a better message and requires per-provider
knowledge that breaks when they change their protocol. A later task may add it
for the top providers behind a flag.

| Threat | Mitigation |
|---|---|
| A new interception point weakens TLS | Same CA, same trust decision as Squid. No new root |
| mitmproxy's admin surface | `--no-web`; only the proxy and health ports listen; non-root |
| Prompt text in logs | Same rule as the adapter: destination, rule, reference, counts. A test greps for a planted string |
| A client negotiating compression anyway | Treated as unreadable and counted, never silently forwarded as "clean" |
| Policy source unavailable | Same fail-closed posture as the adapter, reusing its bundle cache |

## 6. Packaging & deploy

- **New image** `Dockerfile.wsproxy` and a compose service. `requirements-ws.txt`
  pins mitmproxy; it is **not** added to `requirements.txt`, because the data
  plane and admin plane must not grow it.
- **CI:** unit tests import the addon's pure functions (assembly, extraction,
  decision, close-frame construction) with mitmproxy **stubbed**, so
  `requirements-test.txt` gains nothing. The live test is marked and skipped
  unless `SHIELD_WS_TEST=1`.
- **`Dockerfile.admin` is unaffected**: `admin_app.py` imports nothing new.
- **PAC generation** (`icap/pac.py`) learns `SHIELD_WS_HOSTS`, so the browser is
  told where to send them.
- **Images to rebuild:** the new `shield-ws` only; Squid is rebuilt for the
  `deny_info` page.

## 7. Failure modes & edge cases

| Case | Behavior | Fail mode |
|---|---|---|
| `SHIELD_WS_ENABLED=0` | No service, no PAC entry, no change | n/a |
| `shield-ws` down, hosts routed to it | Those hosts unreachable. In `enforce` the PAC has no `DIRECT` fallback, so this is fail-closed and total for those hosts | closed, loud |
| Addon raises on a message | `SHIELD_WS_FAIL_OPEN=0`: close the socket, count it. `=1`: forward and count | configurable |
| Message exceeds the cap | The retained prefix **is screened** and the decision carries `truncated=true`, matching how the ICAP path treats a capped body. Skipping it would make a large paste the safest way to leak | closed on a match, counted |
| Binary frame (protobuf, audio) | `skip reason=ws_binary`, forwarded, counted. **v1 cannot read these** | open, counted |
| Client negotiates compression despite the strip | `skip reason=ws_compressed`, forwarded, counted | open, counted |
| Fragmented message | Assembled to `FIN` before screening, within the cap | n/a |
| Shape the extractor does not know | Falls back to string leaves, Tier 1 still runs, Tier 2 skipped, `parsed=False` | open, counted |
| Close reason longer than 123 bytes | Truncated on a character boundary, reference kept | n/a |
| Origin speaks h2 and offers Extended CONNECT | Out of scope; the client falls back to h1 or is refused with a readable message | closed, loud |
| Very long-lived session | Screening is per message, so memory is bounded by the assembly cap, not the session | n/a |

## 8. Test plan (Definition of Done)

**Unit, mitmproxy stubbed** (`tests/test_ws_screen.py`)
- Fragmented text message assembled correctly; cap enforced mid-assembly.
- Extraction from the Codex and ChatGPT socket shapes; unknown shape degrades to leaves.
- Tier 1 block on the bundle's patterns; allow on clean text.
- `monitor` logs `would_block` and forwards; `enforce` closes.
- Close frame: code 4403, reason under 123 bytes, reference present, valid UTF-8 after truncation.
- Binary, oversize and compressed frames produce the documented `skip` reasons and forward.
- Addon exception honors `SHIELD_WS_FAIL_OPEN` both ways.
- Prompt text never reaches the log line (grep a planted string).
- Latency budget: 64 KB message screened in under 5 ms with the transport stubbed.

**Integration, marked, skipped unless `SHIELD_WS_TEST=1`**
- A local WebSocket echo server behind `shield-ws`: clean message passes, DLP
  message closes with 4403, session usable before the block.
- PAC output contains the WS hosts.

**Acceptance (manual, recorded in the PR)**
- `codex exec` with the margin sentence is refused with the policy message.
- The same sentence without figures completes.
- REST screening unchanged: `deploy/swg/dev/local-e2e.sh` stays green.

**Done means:** full suite green in a clean venv, the CI `pytest` gate passing,
and the acceptance run recorded. Main's gate is currently red on
`test_at_least_one_tenant_scoped_route_is_discovered`, which predates this work.

## 9. Task breakdown

One branch, `feat/websocket-inspection`, a commit per task.

1. **Spec.** This document.
2. **Make the gap explicit.** `squid.conf` denies upgrades with a `deny_info`
   page naming the policy; deployment guide gains a section explaining the
   trade-off and how to revert. Small, shippable on its own, and it turns
   today's mystery 405 into a policy message.
3. **`shield-ws` skeleton.** Image, compose service, health endpoint, shared CA,
   pass-through only. Test: a WebSocket session works end to end through it.
4. **Screening.** Assembly, extraction, Tier 1, monitor and enforce, close on
   block, logging, counters. The unit tests above.
5. **Routing and docs.** PAC learns `SHIELD_WS_HOSTS`; operator documentation;
   the Codex acceptance run.

**Flagged, not in this branch:** server-to-client screening, provider-shaped
error injection, HTTP/2 Extended CONNECT, frame-level redaction.

## 10. Decisions needed before implementation

1. **Which hosts route to `shield-ws`?** An explicit list (`SHIELD_WS_HOSTS`,
   recommended) or every inspected AI host once the service is enabled.
2. **Addon error behavior:** fail closed (recommended, matches the adapter) or
   fail open.
3. **Block semantics in v1:** close-only (recommended) or provider-shaped error
   injection for chatgpt.com from the start.
4. **Phase 2 posture where `shield-ws` is not deployed:** deny upgrades with a
   readable message (recommended) or keep allowing them and document that those
   prompts are unscreened.
