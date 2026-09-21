# Spec: Microsoft Copilot coverage (consumer + Microsoft 365)

Status: **APPROVED, implemented.** Tasks 2–5 are on `feat/swg-rollout` (PR #436):
the query-string logging fix, the SignalR extractor, Tier 2 on the socket, and
the PAC routing with the M365 opt-in (`SHIELD_M365_COPILOT`, off by default).
Decisions §10.2 (build both) and §10.3 (Tier 2 off by default) were taken as
recommended. Outstanding: a consumer-Copilot socket capture (§10.1) to confirm
its field path — the handler is built to the shared SignalR envelope and
verified against a real M365 frame; the consumer path needs one live check.

## 1. Problem & outcome

Prompts typed into Microsoft Copilot reach no screening today, not even Tier 1.
Both variants carry the chat turn over a WebSocket, and `squid.conf` excludes
socket upgrades from ICAP adaptation on purpose (so the AI web apps do not
break). So unlike claude.ai and Gemini, which at least got the regex tier,
Copilot gets nothing.

There are two products, and they are not the same problem:

- **Consumer Copilot** (`copilot.microsoft.com`, personal account). Chat socket
  is on `copilot.microsoft.com` itself, an AI host we already decrypt for its
  REST traffic. Screening it is in scope for the WebSocket spec as written.
- **Microsoft 365 Copilot** (Office/Bizchat, work account). Measured from a real
  session: the page is `copilot.microsoft.com` but the chat socket is
  `wss://substrate.office.com/m365Copilot/Chathub/...`. `substrate.office.com`
  is **not** an AI host. It is Microsoft 365's shared backend and also carries
  Outlook, calendar and people-search APIs. It is not on `DEFAULT_AI_HOSTS`, so
  the gateway never sees the prompt.

**Outcome.** A prompt containing a Tier 1 pattern OR matching a written Tier 2
policy, typed into either Copilot, is blocked before it leaves the endpoint, and
the block is visible in the tenant's telemetry with a destination attached. M365
Copilot coverage is **opt-in and off by default**, because turning it on
decrypts a host that also carries corporate mail.

**Success condition.** With the feature configured, the pricing sentence
("margin 62% ... supplier cost 400 AED") typed into consumer Copilot, and into
M365 Copilot with the opt-in flag set, returns a policy block and never reaches
Microsoft. Verified through the running gateway, as the claude.ai and Gemini
handlers were.

### Non-goals
- Server-to-client screening (the streamed answer). Outbound is the threat;
  this stays request-side, consistent with the WS spec.
- Frame-level redaction. Block or allow a whole message, as today.
- HTTP/2 Extended CONNECT. Copilot uses HTTP/1.1 WebSockets; if that changes it
  is a separate spec.
- Screening non-Copilot `substrate.office.com` traffic (mail, calendar). The
  opposite: §5 requires that this traffic is decrypted-but-never-inspected when
  the opt-in is on, and never decrypted when it is off.
- Purview integration. Named as the alternative control in §5, not built here.

## 2. Plane & latency contract

Data plane, CPU only: the existing `shield-ws` service plus PAC generation. The
admin plane is untouched. No new module is imported by `admin_app.py`, so the
`Dockerfile.admin` allowlist is unaffected.

**Guard path.** `shield-ws` is on the guard path for hosts routed to it.
- **Tier 1 runs in-process per message.** No network call. Budget unchanged from
  the WS spec: under 5 ms added latency per screened message.
- **Tier 2 is the new work.** The WS spec lists `SHIELD_WS_SYNC_SCREEN` in its
  config table (§4) but the code never reads it: `ws_screen.decide()` calls only
  `evaluate(bundle, ...)`, the local regexes. So the pricing sentence would pass
  even with routing in place. This spec implements that flag. It stays **off by
  default** for the same measured reason the ICAP path keeps it off: a chat page
  issues many requests, each Tier 2 call is a 0.4–4 s round trip, and on a
  long-lived socket a queue of them behind `bypass=off` is what collapsed the
  gateway under a retry storm (WS spec §2). Tier 2 on the socket is for the
  operator who has accepted that, per host.

Nothing here touches `/guardrails/*`, `cap/mint` or `tools/call`. The only new
outbound call is the same `/guardrails/input` the ICAP adapter already makes,
and only when `SHIELD_WS_SYNC_SCREEN=1`.

## 3. Data model

No Redis, no new persistent state. `shield-ws` holds the same in-memory
`PolicyCache` it holds today, refreshed on the same timer, scoped to the one
tenant the appliance's API key resolves to. Cross-tenant isolation is unchanged:
one appliance, one key, one tenant.

The SignalR extractor is pure: bytes in, `Extracted` out, no state.

## 4. API / interface

No HTTP surface changes. The interface is the message parser and two config
flags.

### SignalR frame format (measured)

M365 Copilot speaks SignalR's JSON hub protocol: one or more JSON objects, each
terminated by a `0x1E` record separator. The turn is the object with
`type == 4` (StreamItem/Invocation), at:

    arguments[0].message.text          # author == "user"

with `messageType == "Chat"`. The same object carries `optionsSets`, `sliceIds`,
tool lists and a client-info block; none of that is the turn.

Consumer Copilot's socket shape is **not yet captured** (this spec was written
from an M365 capture; the consumer socket needs its own sample before its
handler is written — see §10.1). The extractor is built to the SignalR envelope,
which both share; the field path is confirmed per variant against a real frame.

### New extractor entry (`icap/extract.py`)

A `_copilot_signalr(body, host, path, max_chars)` handler, in the
`_WEB_APP_TURNS` tuple beside `_claude_rpc` and `_gemini_web`. It:
1. Splits the body on `0x1E`.
2. Parses each record as JSON; ignores any that do not parse.
3. Takes `arguments[0].message.text` from the `type==4` record whose
   `message.author == "user"`.
4. Returns `last_user` = that text; `text` = that text plus the decoded body for
   Tier 1; `provider = "copilot"`; `parsed = True`. Returns `None` (fall to the
   generic path) on any structural mismatch, so a format change degrades to raw
   rather than a wrong confident answer — the same contract as the other two.

Routing selects this handler by host (`copilot.microsoft.com`,
`substrate.office.com`) AND path suffix (`/chathub` / `/chat`), so a mail API
call to `substrate.office.com` is never fed to it.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SHIELD_WS_HOSTS` | empty | Hosts the PAC routes to `shield-ws` (WS spec, task 5). Consumer Copilot goes here. |
| `SHIELD_WS_SYNC_SCREEN` | `0` | Tier 2 per socket message. New; read §2. |
| `SHIELD_M365_COPILOT` | `0` | **The opt-in.** `1` adds `substrate.office.com` to the bump list AND to `SHIELD_WS_HOSTS`, scoped to `/m365Copilot/` paths for inspection. Off means substrate is never decrypted. |

## 5. Security & backward compatibility

**Default behavior unchanged.** Every flag defaults off. With nothing set, the
gateway behaves exactly as it does today: consumer Copilot unscreened (a
documented gap, per the WS spec's §4 table), M365 Copilot untouched,
`substrate.office.com` spliced (never decrypted). This satisfies the
secure-by-default-but-non-breaking invariant: the new coverage is opt-in and the
escape hatch is "leave the flag unset."

**The substrate decryption trade-off, stated.** `SHIELD_M365_COPILOT=1`
decrypts `substrate.office.com`. Squid selects what to bump by SNI, before it
can see a path, so there is no way to decrypt the Copilot socket without
decrypting the host — which also carries the user's Outlook and calendar API
traffic. The mitigations, all required for the flag to ship:
1. **Inspection is path-scoped.** `adaptation_access` / the WS host match send
   only `/m365Copilot/` (and the chat socket) to the screener. Mail, calendar
   and people-search paths are decrypted but returned unmodified and **not**
   sent to the adapter or `shield-ws`.
2. **Query strings are never logged** (fixed already; the substrate socket URL
   is exactly why).
3. **The bump is opt-in and documented** as decrypting a mail-bearing host, so a
   works-council conversation happens before it is switched on, not after.
4. **Purview is named as the alternative.** Microsoft's own Purview DLP for M365
   Copilot evaluates inside the tenant with no interception; the captured token
   even carried `DataLossPreventionPolicy.Evaluate`. For customers who will not
   decrypt substrate, that is the right tool, and the gateway covers the rest.

**Authz.** No new caller surface. `shield-ws` is bound to the tailnet interface
only (edge installer, UFW). A malicious LAN client can reach the proxy but not
the tenant key (Docker secret) or the CA private key (0600, generated on the
box).

**Token hygiene.** The substrate socket URL carries a live Entra bearer token in
its query. §2's logging fix keeps it out of logs; the token is in the URL, never
in a body the extractor reads, so it is never sent to `/guardrails/input`
either. A test asserts the extractor's `last_user` and `text` never contain an
`access_token` value even when one is present in a crafted frame.

## 6. Packaging & deploy

- **No new pip dependency.** SignalR parsing is `bytes.split(b"\x1e")` plus the
  stdlib `json` the extractor already uses. No `signalr` client library.
- **No new admin import**, so `Dockerfile.admin` is untouched. `Dockerfile.icap`
  and `Dockerfile.wsproxy` already `COPY icap/`, so the new handler ships with
  no Dockerfile change (regression-guarded by
  `test_admin_dockerfile_imports.py` and the WS image test).
- **Images to rebuild:** `shield-ws` (extractor + Tier 2), and `shield-icap`
  only if consumer Copilot REST also needs the handler (TBD from the consumer
  capture). `squid.conf` changes for the M365 opt-in ship in the same PR as the
  flag that gates them (self-contained-PR invariant).
- **Rollout:** ships behind the flags above. A tenant turns on consumer Copilot
  by adding it to `SHIELD_WS_HOSTS`; M365 by setting `SHIELD_M365_COPILOT=1`
  after the works-council step.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Body is not SignalR (no `0x1E`, not JSON) | handler returns None, generic path runs, Tier 1 on raw text, Tier 2 skipped, `parsed=False`, counted |
| `type==4` record present but no user `message.text` | None; a control frame is not a turn |
| Multiple JSON records in one buffer (turn + Metrics) | split on `0x1E`, screen the turn record, ignore the rest |
| Message split across frames | existing `MessageAssembler` reassembles before `decide()`; cap `SHIELD_WS_MAX_MESSAGE` applies |
| Binary / compressed frame | existing skip (`ws_binary` / `ws_compressed`), unchanged |
| `substrate.office.com` mail API call while opt-in on | decrypted, NOT inspected, NOT logged beyond redacted path, forwarded unchanged |
| Tier 2 enabled, `/guardrails/input` slow or 5xx | `SHIELD_WS_FAIL_OPEN` decides, same as the sync ICAP path. A timeout is not an approval. |
| Tier 2 disabled (default) | Tier 1 only; the pricing sentence passes on the socket, and this is documented, not silent |
| Format change (Microsoft renames the hub method or moves `text`) | `provider=raw parsed=False` reappears on the Copilot path — the drift tripwire, same as claude.ai/Gemini. Worth an operator alert. |
| Bundle empty / cold start | skip, `ws_empty_policy`, unchanged |

**Fail-open vs fail-closed:** unchanged from the WS spec. Fail-open on
availability (a `shield-ws` error never wedges browsing unless the operator set
`SHIELD_WS_FAIL_OPEN=0` AND routed the host), fail-closed on a matched Tier 1
pattern (needs no network).

## 8. Test plan (Definition of Done)

Unit (`tests/test_icap_extract.py`), against a **structural twin** with fake
tokens — the real capture is never committed (it carried a live bearer token):
- SignalR turn extracted from a `type==4` user message → `last_user` is the
  typed text, `provider="copilot"`, `parsed=True`.
- Multi-record buffer (turn + a `type==1` Metrics frame) → only the turn.
- An `access_token`/JWT placed in the frame → never appears in `last_user` or
  `text`.
- Every §7 malformed case → `parsed=False`, never raises.
- Not claimed on a non-Copilot host.

Tier 2 (`tests/test_icap_shield.py` pattern, adapted for the WS decide path):
- With sync on, the Copilot turn reaches `/guardrails/input` as the typed text
  alone; no options/tool/token data in the payload.
- With sync off (default), Tier 2 is not called; Tier 1 still runs.

Routing / config:
- `SHIELD_M365_COPILOT=1` puts `substrate.office.com` in the PAC's WS host set
  and the bump list; `=0` leaves it spliced. A test holds the PAC output and the
  Squid ACL in agreement, as `test_icap_deploy.py` already does for the AI list.
- `redact_path` covers the substrate socket URL (added with the §2 fix).

Regression guards: WS image still builds with the handler; the two-list
agreement test extends to the substrate entry.

Full suite green in a clean venv; CI `pytest` gate passes. Live verification
through the running gateway for both variants, as done for claude.ai and Gemini.

## 9. Task breakdown (one PR each, in order)

On `feat/swg-rollout` (this workstream is already one branch, per the single-
branch decision), a commit per task:

1. **This spec.**
2. **Logging leak** — done, committed (`redact_path`). Listed here because it is
   the prerequisite that makes routing a Microsoft socket safe.
3. **Tier 2 on the socket** — `ws_screen.decide()` learns
   `SHIELD_WS_SYNC_SCREEN`; the pipeline calls `/guardrails/input` for the
   assembled turn. Unit + live test with consumer Copilot once captured.
4. **SignalR extractor** — `_copilot_signalr` in `_WEB_APP_TURNS`; the tests in
   §8. Consumer Copilot capture obtained and its field path confirmed.
5. **M365 opt-in** — `SHIELD_M365_COPILOT` gates the substrate bump and WS
   routing, path-scoped; PAC + Squid agreement test; docs with the works-council
   note and the Purview alternative.

## 10. Decisions needed before implementation

1. **Consumer Copilot capture.** This spec was written from an M365 frame. The
   consumer socket (`copilot.microsoft.com`) needs its own sample to confirm its
   field path before task 4. Cheap to get; needed before that PR, not this spec.
2. **Is M365 Copilot in scope at all for v1, or consumer-only first?**
   Recommendation: build tasks 3–4 (consumer + Tier 2) first, ship task 5 (the
   substrate opt-in) behind its flag once a customer actually asks. The hard part
   is the decryption policy conversation, not the code.
3. **Tier 2 on the socket by default?** Recommendation: **no**, off by default,
   matching the ICAP path and the WS spec's measured latency warning.
4. **substrate opt-in granularity:** whole host bumped with path-scoped
   inspection (recommended, only feasible option given SNI-time selection), vs
   any attempt to bump by path (not possible — Squid chooses at SNI).
