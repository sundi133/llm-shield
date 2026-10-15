---
title: "Spec: Device DLP at fleet scale"
layout: default
nav_exclude: true
permalink: /specs/device-fleet-scale/
description: Keep device enrollment, the device list and the Device DLP portal page fast and usable at thousands of laptops, by indexing devices instead of reading the whole fleet on every enrollment and every page view.
---

# Spec: Device DLP at fleet scale

> Status: **APPROVED 2026-10-15.** Branch `device-fleet-scale`.
> Task 1 (serial index) built: `core/dlp/device_index.py`, `enroll()` and
> `revoke()` in `core/dlp/devices.py`, `tests/test_device_fleet_scale.py`.
> Builds on: `docs/specs/device-dlp-agent.md` (enrollment, heartbeat, revoke,
> §5.2 and §6) and `docs/specs/device-rollout-kit.md` (kits, inventory).

## 1. Problem & outcome

Device DLP stores every laptop in two Redis hashes per tenant:
`devices:{tenant_id}` (identity) and `device_seen:{tenant_id}` (last
heartbeat). Three code paths read **both hashes in full**:

| Path | Where | Cost today | When it hurts |
|---|---|---|---|
| Enrollment, live-serial check | `core/dlp/devices.py` `enroll()` (the loop over `_hgetall(devices)`) | 2 × HGETALL of the whole fleet **per enrollment** | A rollout: N laptops enrolling in the same window cost O(N²) Redis traffic. 5,000 laptops is 5,000 full-fleet reads, each a large Upstash REST response |
| Device list | `list_devices()`, `GET /v1/tenant/me/devices` | 2 × HGETALL, sort, every row with its counters in one response | Every portal page view. Roughly 1 MB at 1,000 devices, several MB at 10,000, close to Upstash's per-response size cap |
| Portal table | `static/tenant.html` `ddDevices()` | Renders every row; no search, filter or paging | Finding the stale laptops in one fleet means scrolling the whole estate |

Two smaller readers do the same full read only to turn a device id into a
hostname: `api/routes_hooks_portal.py` `claude_code_overview` and the OS
events summary.

**Outcome.** At 10,000 devices per tenant:

1. An enrollment costs a fixed, small number of Redis commands, independent
   of fleet size.
2. A device-list request returns one page (at most 500 rows) and a summary,
   with Redis work proportional to the page, not the fleet.
3. An operator can, in the portal, see totals by fleet and state, jump to
   the stale laptops of one fleet, and search by hostname, without loading
   the whole fleet.

Observable success: a test with 10,000 enrolled devices shows enrollment and
a 50-row page each issue a bounded number of Redis commands (asserted by a
counting fake), and the portal's Devices tab paints one page.

**Non-goals.**
- The fleet overview in `routes_hooks_portal.py` (`_fleet_rows`: laptops per
  fleet by hook state and OS-events state) still reads every device. It is a
  per-fleet aggregate over per-device fields; indexing it is a follow-up spec
  if it shows up as slow. Stated here so nobody assumes it is covered.
- Changing what a heartbeat carries, how often agents send it (every 300 s),
  or anything on the laptop. The agent is untouched.
- Full-text or substring hostname search. Search is a case-insensitive
  **prefix** match, which is what an index can serve cheaply.
- Exporting the device list (CSV). Possible later on top of the paged API.

## 2. Plane & latency contract

- **Planes.** The device routes live in `api/routes_devices.py`.
  `router` (`/v1/devices/*`: enroll, heartbeat, CA) is mounted only on the
  **data plane** (`core/app.py`). `tenant_router` (`/v1/tenant/me/devices/*`)
  is mounted on **both** the data plane and the **admin plane**
  (`admin_app.py`); the portal calls the admin plane. Both planes change.
- **Guard path.** None of these touch `/guardrails/*`, `cap/mint` or
  `tools/call`. Enrollment and heartbeat are device-key endpoints called once
  at install and every 300 s. **Off hot path, no guarded-traffic impact.**
- **The one hot-adjacent reader is unchanged.** The Claude Code hook route
  resolves its caller with `caller_device()`, which does a single
  `HGET devices:{tenant_id}`. This spec does not change that function.
- **Heartbeat cost goes up slightly.** Today one HSET. After: one HGET of the
  previous heartbeat (to detect a state change), the HSET, one ZADD, and on a
  state change only, two set moves and two counter updates. At 10,000
  devices and one heartbeat per 300 s that is about 33 heartbeats per second
  per tenant, each a handful of commands. Acceptable; no request waits on it
  except the agent's own sync, which is asynchronous on the laptop.

## 3. Data model

New keys, all tenant-scoped by `{tenant_id}` in the key name, exactly like
the existing `devices:` and `device_seen:` hashes. Index entries have no TTL:
they live as long as the device records they index, and revoke removes them.
Only the version key expires (below).

| Key | Type | Member / field → value | Written by | Read by |
|---|---|---|---|---|
| `device_serial:{tenant_id}` | HASH | `{fleet}\|{serial_hash}` → `device_id` | enroll, revoke | enroll (live-serial check) |
| `device_names:{tenant_id}` | ZSET, score 0 (lexical) | `{hostname_lower}\x00{device_id}` | enroll, revoke | paged list, prefix search |
| `device_names:{tenant_id}:{fleet}` | ZSET, score 0 (lexical) | same member | enroll, revoke | paged list filtered by fleet |
| `device_last:{tenant_id}` | ZSET | `device_id`, score = last heartbeat, or `enrolled_at` until the first one | enroll, heartbeat, revoke | stale count (ZCOUNT), stale-only list |
| `device_state:{tenant_id}:{state}` | SET | `device_id` | enroll (`never_seen`), heartbeat on a state change, revoke | list filtered by state |
| `device_counts:{tenant_id}` | HASH | `fleet:{fleet}` and `state:{state}` → integer | enroll, heartbeat on a state change, revoke (HINCRBY) | summary |
| `device_index_v:{tenant_id}` | STRING, expires after `REFRESH_S` (1 h) | index version, `1` | the rebuild | every indexed read (is the index present and fresh?) |
| `device_index_lock:{tenant_id}` | STRING, `SET NX EX 60` | `1` | the rebuild | the rebuild (one at a time) |

Notes:
- **Why a lexical ZSET for names.** `ZRANGEBYLEX` gives hostname order,
  prefix search (`[{q}` to `[{q}\xff`) and a stable cursor (the last member
  returned) in one structure. Appending `\x00{device_id}` keeps two laptops
  with the same hostname distinct.
- **Hostnames only change at enrollment.** A re-enrollment that replaces a
  device (same serial, same fleet) reuses the `device_id`; the index update
  removes the old name member and adds the new one.
- **States** are the existing `STATES` in `core/dlp/devices.py` plus
  `never_seen` (what `list_devices` already reports before the first
  heartbeat). The heartbeat's `state` field is already validated against
  `STATES`.
- **`device_counts` can drift** if a process dies between commands. The
  summary therefore takes the device total from `HLEN devices:{tenant_id}`
  (exact, O(1)) and the stale count from `ZCOUNT device_last` (exact). Only
  the per-fleet and per-state breakdowns come from counters, and the rebuild
  (below) resets them.

**Building the index for existing tenants (no migration step).** On the
first indexed read or enrollment for a tenant, if `device_index_v:{tenant_id}`
is absent, Shield rebuilds every index above from one full read of the two
existing hashes, under a short lock (`SET device_index_lock:{tenant_id} NX
EX 60`). Until the rebuild finishes, callers use today's full-scan code, so
results are never wrong, only as slow as today. A tenant with no devices
builds an empty index instantly.

**Hourly refresh (built in task 1).** The version key expires after
`REFRESH_S` (1 hour). The next enrollment after that rebuilds the serial index
under the lock, which picks up any device written without it: one enrolled by
an older data-plane worker during a rolling deploy, or one whose enrollment
crashed between its two writes. That costs one full read per tenant per hour,
against one per enrollment before. A rebuild only adds entries, or replaces
an entry whose device is gone; it never overwrites an entry naming a device
that exists, so it cannot race an enrollment back to an older device. Where
an older Shield left two devices with one serial in one fleet, the one heard
from most recently is indexed.

**The serial index is a hint, not the authority.** A hit is checked against
the device record (same serial, same fleet) before it is used; a hit naming a
device that is gone falls back to the full read for that enrollment. A miss
only ever leads to enrolling a **new** device, never to replacing one. So a
missing entry can at worst let one duplicate-serial enrollment through without
the refusal and alert, until the next refresh; it can never knock a live
laptop off the fleet.

**Drift check (task 2).** An indexed list compares `HLEN devices:{tenant_id}` with
`ZCARD device_names:{tenant_id}`. If they differ, it serves this request
from the full scan and triggers a rebuild. An operator can also force one
(§4).

## 4. API / interface

All endpoints keep their current auth: tenant `X-API-Key` (portal session
on the admin plane), and writes go through `require_registry_write`.

**`GET /v1/tenant/me/devices`** (both planes), extended:

| Query parameter | Meaning |
|---|---|
| `limit` | 1 to 500. **When absent, the response is exactly today's** (every device, same shape). Present: paged mode |
| `cursor` | Opaque, from the previous page's `next_cursor` |
| `fleet` | Only this fleet |
| `state` | Only this state (`ok`, `never_seen`, `model_unavailable`, ...) |
| `stale` | `true`: only devices with no heartbeat for `stale_after_s` |
| `q` | Hostname prefix, case-insensitive, at most 64 characters |

Paged response:

```json
{
  "tenant_id": "acme",
  "summary": {"devices": 9812, "stale": 41, "stale_after_s": 3600,
              "by_fleet": {"sales": 4100, "eng": 5712},
              "by_state": {"ok": 9650, "never_seen": 120, "model_unavailable": 42}},
  "devices": [ ...rows, same shape as today... ],
  "next_cursor": "..." ,
  "filtered": {"fleet": "sales", "stale": true}
}
```

- `summary` is always for the whole tenant, not the filter, so the cards in
  the portal stay stable while you filter.
- Which index drives a page: `stale=true` walks `device_last` (oldest
  first, which is the order an operator wants for stale laptops); else
  `state` walks `device_state:{state}`; else names, per fleet when `fleet`
  is given. The remaining filters are applied to the page's rows.
- **A page may hold fewer than `limit` rows** when filters are combined
  (for example `state` and `q`); `next_cursor` is still returned until the
  walk ends. The portal handles this. Each request reads at most
  `4 × limit` index entries before returning, so a sparse filter can never
  turn one request into a fleet scan.
- Rows are fetched with `HMGET` on both hashes for just the page's
  device ids.
- 400 for an unknown parameter value (`limit` out of range, `state` not a
  known state, `cursor` not one this endpoint issued).

**`POST /v1/tenant/me/devices/reindex`** (both planes, registry write):
rebuilds every index for the tenant from the two hashes. Returns
`{"devices": n, "took_ms": t}`. Audited as `tenant_reindex_devices`. For
operators after a suspected drift and for the runbook.

**Unchanged:** `POST /v1/devices/enroll`, `POST /v1/devices/heartbeat`,
`DELETE /v1/tenant/me/devices/{device_id}` keep their request and response
shapes; only their internals maintain the indexes.

**`api/routes_hooks_portal.py`:** the two hostname lookups switch from
`_hgetall(devices)` to an `HMGET` of only the device ids in the rows being
returned.

**Portal (`static/tenant.html`, Device DLP page):**
- Three tabs: **Devices** · **Enrollment** (tokens, rollout kits, company
  inventory, MDM settings) · **Policy**. A tab loads its data when first
  opened, instead of `ddLoad()` loading every section at once.
- Devices tab: summary cards (total, stale, then one per fleet and one per
  non-`ok` state). Clicking a card sets that filter. A hostname search box
  (prefix, debounced 300 ms), a **Stale only** toggle, a fleet selector, a
  page of 50 rows with **Next** and **Previous** (the portal keeps the stack
  of cursors), and the existing per-row Revoke.
- The table keeps today's columns.

## 5. Security & backward compatibility

- **Non-breaking by construction.** `GET /v1/tenant/me/devices` without
  `limit` returns today's response. Enroll, heartbeat and revoke keep their
  contracts. Existing callers (tests, `routes_hooks_portal._fleet_rows`, any
  customer script) see no change.
- **No behavior-changing default**, so no escape-hatch flag is needed for
  correctness. One operational flag, for safety during rollout:
  `SHIELD_DEVICE_INDEX=off` makes every path use today's full-scan code and
  stops maintaining indexes. A later `on` triggers a rebuild (the version
  key is cleared when indexing is turned off). Default `on`.
- **Live-serial protection must not weaken.** Today's check refuses an
  enrollment that claims the serial of a device heard from in the last 24 h,
  and raises an alert. With the index, the lookup is `HGET
  device_serial:{tenant_id} {fleet}|{serial_hash}` followed by the same
  liveness test on that one device. If the index is absent or being
  rebuilt, the check falls back to today's full scan. It never skips the
  check.
- **Tenant isolation.** Every key embeds `tenant_id` resolved from the
  caller's key, as today. The cursor is opaque but carries no authority: it
  is decoded and validated as a position in the caller's own tenant's
  index, so a cursor from another tenant only yields a 400 or that position
  in your own data.
- **Malicious caller.** `limit` is capped at 500 and each request reads at
  most `4 × limit` index entries, so the endpoint cannot be used to make
  Shield read the whole fleet repeatedly. `q` is length-capped and used only
  as a lexical range bound (no pattern matching, no regex).
- **Device keys** still reach only `DEVICE_PATHS`; the list and reindex
  endpoints remain tenant-key only.

## 6. Packaging & deploy

- New module `core/dlp/device_index.py` (index maintenance, rebuild, paged
  reads). `Dockerfile.admin` already copies the whole directory
  (`COPY core/dlp/ core/dlp/`), so no Dockerfile change;
  `tests/test_admin_dockerfile_imports.py` keeps guarding it.
- No new pip dependency. Redis commands used: HGET, HSET, HDEL, HLEN, HMGET,
  HINCRBY, ZADD, ZREM, ZCARD, ZCOUNT, ZRANGEBYLEX, ZRANGEBYSCORE, SADD, SREM,
  SSCAN, SET NX EX, DEL. All are supported by the Upstash REST client. No
  MULTI/pipeline is required; where the code batches, it uses the same
  pipeline-with-sequential-fallback pattern as `storage/guardrail_metrics.py`.
- The in-memory fallback (`_mem_hash`, used when Redis is absent and in
  tests) gets matching in-memory structures.
- Rebuild both images. Deploy order does not matter: an un-upgraded plane
  keeps using full scans and does not maintain indexes, and the drift check
  (`HLEN` vs `ZCARD`) catches devices it enrolled or revoked in the meantime.
- New env flag: `SHIELD_DEVICE_INDEX` (`on` default, `off`). Document it in
  `docs/device-dlp-runbook.md` with the reindex endpoint.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Redis down | Unchanged from today: device endpoints fail as they do now. Nothing fails open that was closed |
| Index absent (existing tenant, first request) | Full-scan path for that request; rebuild under the lock |
| Two workers rebuild at once | `SET NX EX 60` lock: one rebuilds, the other serves the full scan |
| Process dies mid-update (counts drift) | Totals stay exact (HLEN, ZCOUNT). Breakdowns may be off until the next rebuild. Drift check rebuilds when HLEN and ZCARD differ; `/reindex` forces it |
| An un-upgraded plane enrolls or revokes during rollout | An enrollment it makes has no serial entry until the hourly refresh; meanwhile a claim to that serial enrolls as a new device (no replacement, no alert). A revoke it makes leaves a stale entry, which fails the record check and sends that enrollment to the full read. The task 2 drift check catches both for the list |
| Same hostname on many laptops (images, `MacBook-Pro`) | Distinct members (`\x00{device_id}`); ordering stable by device id within a name |
| Hostname over 255 characters | Already rejected at enrollment (`_text(..., 255)`) |
| Hostname containing `\x00` | Not rejected today. The index parses a member by splitting at the **last** `\x00`, and device ids never contain one (`_ID`), so the id is always recovered. Search treats the name as given |
| Fleet renamed or a device moves fleet | Not possible today (fleet is fixed by the token at enrollment); re-enrollment into another fleet is a new device |
| Empty tenant | `{"summary": {"devices": 0, ...}, "devices": [], "next_cursor": null}` |
| `limit` absent on a 10,000-device tenant | Today's full response, as before. The portal stops calling it this way; a script that does keeps today's cost |
| Heartbeat for a revoked device | Already rejected with 401 by `caller_device()` before any index write |
| Stale toggles while paging (a laptop reports mid-walk) | A page reflects the index at read time; a device may appear on two pages or none during one walk. Acceptable for an operator view; documented |

Fail mode: there is no new fail-open path. Every indexed read has a full-scan
fallback that returns today's answer.

## 8. Test plan (Definition of Done)

New `tests/test_device_fleet_scale.py`, with a counting fake Redis (records
each command) and the in-memory fallback:

1. **Enrollment cost is flat:** with 10, 1,000 and 10,000 enrolled devices,
   one enrollment issues the same number of Redis commands, and no HGETALL.
2. **Live-serial check unchanged:** an enrollment claiming the serial of a
   device seen within 24 h in the same fleet is refused with 409 and the
   alert, through the index; with the index absent, through the fallback.
   Same serial in another fleet is allowed (today's behavior).
3. **Re-enroll after 24 h replaces** the device, keeps `device_id`, updates
   the name index (old name gone, new name present), and counts are unchanged.
4. **Paged list:** 120 devices, `limit=50` gives 50, 50, 20 in hostname
   order with a null final cursor; no device repeated or missing.
5. **Filters:** `fleet`, `state`, `stale=true` (oldest first), `q` prefix
   (case-insensitive), and combinations, each against a hand-computed answer;
   a combined filter that yields a short page still returns a cursor.
6. **Bounded work:** a filter matching nothing on 10,000 devices reads at
   most `4 × limit` index entries per request.
7. **Summary:** totals from HLEN and ZCOUNT are exact after a simulated
   crash between two index commands; breakdowns are corrected by `/reindex`.
8. **Backward compatibility:** `GET /v1/tenant/me/devices` with no
   parameters returns a response identical to today's for the same data
   (golden comparison with the current implementation).
9. **Lazy build:** an existing tenant with devices and no index gets correct
   answers on the first request (fallback) and indexed answers after.
10. **Drift:** a device written straight into `devices:` (simulating an old
    plane) is detected by the HLEN vs ZCARD check and indexed by the rebuild.
11. **Revoke** removes the device from every index and decrements counts.
12. **`SHIELD_DEVICE_INDEX=off`:** every path uses the full scan; no index
    keys are written.
13. **Validation:** `limit` 0 and 501, an unknown `state`, a forged cursor,
    a 65-character `q` each return 400.
14. **Tenant isolation:** tenant B's cursor and filters never return tenant
    A's devices.
15. **Hooks portal hostnames:** `claude_code_overview` and the OS-events
    summary name laptops with HMGET and no HGETALL of `devices:`.

Existing suites must stay green unchanged: `tests/test_device_enrollment.py`,
`test_device_agent.py`, `test_device_rollout.py`, `test_device_ca.py`,
`test_runtime_hooks_portal.py`, and `tests/test_admin_dockerfile_imports.py`.
Full suite green in a clean venv; CI `pytest` gate passes.

Portal (task 3): a `tests/test_device_dlp_portal.py` in the style of
`tests/test_exceptions_portal.py` (static checks that `static/tenant.html`
calls the paged API with the parameters it accepts, sends `cursor` back
unchanged, and has the tabs, cards, search and stale toggle wired); and a
check of the page in the browser against a tenant seeded with 2,000 devices.

## Tasks (one PR each, in order)

1. **Serial index and flat-cost enrollment.** `core/dlp/device_index.py`
   with the serial index, version key, lock and rebuild (serial part);
   `enroll()` and `revoke()` use it; `SHIELD_DEVICE_INDEX`. Tests 1 to 3, 9
   (serial part), 11 (serial part), 12. This alone makes a large rollout safe.
2. **Fleet indexes and the paged API.** Names, last-seen, state sets and
   counts, maintained by enroll, heartbeat and revoke; paged and filtered
   `GET /v1/tenant/me/devices`; `POST .../reindex`; HMGET hostname lookups in
   `routes_hooks_portal.py`; runbook entry. Tests 4 to 15.
3. **Portal.** Tabs with lazy loading, summary cards as filters, search,
   stale toggle, fleet selector, paging. `tests/test_device_dlp_portal.py`
   and the 2,000-device browser check.
