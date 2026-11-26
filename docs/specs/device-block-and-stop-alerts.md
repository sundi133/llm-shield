# Spec: alerts for device blocks and stopped agents

Status: **draft, awaiting approval.** Branch `spec/poc-phase1-quick-wins`.

Roadmap item R2 from the "Test Cases G" POC gap analysis. Lifts AG-47 (real-time
alerts for blocked activity) and AG-31 (agent tampering detected and reported).
Builds on `docs/specs/device-dlp-agent.md` (the agent, its audit log, section 7
"detection, not prevention"), `docs/specs/device-fleet-scale.md` (the
`device_last` index) and the existing webhook + SIEM fan-out
(`core/webhook_dispatcher.py`, `core/siem_dispatcher.py`). No new SIEM transport.

## 1. Problem & outcome

**Problem.** Two things a SOC expects to be told about are only visible if
someone opens the portal:

1. **Device DLP blocks.** The agent records each decision in its hash-chained
   audit log (`votal_device_agent/audit.py`) and pushes it every sync (300 s,
   `agent.py:350`) to `POST /v1/shield/runtime/events` as `kind: "dlp"`,
   `decision: "deny"` (`audit.to_event`). `core/runtime_policy/events.ingest`
   writes the decision audit and telemetry. No webhook fires, so nothing reaches
   the tenant's webhooks or SIEM. (`guardrail_blocked` fires only from the tool
   path, `api/routes_tool.py:813`.)
2. **A stopped agent.** The agent runs as a root LaunchDaemon or LocalSystem
   service, but a local admin can stop it. The server only notices passively: a
   device whose last heartbeat is older than `SHIELD_DEVICE_STALE_S` (default
   3600 s, `core/dlp/devices.py:95`) shows as `stale` in the fleet view. No
   alert, and no way to tell a stopped agent from a laptop that was asleep.

Separately, `dispatch_event` returns before the SIEM fan-out when no webhook
subscribes to the event (`core/webhook_dispatcher.py:85-87`). A tenant that
configured only a SIEM receives nothing. Every alert in this spec depends on
fixing that.

**Outcome.**
- A `device_dlp_blocked` event reaches the tenant's webhooks and SIEM within
  about one minute of a block on an online laptop. Offline laptops deliver on
  reconnect, marked `delayed`.
- A `device_agent_alert` event, with a `reason`, when an agent is stopped
  while the machine stays up, restarts without a reboot, loses its system proxy
  (PAC) setting, or goes silent (opt-in). A `returned` event follows when it
  comes back.
- Sleep and reboots do not raise tamper alerts.

**Non-goals.**
- Preventing a local admin from stopping the agent (OS tamper protection, MDM
  restrictions). This is detection only, as in device-dlp-agent.md section 7.
- New SIEM transports or formats (syslog, CEF).
- Alerts for redact, justify or monitor decisions (follow-up).
- Changing the default `fail_mode` (stays `allow`).

## 2. Plane & latency contract

- **Off the guard path.** Nothing touches `/guardrails/*`, `cap/mint` or
  `tools/call`, or the device agent's prompt decision path.
- **Data plane:** the runtime events route (device audit batches) and the
  heartbeat route. Both are management traffic from laptops. Alert work runs in
  the existing background task (`background.add_task(rt_events.ingest, ...)`)
  or after the heartbeat write: a few Redis calls, then `create_task` for
  delivery. The HTTP response is not delayed by delivery.
- **Admin plane:** one daemon thread, started at admin startup, sweeps for
  silent and stopped devices every 60 s (`SHIELD_DEVICE_WATCH=off` disables it).
  A cluster-wide lock makes it one sweep per minute across replicas.
- **Endpoint:** the agent pushes its audit log within 30 s of a block (debounced)
  instead of waiting for the next 300 s sync, and adds lifecycle fields to the
  heartbeat.

## 3. Data model

New keys (both Redis clients; device helpers in `core/dlp/devices.py` style):

| Key | Shape | TTL | Purpose |
|---|---|---|---|
| `device_dlp_seen:{tenant}:{record_hash}` | `"1"` (SET NX) | 7 days | Drop a block the agent pushes twice |
| `device_dlp_alert:{tenant}:{device_id}:{category}` | counter (INCR) | `SHIELD_DEVICE_DLP_ALERT_WINDOW_S`, default 300 s | First block per device and category per window alerts; the rest are counted |
| `device_dlp_rate:{tenant}:{epoch_minute}` | counter | 120 s | Tenant cap, default 60 alerts per minute; the overflow becomes one `reason: "more"` summary |
| `device_health:{tenant}` | HASH `device_id` -> `{"state", "reason", "since", "alerted_at"}` | none (field removed on revoke) | Health episode, so each episode alerts once and `returned` fires once |
| `device_watch_lock` | SET NX | 55 s | One sweep per minute across admin replicas |

Heartbeat `seen` record (`device_seen:{tenant}`, existing) gains optional
fields: `agent_started_at`, `booted_at` (both server time, see section 7),
`slept_s`, `last_capture` (the last `capture.state` seen, defined by
`docs/specs/device-agent-vpn-validation.md`) and `last_stop` (`{"at", "reason"}`).

Device policy (`core/dlp/device_policy.py`) gains an optional `alerts` section,
stored only when set (like `discovery`), so existing policy hashes are unchanged:

```json
"alerts": {"dlp_blocks": true, "tamper": true, "silent_after_s": 0}
```

`silent_after_s: 0` means no silence alerts (the default; laptops sleep every
night). Tenant-scoped like every device key: the tenant comes from the device
key (`caller_device`) or the tenant key, never from the request body.

## 4. API / interface

**New webhook event types** in `api/routes_webhooks.VALID_EVENTS`, with
checkboxes on the portal's webhook form:

- `device_dlp_blocked`: `{device_id, hostname, fleet, destination, app,
  category, rule_ids, mode, bundle_version, prompt_sha256, prompt_len, at,
  delayed, window_s, excerpt?}`. `excerpt` only when the tenant turned on
  `privacy.capture_excerpt` (already masked by the agent). Never the prompt.
- `device_agent_alert`: `{device_id, hostname, fleet, reason, since,
  last_seen, detail}`, where `reason` is one of `stopped`,
  `restarted_without_reboot`, `capture_disabled`, `silent` or `returned`.

Webhooks keep their explicit subscription lists, so no existing webhook starts
receiving these. A SIEM config with an empty `events` list ("all") receives
them, which is what that setting means (section 5).

**Agent to Shield (unchanged routes, new optional fields):**
- `POST /v1/devices/heartbeat` adds `agent_uptime_s`, `system_uptime_s`,
  `slept_s` (best effort), and on shutdown
  `lifecycle: {"event": "stop", "reason": "signal" | "service"}`. Older servers
  ignore unknown fields (`devices.heartbeat` docstring).
- `POST /v1/shield/runtime/events` is unchanged; the agent calls it sooner.

**Portal:** the fleet view shows the device's open health reason next to
`stale`. The Device DLP policy page gets the three `alerts` settings.

## 5. Security & backward compatibility

- **Defaults.** Block and tamper alerts are on in policy terms, but only deliver
  to a webhook that subscribes to the new types or a SIEM set to "all events".
  Silence alerts are off (`silent_after_s: 0`).
- **SIEM fan-out without a webhook (behavior change).** `dispatch_event` will run
  the SIEM fan-out even when no webhook subscribes. SIEM configs set to "all
  events" will start receiving event types they never got before (for example
  `ai_discovered`, `check_unavailable`). That matches their stated filter, but
  it is new traffic. Escape hatch: `SHIELD_SIEM_REQUIRES_WEBHOOK=1` restores the
  old rule. Migration note in the release notes.
- **Kill switch:** `SHIELD_DEVICE_ALERTS=off` stops both new event types.
  `SHIELD_DEVICE_WATCH=off` stops the admin sweep.
- **Authz.** Only a device key can produce `device_dlp_blocked` for that device:
  the route already stamps `device_id` from the key (`routes_runtime.py:93-97`).
  A tenant key posting `kind: "dlp"` events does not raise device alerts. Policy
  `alerts` writes go through the existing device-policy write gate.
- **Abuse.** A compromised device key can raise its own block alerts at most once
  per category per window, and the tenant cap bounds the total. It can suppress
  its own health alerts, as it can today by faking heartbeats. That is the known
  limit of self-reporting.
- **Privacy.** No prompt text. Hostname and destination are already in the
  fleet view and the audit.

## 6. Packaging & deploy

- New module `core/dlp/device_alerts.py`: the throttle, health classification and
  payloads. `Dockerfile.admin` already copies `core/dlp/` whole (line 59), so no
  Dockerfile change. `tests/test_admin_dockerfile_imports.py` still guards it.
- No new pip dependencies. The agent reads the system proxy setting and uptime
  with the standard library: `sysctl -n kern.boottime` on macOS and
  `GetTickCount64` via `ctypes` on Windows. Reading the effective proxy is R5's
  `capture` self-check, not this spec.
- Rebuild the data plane, admin and device agent images. Devices pick up the
  agent change on their next upgrade. Server-side block alerts work with older
  agents, but only on the 300 s sync.

## 7. Failure modes & edge cases

- **Laptop asleep, then wakes.** The sweep can't tell sleep from stop while the
  device is silent, so silence alerts are opt-in. When the laptop wakes, the next
  heartbeat classifies the gap: `slept_s` covers it, so no alert.
- **Reboot or shutdown.** The agent sends `lifecycle: stop` on SIGTERM, and
  launchd and the Windows SCM send one at shutdown too. `system_uptime_s` on
  return shows the machine rebooted after the stop, so no alert. If no reboot
  followed and the device stays silent past `SHIELD_DEVICE_STOP_GRACE_S`
  (default 900 s), the sweep raises `stopped`.
- **Agent killed with no stop event** (`kill -9`, service deleted). The device
  goes silent. If it comes back, its agent started after the last heartbeat but
  the machine did not reboot: `restarted_without_reboot`. If it never comes back
  and silence alerts are off, it shows only as stale. The doc states this limit.
- **PAC removed or overridden while the agent runs.** The heartbeat's `capture`
  object (R5, `docs/specs/device-agent-vpn-validation.md`) changes from `ok` to
  `missing` or `overridden`. That change raises `capture_disabled`. Agents
  without R5 send no `capture` object, and no capture alert is raised for them.
- **Clock skew.** The agent reports durations (`agent_uptime_s`,
  `system_uptime_s`), not device timestamps, and the server converts them to its
  own clock. Silence is measured on server time only.
- **Duplicate pushes.** After a failed sync the agent re-sends records.
  `record_hash` dedupe drops them.
- **Old blocks pushed after a long offline period.** Still alerted, with
  `delayed: true`. Records older than 7 days are not alerted (they stay in the
  audit).
- **Redis down.** Alert work is wrapped and fails open: the audit and telemetry
  writes are unaffected, and the alert is skipped and logged. The sweep skips a
  cycle.
- **Many devices go silent at once** (an outage on Shield's side): the sweep
  raises at most one `silent` per device per episode. If more than 50 devices in
  a tenant go silent in one sweep, it sends one summary instead of per-device
  events.
- **Unknown `lifecycle` values** are ignored, not rejected,
  so older and newer agents mix.

## 8. Test plan (Definition of Done)

- **Block alerts.** A device block raises `device_dlp_blocked` with device fields
  and no prompt. The second block in the window is counted, not sent. Replays are
  dropped by `record_hash`. The tenant cap produces one `more` summary.
  `privacy.capture_excerpt` controls `excerpt`. A tenant-key `dlp` event does not
  alert. `SHIELD_DEVICE_ALERTS=off` sends nothing.
- **SIEM fan-out.** A SIEM with no webhooks receives the event, and its filter is
  honored. `SHIELD_SIEM_REQUIRES_WEBHOOK=1` restores the old behavior. Existing
  webhook tests are unchanged.
- **Health classification**, one test per row: sleep, reboot after stop, stop
  with no reboot past the grace period, `restarted_without_reboot`,
  `capture_disabled`, `returned` fires once, silence alerts off by default and
  on when set.
- **Sweep.** Lock held: no second sweep. Redis down: no exception. Over 50 silent
  devices: one summary.
- **Agent.** A block triggers an audit push within the 30 s debounce and never
  more often. The stop path sends `lifecycle: stop` within a 3 s timeout and
  still exits if Shield is unreachable. The uptime fields are present.
- **Policy.** `alerts` validates, and is stored only when set: the policy hash is
  unchanged for tenants that never set it.
- **Regression.** A heartbeat with the new fields is accepted by the current
  server. Every new key name appears in tests. The full suite is green in a clean
  venv.

## 9. Tasks (one PR each, in order)

1. **Block alerts to webhooks and SIEM.** `core/dlp/device_alerts.py` (throttle,
   dedupe, payload). Hook it from the runtime events route for device-key
   batches. Add `device_dlp_blocked` to `VALID_EVENTS` and the portal form. Move
   the SIEM fan-out ahead of the early return, behind
   `SHIELD_SIEM_REQUIRES_WEBHOOK`. Tests.
2. **Agent signals.** Debounced audit push after a block. Lifecycle stop on
   shutdown. Uptime fields and `slept_s` in the heartbeat.
   macOS and Windows fixtures. Tests.
3. **Health alerts.** Classification on heartbeat (`returned`,
   `restarted_without_reboot`, and `capture_disabled` from R5's `capture.state`,
   so it needs R5 tasks 1 and 2 merged first; the other reasons do not). Admin sweep for `stopped`
   and opt-in `silent`. `device_agent_alert` event type. Policy `alerts` section
   and portal settings. Fleet view reason. Tests.
4. **Docs.** POC runbook section covering which events to subscribe,
   `fail_mode: block` for POC fleets, users without local admin rights, and what
   is still undetectable (a permanent stop with silence alerts off). No em
   dashes.

## Follow-ups (not in this spec)

- Alerts for redact and justify decisions, and per-category routing (for example,
  only `credentials` blocks page the SOC).
- MDM-side tamper protection (macOS managed login items, Windows service ACLs)
  to make stopping the agent harder, not just visible.
- A digest email of device alerts for tenants without a SIEM.
