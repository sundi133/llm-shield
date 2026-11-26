# Spec: device agent under VPN (capture self-check and validation matrix)

Status: **draft, awaiting approval.** Branch `spec/poc-phase1-quick-wins`.

Roadmap item R5 of the POC gap roadmap (`Test Cases G - Shield coverage v2.xlsx`),
lifting **AG-33**: "Test guardrail functionality when users connect through VPN.
Policies remain consistently enforced." Builds on `docs/specs/device-dlp-agent.md`
(the agent) and `docs/specs/device-rollout-acceptance.md` (the acceptance format
reused in section 4.3).

## 1. Problem & outcome

**Problem.** The device agent sees AI traffic only because the OS proxy settings
point at its PAC: the MDM profile sets `ProxyAutoConfigURLString` on macOS
(`packaging/macos/mdm/votal-device-agent-proxy.mobileconfig`) and the Intune
script sets the machine-wide `AutoConfigURL` on Windows
(`packaging/windows/intune/set-pac.ps1`), both to
`http://127.0.0.1:47823/proxy.pac`. The PAC sends AI hosts to
`PROXY 127.0.0.1:47824` and everything else `DIRECT`
(`votal_device_agent/pac.py`). The proxy listens on loopback, so a VPN tunnel by
itself does not bypass it. What does bypass it:

- **The VPN pushes its own proxy or PAC** while connected (GlobalProtect,
  AnyConnect / Secure Client and FortiClient can; Zscaler Client Connector in
  Z-Tunnel 1.0 mode sets a system PAC). The browser then never asks our PAC.
- **Packet-level steering with TLS inspection** (Zscaler Z-Tunnel 2.0, Netskope)
  intercepts the agent's own upstream connection. The agent verifies upstream
  certificates against mitmproxy's default bundle, not the OS store, and
  `Proxy(upstream_ca=...)` exists (`proxy.py:153`) but no config sets it, so
  inspected upstream TLS likely fails and AI sites break.
- **A loopback exclusion is missing** in the VPN's proxy bypass list, so the
  PAC fetch or the `127.0.0.1:47824` hop is sent into the tunnel.

Today none of this is visible: the heartbeat reports bundle and model state
only (`core/dlp/devices.py` `STATES`), and `verify` checks that the local proxy
runs (`installed.py:245`), not that the OS still routes through it.

**Outcome.**
1. The agent checks every 60 s whether the effective system proxy is still its
   own PAC and reports the result in the heartbeat as a new optional `capture`
   object. The fleet view shows it and can filter on it.
2. A validation matrix (per VPN client and OS) with expected results and the
   known fix for each conflict, in the rollout docs.
3. A scripted acceptance run a field engineer does on a laptop with the VPN
   connected.
4. Managed setting `upstream_ca` (or `upstream_trust: system`) so the agent
   trusts a TLS-inspecting VPN's root on its own upstream connections.

Observable success: on a laptop where GlobalProtect pushes its own PAC, the
device shows "Capture: overridden" in the fleet view within two heartbeats,
and after the documented fix it shows "ok" and a test prompt is blocked in
enforce mode.

**Non-goals.**
- Running real VPN clients in CI. The matrix is manual (section 8 says which parts are unit tested).
- Taking proxy settings back from a VPN automatically (fighting the VPN client is fragile and the customer's network team owns it).
- Linux, VDI (R19), unmanaged devices (R20).
- Alerting itself: `docs/specs/device-block-and-stop-alerts.md` (R2) raises `capture_disabled` when `capture.state` changes from `ok` to `missing` or `overridden`. The `capture` object defined here is the only definition; R2 reads it. This spec does not depend on R2.

## 2. Plane & latency contract

- **Endpoint** (device agent): the self-check runs on its own timer in the agent, never in the request path of the local proxy.
- **Data plane:** `POST /v1/devices/heartbeat` accepts the new optional field. Management traffic, not the guard path.
- **Admin plane:** the fleet view (`GET /v1/tenant/me/devices`, `static/tenant.html` Devices page) shows and filters it.
- **Off hot path**, no change to `/guardrails/*`, `cap/mint` or `tools/call`.

## 3. Data model

No new Redis keys. The heartbeat record `device_seen:{tenant}` (field per device,
written by `devices.heartbeat`) gains an optional `capture` object:

```json
"capture": {
  "state": "ok | overridden | missing | unknown",
  "kind": "pac | manual_proxy | none",
  "effective": "http://10.1.2.3/vpn.pac",   // host and path only, 200 chars max
  "since": 1795700000                        // when this state started
}
```

- `ok`: the effective PAC URL is the agent's own, or one listed in the device policy's `capture.allowed_pac_urls` (a VPN PAC the customer has chained to the agent).
- `overridden`: a different PAC URL, or a manual proxy, is effective.
- `missing`: no proxy configuration at all (profile removed, or `capture=off`).
- `unknown`: the OS settings could not be read.

Device policy (`core/dlp/device_policy.py`) gains an optional section, stored only
when set so existing policy hashes do not change (the `discovery` pattern):
`"capture": {"allowed_pac_urls": []}` (at most 10 http(s) URLs). It travels in the
signed bundle like the rest of the policy.

Tenant scoping is unchanged: the heartbeat is authenticated by the device key,
which resolves the tenant (`devices.caller_device`).

## 4. API / interface

### 4.1 Agent
- `platform/proxy_settings.py` (new): `read_effective(os_name) -> dict`.
  macOS: parse `scutil --proxy` (the effective dictionary, including scoped
  VPN entries). Windows: `WinHttpGetIEProxyConfigForCurrentUser` via `ctypes`
  plus the HKLM `AutoConfigURL` / `ProxySettingsPerUser` values the Intune
  script sets. Readers are injected so tests mock them.
- `capture_check.classify(settings, own_pac_url, allowed) -> dict`: pure function.
- `Agent.heartbeat_payload()` adds `capture` when `cfg.capture == "proxy"`.
- `votal-device-agent verify` gains a line `capture: ok (http://127.0.0.1:47823/proxy.pac)` or the reason.
- Managed setting `upstream_ca` (path to a PEM bundle) or `upstream_trust: system`, read by `platform/managed.py`, passed to `Proxy(upstream_ca=...)`.

### 4.2 Server
- `devices.heartbeat` validates `capture` like `os_events`: an object with a known `state`; unknown extra keys rejected; `effective` truncated.
- `_row` copies it to the fleet row; `list_devices` summary adds `by_capture`.
- `GET /v1/tenant/me/devices?capture=overridden` filters (paged path uses the row data already read; no new index).
- Portal: a "Capture" column and filter chip on the Devices page.

### 4.3 Acceptance run (field engineer, per VPN client)
A new section in `docs/specs/device-rollout-acceptance.md` format, run with the
VPN connected and disconnected:

| # | Step | Expected |
|---|---|---|
| V.1 | `votal-device-agent verify` | `capture: ok` |
| V.2 | Connect the VPN; wait 2 minutes; `verify` again | `capture: ok`, or `overridden` naming the VPN's PAC |
| V.3 | Portal, Devices | Same capture state as V.2 |
| V.4 | Fleet in enforce; paste a test secret into ChatGPT in Chrome and Edge | Blocked; decision in the audit |
| V.5 | Apply the matrix fix if V.2 was not ok; repeat V.1 to V.4 | All ok |
| V.6 | Disconnect the VPN; repeat V.1 | `capture: ok` |

`scripts/vpn_capture_check.sh` / `.ps1` automate V.1, V.2 and the audit lookup
(through the local API `/v1/local/status`); V.4 stays a manual browser step.

### 4.4 Validation matrix (docs, `docs/device-agent-vpn.md`)

| VPN client | Typical conflict | Expected without fix | Fix |
|---|---|---|---|
| GlobalProtect | Portal pushes proxy / PAC | `overridden` | Remove proxy from the portal config, or chain AI hosts to `127.0.0.1:47824` in the VPN PAC and list it in `allowed_pac_urls` |
| Cisco Secure Client | Group policy "MSIE proxy" (Windows) | `overridden` on Windows | Same; add `127.0.0.1` to the proxy exception list |
| Zscaler Client Connector, Z-Tunnel 1.0 | Sets a system PAC | `overridden` | Chain in the Zscaler PAC, or move to Z-Tunnel 2.0 |
| Zscaler Z-Tunnel 2.0 / Netskope | Inspects the agent's upstream TLS | `ok`, but AI sites fail with a certificate error | `upstream_trust: system`, or exempt the agent process from inspection |
| FortiClient | Tunnel can set a proxy / PAC | `overridden` | Same as GlobalProtect |
| WireGuard / Tailscale | DNS only | `ok` | None expected |
| macOS / Windows built-in IKEv2 | Per-service proxy on the VPN service | `overridden` if set | Leave proxy empty on the VPN service |

Rows are expectations until run. Each run records pass or fail with the client version.

## 5. Security & backward compatibility

- **Opt-in by nature:** the check only reports. No routing change.
- **Old servers, new agents:** `capture` is a new top-level key; `devices.heartbeat` ignores keys it does not read, so an old server accepts the heartbeat. Using a new value of `state` instead would be rejected with 400 (`state: one of ...`) and break heartbeats, which is why it is a separate field.
- **New servers, old agents:** no `capture` field; the fleet view shows "not reported".
- `effective` can reveal an internal PAC host. It is stored as host and path only (no query) and shown only to the tenant.
- `upstream_trust: system` widens what the agent trusts upstream to the OS store, which the browser already trusts; off by default.
- A user who edits proxy settings is reported as `overridden`; they cannot make the report say `ok` without pointing at an allowed PAC.

## 6. Packaging & deploy

- Agent: new modules in `packages/votal-device-agent`; no new dependency (`ctypes` and `subprocess` are standard library). Agent release as usual.
- Server: changes in `core/dlp/devices.py`, `core/dlp/device_policy.py`, `static/tenant.html`. No new module imported by `admin_app.py`, so `Dockerfile.admin` is unchanged.
- No env flags. Both images rebuild on merge.

## 7. Failure modes & edge cases

- `scutil` or the WinHTTP call fails or times out (2 s): `unknown`, never crash the agent loop.
- Several active network services with different proxies (macOS): report the primary service's effective settings, which is what browsers use.
- PAC URL differs only by case, trailing slash or `localhost` vs `127.0.0.1`: normalised before comparison.
- State flaps while a VPN connects: `since` only changes on a real change; the fleet view shows the current state.
- `capture=off` in the agent config: report `missing` with kind `none`, so a fleet configured for extension-only is visible as such.
- Huge or malformed `capture` from a device: rejected with 400 like other heartbeat fields.
- Redis down: heartbeat already fails as today; nothing new.

## 8. Test plan (Definition of Done)

Unit-tested (CI):
- `classify`: own PAC, allowed PAC, other PAC, manual proxy, no proxy, unreadable, URL normalisation.
- macOS reader against recorded `scutil --proxy` outputs (plain, GlobalProtect-style, Zscaler PAC); Windows reader with a mocked WinHTTP struct.
- Heartbeat validation: valid, unknown state, extra keys, oversize `effective`; old-server compatibility (a payload with `capture` against the existing validator leaves `state` handling unchanged).
- Fleet row and `by_capture` summary; `capture=` filter.
- `verify` prints the capture line.
- `upstream_ca` / `upstream_trust` passed to `Proxy`.

Manual (not CI): the matrix in 4.4 on at least GlobalProtect and Zscaler for macOS and Windows before the POC, results recorded in the acceptance record.

Full suite green in a clean venv; CI `pytest` gate passes.

## 9. Tasks (one PR each, in order)

1. Agent: `proxy_settings` readers, `classify`, heartbeat `capture`, `verify` line, managed `upstream_ca` / `upstream_trust`. Tests.
2. Server: heartbeat validation, fleet row, summary, filter, device policy `capture.allowed_pac_urls` in the bundle, Devices page column and chip. Tests.
3. Docs: `docs/device-agent-vpn.md` (matrix and fixes), acceptance section V, `vpn_capture_check` scripts.
4. Field run of the matrix on the POC VPN clients; record results and update the matrix.

## Follow-ups (not in this spec)

- Alert on `capture.state != ok` (R2 spec, if approved).
- Agent re-applies its PAC when the VPN disconnects and the setting is not restored.
- A PAC evaluator in the agent, to check per host rather than per URL.
