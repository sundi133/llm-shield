# Spec: Firefox and terminal coverage in the device rollout kit

Status: **draft, awaiting approval.** Branch `spec/poc-phase1-quick-wins`.

Roadmap item R1 (POC "Test Cases G": AG-03 Firefox, AG-54 CLIs, SDKs and
desktop clients). Builds on `docs/specs/device-rollout-kit.md` (the kit,
`core/dlp/rollout_kit.py`), `docs/specs/device-dlp-agent.md` (the agent, its
PAC and device CA) and the secure web gateway's MDM scripts
(`deploy/swg/mdm/install-macos.sh`, `install-windows.ps1`), which already
cover Firefox and terminals for the gateway and are reused here.

## 1. Problem & outcome

**Problem.** The rollout kit sends AI traffic to the device agent through the
system PAC (`com.apple.SystemConfiguration` payload on macOS,
`windows/set-pac.ps1` on Windows) and trusts the device CA in the OS store.
Two kinds of client miss both:

- **Firefox** has its own proxy setting and its own trust store. Today the kit
  pushes Chrome and Edge policy only (`mac_profile`, `browser-extensions.ps1`).
  A Firefox user's prompts reach chatgpt.com directly and are never screened.
- **Terminals, SDKs and CLI agents** (curl, Python `requests`/`httpx`, Node,
  the OpenAI and Anthropic SDKs, Codex) cannot read a PAC and mostly ship their
  own CA list. The kit does nothing for them. `docs/device-dlp-agent.md`
  ("Command-line tools and SDKs") tells admins to set `HTTPS_PROXY` and a CA
  bundle by hand.

**Outcome.**
- A kit with the proxy on configures Firefox on both OSes (PAC + enterprise
  roots).
- A kit with the new `terminal_coverage` option makes new terminals on
  enrolled laptops send AI traffic through the agent and trust its CA, without
  breaking TLS for anything else.
- Success is observable: on a POC laptop, a prompt typed in Firefox and a
  `curl https://api.openai.com/...` from a new terminal both show in the
  device audit; `pip install`, `git clone` and `npm install` keep working;
  `votal-device-agent verify` reports `Firefox policy` and `terminal coverage`.

**Non-goals.**
- Java (its own truststore and proxy properties), WSL, Docker containers and
  IDE-internal runtimes that ignore environment variables: follow-ups.
- Making terminal coverage a control. Users can unset environment variables;
  only egress control makes the agent mandatory. This is a default, as the
  gateway script already says.
- Linux. The agent has no Linux build (`platform/__init__.py`).
- Pinned clients: unchanged, handled by `pinned_host_action`.

## 2. Plane & latency contract

- **Endpoint:** kit templates (`core/dlp/kit_templates/`), the macOS profile
  built in `core/dlp/rollout_kit.mac_profile`, and the device agent package.
- **Admin plane and data plane:** only the existing rollout-kit route
  `POST /v1/tenant/me/devices/rollout-kits` (mounted on both via
  `devices_router`) gains two body keys.
- **Off the guard path.** No change to `/guardrails/*`, `cap/mint` or
  `tools/call`. No server-side per-request work.
- Endpoint latency: one loopback TCP probe when a shell starts on macOS
  (below 1 ms when the agent is up, an immediate refusal when it is down).

## 3. Data model

No Redis keys change. The kit record (`core/dlp/kits.py`) and `kit.json` gain
two booleans: `include_firefox` and `terminal_coverage`.

**On the laptop** (written by the agent, root or SYSTEM, world-readable,
admin-writable only):

| File | Contents | Used by |
|---|---|---|
| `<install>/trust/device-ca.pem` | The certificate clients must trust: the tenant root on macOS (`CAMode: tenant`), the device CA on Windows. Copied from `state/ca/mitmproxy-ca-cert.pem`, which only the agent's account can read. | `NODE_EXTRA_CA_CERTS` (additive) |
| `<install>/trust/ca-bundle.pem` | The OS trust store's roots exported as PEM, followed by `device-ca.pem` | `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE` (each **replaces** the default store) |

`<install>` is `/Library/Application Support/Votal/DeviceAgent` on macOS and
`%ProgramData%\Votal\DeviceAgent` on Windows. Roots are exported with
`security find-certificate -a -p` over `SystemRootCertificates.keychain` and
`System.keychain` on macOS, and the `LocalMachine\Root` store on Windows.
Exporting the OS store, not certifi, keeps corporate roots (for example an
existing TLS-inspection CA) working.

**New MDM setting** `TerminalCoverage` (bool), added to `managed.KEYS`. It
comes from the profile's settings payload on macOS and from the MSI property
`TERMINALCOVERAGE=1` on Windows.

## 4. API / interface

`POST /v1/tenant/me/devices/rollout-kits` (unchanged auth: tenant key or
portal session, registry write gate). New optional body keys:

| Key | Type | Default | Effect |
|---|---|---|---|
| `include_firefox` | bool | `true` | Firefox policy in the profile and in `set-pac.ps1` |
| `terminal_coverage` | bool | `false` | `TerminalCoverage` in the settings payload / MSI property |

A non-boolean is a 400 naming the key, like `include_proxy` today. Both keys
appear in `kit.json`, the kit list and the `tenant_create_rollout_kit` audit.

**What the kit contains:**

- **macOS profile:** a new payload `PayloadType: org.mozilla.firefox`
  (Firefox's managed-preferences domain) with:
  ```json
  {"EnterprisePoliciesEnabled": true,
   "Certificates": {"ImportEnterpriseRoots": true},
   "Proxy": {"Mode": "autoConfig", "AutoConfigURL": "<PAC_URL>", "Locked": true},
   "Preferences": {"network.http.http3.enable": {"Value": false, "Status": "locked"}}}
  ```
  A profile is used rather than `policies.json` inside `Firefox.app` (the
  gateway script's approach), because a Firefox update replaces the app bundle
  and deletes that file. `ImportEnterpriseRoots` makes Firefox trust the
  tenant root that the same profile installs in the System keychain.
- **Windows `set-pac.ps1`:** also writes `HKLM:\SOFTWARE\Policies\Mozilla\Firefox`:
  `Certificates\ImportEnterpriseRoots=1`, `Proxy\Mode=autoConfig`,
  `Proxy\AutoConfigURL`, `Proxy\Locked=1`, and the same HTTP/3 preference.
  On Windows, `ImportEnterpriseRoots` reads `LocalMachine\Root`, where the
  agent already puts its device CA (`trust_store.trust`, `certutil -addstore`).
  So the different CA origin per OS needs no Firefox-specific handling.
- **`include_proxy: false`** (customer has their own PAC): the Firefox policy
  keeps `ImportEnterpriseRoots` and omits `Proxy`. `README-own-pac.md` says to
  point Firefox at the customer's PAC.

**Agent behaviour with `TerminalCoverage: true`** (new module
`votal_device_agent/terminal.py`; applied at service start, after every CA
rotation through `on_ca_rotated`, and when MDM settings change):

1. Write `trust/device-ca.pem` and `trust/ca-bundle.pem` atomically.
2. Set the variables:
   - `HTTPS_PROXY` / `https_proxy` and `HTTP_PROXY` / `http_proxy`:
     `http://127.0.0.1:47824`
   - `NO_PROXY`: `localhost,127.0.0.1,::1`
   - `NODE_USE_ENV_PROXY=1` (Node 24+ fetch)
   - `NODE_EXTRA_CA_CERTS`: `device-ca.pem`
   - `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`: `ca-bundle.pem`
3. Where the variables are set:
   - **macOS:** a block between `# >>> votal-device-agent` and
     `# <<< votal-device-agent` markers in `/etc/zshenv` and `/etc/profile`.
     The block exports the variables only if
     `/usr/bin/nc -z -G 1 127.0.0.1 47824` succeeds, so a shell started while
     the agent is down goes direct. `VOTAL_TERMINAL_PROXY=off` in the user's
     environment skips the block.
   - **Windows:** machine environment variables, set when the local proxy is
     listening. They are removed in the service's stop handler, and a
     `WM_SETTINGCHANGE` broadcast tells new processes.
4. With `TerminalCoverage` false or absent, the same code removes its block
   and variables. Uninstall (`uninstall_hooks`, macOS `uninstall.sh`) removes
   them too.

**Scope to AI hosts.** Environment variables cannot express an allowlist (no
"proxy only these hosts"). The agent already tunnels every non-AI host
untouched (`proxy.tls_clienthello` sets `ignore_connection`), and the CA is
name-constrained to the policy's AI hosts (`ca.ensure_ca`, `NameConstraints`).
So non-AI TLS is never decrypted, and the device CA in a combined bundle cannot
vouch for any other site.

**`verify` gains two non-critical checks:**
- `Firefox policy`: ok when Firefox is not installed, or when the policy is
  present.
- `terminal coverage`: only when `TerminalCoverage` is set. It reports bundle
  present and readable, root count, and markers or variables in place.

## 5. Security & backward compatibility

- **`terminal_coverage` defaults to off.** It changes how every CLI process on
  the laptop reaches the network and which CA file it trusts; a fleet must opt
  in. Existing kits and laptops are unchanged.
- **`include_firefox` defaults to on** for kits with the proxy. It only touches
  Firefox, which today is silently uncovered. The PAC sends non-AI traffic
  DIRECT, so browsing is unaffected. Escape hatch: `include_firefox: false`,
  then re-upload the profile. Previously generated kits are unchanged until an
  admin builds a new one.
- **Terminals fail open, whatever the fleet's `fail_mode`.** A global proxy
  variable cannot fall back per host the way the PAC does (`"PROXY ...;
  DIRECT"`). Failing closed would break git, pip and package managers
  fleet-wide whenever the agent restarts.
  - macOS: new shells skip the proxy when the port is closed.
  - Windows: the variables are removed on a clean stop. After a crash they
    remain until the service restarts (service recovery, about 60 s); in that
    window only new processes are affected.
  - `verify` and the heartbeat state make a stopped agent visible (R2 adds the
    alert).
- **Trust-store risk.** `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` and
  `CURL_CA_BUNDLE` replace a client's default roots. Pointing them at the
  device CA alone breaks every HTTPS call to a non-AI site.
  - They therefore always point at `ca-bundle.pem`, never `device-ca.pem`.
  - If the export yields fewer than 50 roots or fails, the agent sets none of
    the replacing variables. It keeps the proxy and `NODE_EXTRA_CA_CERTS`, and
    `verify` fails `terminal coverage` with the reason.
  - The gateway's `install-macos.sh` and `install-windows.ps1` point these
    variables at the CA alone today. That is noted as a follow-up and not fixed
    here.
- **Existing values are respected.** If a machine-level variable is already set
  outside our markers (another tool or the customer's own bundle), the agent
  leaves it, does not override it, and reports `set by another tool` in
  `verify`.
- **Authz:** unchanged: building a kit requires the registry write gate. All
  new values are constants or validated paths; no tenant input reaches the
  shell snippet.

## 6. Packaging & deploy

- **Admin image:** `core/dlp/` is copied whole (`Dockerfile.admin`:
  `COPY core/dlp/ core/dlp/`), so new templates ship. `test_templates_ship_in_both_images`
  already guards that. No new admin imports.
- **No new pip dependencies.** Root export uses `security` and PowerShell /
  `certutil` through the agent's existing `platform.run`.
- **Agent release:**
  - `managed.KEYS` gains `TerminalCoverage`.
  - The MSI (`packaging/windows/*.wxs`) maps the `TERMINALCOVERAGE` property to
    the managed registry value, like `EXTENSIONIDS`.
  - The new agent version is required for terminal coverage. Older agents
    ignore the unknown setting, which is harmless.
  - Firefox coverage needs no new agent.
- **Rollout:** build a new kit and re-upload the profile (macOS) and
  `set-pac.ps1` (Windows). For terminals, also update the app with the new
  install command.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Firefox not installed, or installed later | The profile or registry policy is inert until Firefox runs; `verify` is ok. |
| Firefox in `~/Applications` or ESR | Managed preferences and HKLM policy apply by domain, not path. |
| Firefox HTTP/3 to an AI host | Disabled by the locked preference, so it cannot bypass the proxy. |
| OS root export fails or is tiny | Replacing variables are not set (see §5); proxy and Node still covered. |
| CA rotates (Windows, policy adds a host) | `on_ca_rotated` rewrites both files atomically; open processes keep the old file until restart. |
| Agent down (macOS) | New shells go direct; existing shells keep the variables and fail AI calls until reopened. Users can `export VOTAL_TERMINAL_PROXY=off` or unset the variables. |
| Agent crash (Windows) | Variables remain until restart (about 60 s); new processes in that window fail to connect. |
| Customer already sets `HTTPS_PROXY` or a CA bundle | Not overridden; reported by `verify`. |
| `/etc/zshenv` missing, read-only or edited by the admin | Only the marked block is written or removed. Missing files are created. A write failure is reported, never fatal. |
| Bash vs zsh vs fish | zsh (`/etc/zshenv`) and bash/sh login shells (`/etc/profile`) are covered; fish is documented as manual. |
| Huge trust store | Bounded by the OS store (a few hundred roots); written once per rotation. |
| Kit with `include_proxy: false` and `terminal_coverage: true` | Allowed: terminals use the agent directly, and the README says so. |

## 8. Test plan (Definition of Done)

**Kit (`tests/test_device_rollout.py`, extended):**
- The profile has an `org.mozilla.firefox` payload with
  `EnterprisePoliciesEnabled`, `ImportEnterpriseRoots`, the PAC and the HTTP/3
  lock.
- There is no `Proxy` key when `include_proxy` is false, and no Firefox payload
  when `include_firefox` is false.
- `set-pac.ps1` writes the Firefox registry keys and still parses (existing
  `test_scripts_parse`).
- `TerminalCoverage` appears in the settings payload and in
  `install-command.txt` only when `terminal_coverage` is true.
- `kit.json`, the list and the audit carry both booleans; non-booleans return
  400.
- The README names Firefox and terminals only when they are in the kit.

**Agent (`packages/votal-device-agent/tests/test_terminal.py`, new):**
- Bundle = exported roots + device CA.
- Each replacing variable points at `ca-bundle.pem` and never at
  `device-ca.pem`: a regression guard over the variable map.
- A root export below 50 sets no replacing variable.
- The marked block is idempotent across repeated applies and removed cleanly,
  leaving foreign lines byte-identical.
- The shell snippet runs under `sh -n` and `zsh -n`, and skips export when the
  port is closed (run against a closed port).
- Windows variables are set, then cleared, through an injected runner.
- Pre-existing foreign values are left alone.
- `verify` covers both new checks, ok and failing.

**Done when:**
- The full suite is green in a clean venv and CI `pytest` passes.
- Manual acceptance rows are added to `docs/specs/device-rollout-acceptance.md`:
  - Firefox prompt captured on Mac and Windows.
  - `curl` and the Python OpenAI SDK captured from a new terminal.
  - `git clone` and `pip install` still work with the agent up and with it
    stopped.

## 9. Tasks (one PR each, in order)

1. **Firefox in the kit.**
   - Profile payload, `set-pac.ps1` keys, the `include_firefox` body key and
     manifest, README text, and kit tests.
   - Kit-only: no agent release.
2. **Agent terminal module.**
   - `terminal.py` (bundle export, macOS marked block with liveness probe,
     Windows machine variables with stop-handler removal).
   - The `TerminalCoverage` managed key and MSI property, uninstall cleanup,
     and the `verify` checks.
3. **Kit option and docs.**
   - The `terminal_coverage` body key, settings payload and MSI property in
     `install-command.txt`, and kit tests.
   - Rewrite "Command-line tools and SDKs" in `docs/device-dlp-agent.md`
     around the option.
   - Acceptance checklist rows.

## Follow-ups (not in this spec)

- Java truststore and `-Dhttps.proxyHost` (the gateway script does this; the
  agent kit could reuse it).
- `AWS_CA_BUNDLE` (Bedrock via boto3) and other SDK-specific variables, once
  Bedrock hosts are in `ai_hosts`.
- WSL and Docker Desktop containers (they inherit neither the variables nor the
  trust store).
- Fix `deploy/swg/mdm/install-*.{sh,ps1}`, which set
  `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` / `CURL_CA_BUNDLE` to the gateway CA
  alone. That replaces the default roots, so non-gateway HTTPS fails.
- Fish shell and per-user shells outside `/etc/zshenv` and `/etc/profile`.
