# votal-device-agent

On-laptop DLP for prompts to AI tools, for Mac and Windows. Rules first, then
the Tev1 0.8B decision model on a dedicated local Ollama, then the tenant's
policy. Prompts are never sent to Shield for inspection. Spec:
`docs/specs/device-dlp-agent.md`.

The agent core is task 4; capture (the local proxy, the per-device CA, the PAC
file, the reason page and the browser extension switch) is task 5. The
installers (task 6) come next.

## What it does

| Piece | Module | Notes |
|---|---|---|
| Bundle trust | `trust.py` | Verifies the signed DLP bundle against the key MDM pinned. Expired bundles are used for `grace_s`, then the fallback rules. Never accepts an older bundle, and never lets a wound-back clock extend one. |
| Decisions | `engine.py` | Rules (the same engine as the ICAP adapter), then the model on the rule-redacted text: last user turn first, at most 4 chunks. Per-category enforcement, `fail_mode`, justify, and after-send mode on slow hardware. |
| Model | `model.py` | `/v1/systemone` client, the calibrated decision rule, a latency gate from its own measured p95, and a health check for the Ollama version and model digest. |
| Audit | `audit.py` | shield-mavlink's hash-chained log. Holds verdicts, hashes and lengths; never the prompt. |
| Sync | `sync.py` | Enroll, pull the bundle, push the audit log as `dlp` events, send heartbeats. Offline is fine. |
| Loopback API | `local_api.py` | `127.0.0.1` only. Requires the per-install secret, the loopback Host header and no web Origin. Also serves `/proxy.pac` and the reason page `/justify/{token}`. |
| Local proxy | `proxy.py`, `capture.py`, `ws.py` | mitmproxy on `127.0.0.1:47824`. Intercepts TLS for AI hosts only and tunnels everything else untouched. Reads bodies with the ICAP adapter's decoder and extractor. Redacts by rewriting the JSON, and blocks with the provider's own error shape. |
| Device CA | `ca.py` | Name-constrained to the AI hosts, so a stolen key cannot impersonate any other site. Windows (`ca_mode` device): a CA made and trusted on the laptop. macOS (`ca_mode` tenant): a 7-day intermediate, renewed daily, under the tenant root that MDM trusts. The laptop's key never leaves it. |
| Browser | `native_host.py`, `examples/browser-extension/agent_client.js` | The extension gets the port and secret over native messaging and asks the agent. It falls back to Shield when there is no agent. |

## Run it (from a Shield checkout)

`agent.json` is written by the MDM install:

```json
{"shield_url": "https://api.guardrails.votal.ai", "tenant_id": "acme", "fleet": "sales",
 "pinned_public_key": "<64 hex, from the admin portal, copied into the MDM profile>",
 "state_dir": "/Library/Application Support/Votal/agent"}
```

Enroll with a token from the portal (Enterprise Controls, then Device DLP):

```bash
PYTHONPATH=packages/votal-device-agent python -m votal_device_agent --config agent.json enroll --token vde....
```

Run the agent:

```bash
PYTHONPATH=packages/votal-device-agent python -m votal_device_agent --config agent.json run
```

Check one prompt:

```bash
echo "my key is AKIAIOSFODNN7EXAMPLE" | PYTHONPATH=packages/votal-device-agent python -m votal_device_agent --config agent.json check --destination chatgpt.com
```

The agent expects its own Ollama (0.35.0 or later) on `127.0.0.1:11535` with
`tev1:0.8b` pulled. Start one for development:

```bash
OLLAMA_HOST=127.0.0.1:11535 ollama serve
```

Point the system proxy at the PAC file (MDM does this in production):
`http://127.0.0.1:47823/proxy.pac`. Trust `<state_dir>/ca/mitmproxy-ca-cert.pem`
(the installer does this in task 6).

`model_inline` in `agent.json` can be `auto` (the default), `always` or `never`.
With `auto`, the model sits on the send path only when its measured p95 meets
the gate: 300 ms on Apple Silicon, 800 ms on x86. Otherwise it judges after the
prompt is sent and its verdict is only recorded.

## Releasing

1. Set the new version in `votal_device_agent/_version.py` (and
   `core/dlp/kits.py DEFAULT_AGENT_VERSION`; a test keeps them equal).
2. To move to a newer Ollama, regenerate the lock from GitHub's asset digests
   and review the diff:

   ```bash
   python packages/votal-device-agent/packaging/fetch_ollama.py --print-digests 0.36.0 > packages/votal-device-agent/packaging/ollama.lock
   ```

3. Merge, then tag `device-agent-v<version>` on main. The
   `device-agent-release` workflow checks that the tag matches `_version.py`,
   builds both installers with the pinned Ollama (CUDA left out on Windows),
   signs and notarizes them when the repository secrets exist, and publishes a
   GitHub Release with `SHA256SUMS`. Without the secrets it publishes an
   **unsigned pre-release**, labelled so, for pilots.

Repository secrets for signed releases:

| Secret | What |
|---|---|
| `APPLE_APP_CERT_P12`, `APPLE_INSTALLER_CERT_P12` | Developer ID Application and Installer certificates, base64 `.p12` |
| `APPLE_CERT_PASSWORD` | Their password |
| `NOTARY_KEY_ID`, `NOTARY_ISSUER`, `NOTARY_KEY_P8` | App Store Connect API key for `notarytool` |
| `WINDOWS_SIGN_CERT_PFX`, `WINDOWS_SIGN_PASSWORD` | Code-signing certificate, base64 `.pfx` |

Then set `SHIELD_APPLE_TEAM_ID` on Shield so the kits' `get-installer.sh` and
the managed login item check Votal's Apple team.
