# SWG demo — a real browser, auto-governed, no curl, no MDM

Show a customer the public SWG screening real AI-chat traffic from a browser
that was *configured once*, not driven by curl. This is the single-machine,
manual equivalent of the MDM push (`deploy/swg/mdm/install-macos.sh`); use it
to demo before standing up MDM.

It stays out of the way of the machine you run it on: the proxy routing and the
proxy's DNS are scoped to a throwaway Chrome profile (`--proxy-pac-url` +
`--host-resolver-rules`), so your normal browser, your terminal, and any Claude
session keep going DIRECT. The only system-wide change is trusting your own
inspection CA, which `teardown` removes.

## Prerequisites (once)

From `deploy/swg/gcp/`, you need the three files the verify gate already makes
(see `docs/swg-public-proxy-runbook.md` §2):

- `interception-ca.pem` — `gcloud secrets versions access latest --secret=swg-ca-pem > interception-ca.pem`
- `device.crt`, `device.key` — the device client cert you minted (CN `test-laptop-01`)

Google Chrome installed. The SWG up in **enforce** mode (so blocks are visible).

## Run the demo

```bash
cd deploy/swg/demo
./demo-mac.sh setup      # trusts the CA (one sudo) + imports the device identity
./demo-mac.sh launch     # opens the demo Chrome, already pointed at the SWG
```

`setup` env overrides if your values differ:
`SHIELD_PROXY_PUBLIC_HOST`, `SHIELD_PROXY_IP`, `DEVICE_CN`, `CERTS=` (cert dir).

### The script to run on screen

1. **It's a normal laptop.** Open the demo Chrome. Sign in to claude.ai (or
   chatgpt.com) — it works normally; nothing looks different.
2. **Benign prompt passes.** Ask something ordinary ("summarise our Q3 goals").
   It reaches the model and answers.
3. **Sensitive prompt is blocked.** Paste a message with protected data (a
   customer SSN, a card number, a secret). The send **fails — the prompt never
   leaves the laptop**. (The cert picker on first use *is* the device
   authenticating itself — mTLS.)
4. **The SOC sees it.** Switch to the Shield **Telemetry** tab
   (shield.votal.ai). The blocked prompt is there in real time with the policy
   name (`PII data block policy`), the benign one shows **PASS**. One place,
   every surface.

The Telemetry tab is the strongest visual — have it open on a second screen.

## Reset

```bash
./demo-mac.sh teardown   # removes CA trust, the device identity, the profile
```

## Notes / troubleshooting

- **No prettier "blocked" banner in claude.ai.** The web app only sees a `403`,
  so the message shows as a failed send. The policy reason lives in the `403`
  body and in Telemetry — that's the intended place for it.
- **If an AI site shows a cert error**, the CA isn't trusted — re-run `setup`,
  or confirm it in Keychain Access (search "Inspection").
- **If AI traffic goes DIRECT (not blocked)**, Chrome ignored the PAC: make sure
  you launched via `./demo-mac.sh launch` (not a normal Chrome window), and that
  `--disable-quic` took (QUIC/HTTP3 bypasses an HTTP proxy).
- **Firefox / native apps / the terminal** are *not* covered by this scoped
  demo — that breadth is what the MDM script and network egress-lock provide.
- Do **not** point the *system* proxy at the SWG on the machine running Claude
  Code — it would route this session's traffic through the proxy too. The scoped
  Chrome profile avoids that; that's why the demo uses it.
