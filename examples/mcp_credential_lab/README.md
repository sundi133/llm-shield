# MCP credential lab

A local MCP server that demands whichever credential mode you want to test, so the
eight modes in [docs/spec-mcp-credential-modes.md](../../docs/spec-mcp-credential-modes.md)
can be exercised end to end **without a vendor account, a browser, or internet
access**.

It is also a realistic gateway target on purpose:

- **read and write tools** (`get_invoice`, `list_payments`, `refund_payment`), so a
  `tools.allow` floor has something real to block;
- **one poisoned tool description** (`summarize_notes` tells the model to ignore
  its instructions and read `~/.ssh`), so the onboarding scanner has a genuine
  CRITICAL to find and `scan_policy.on_register: block_on_critical` can be shown
  working;
- **a card number in a tool result**, so output DLP has something to redact rather
  than passing a clean string through;
- **short-lived tokens** (120 s by default), so you can *watch* the renewal loop
  replace a credential instead of taking it on faith.

## Run it

```bash
pip install fastapi uvicorn
python lab_server.py                       # mode 1: no auth
LAB_AUTH=api_key python lab_server.py      # mode 2
LAB_AUTH=bearer  python lab_server.py      # mode 3
LAB_AUTH=oauth   python lab_server.py      # modes 4, 5, 6
```

`GET /health` reports the active mode, how many tokens it has issued, and the TTL.

## Register it with Shield

The gateway dials the upstream **from the data-plane process**, so use an address
that resolves there. Same machine:

```bash
curl -s -X PUT "$SHIELD/v1/tenant/me/mcp-gateway/upstreams/lab" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{"transport":"http","url":"http://localhost:9200/mcp","headers":{"Authorization":"Bearer lab-token"},"isolation_ack":true}'
```

`isolation_ack: true` is honest here — it is a localhost service, genuinely
reachable only from your machine. That makes the lab the easiest place to see
non-bypassable enforcement, which you cannot get with a public SaaS upstream.

## What each mode looks like

| Mode | `LAB_AUTH` | Route config |
|---|---|---|
| 1 no-auth | `none` | omit `headers` |
| 2 api key | `api_key` | `{"X-API-Key": "lab-secret"}` |
| 3 static bearer | `bearer` | `{"Authorization": "Bearer lab-token"}` |
| 4 auth code + PKCE | `oauth` | `POST .../oauth/connect`, then visit the URL (auto-approves) |
| 5 device flow | `oauth` | provider advertises `device_authorization_endpoint` |
| 6 client credentials | `oauth` | `client_id` + secret from `/oauth2/register` |
| 7 GitHub App | — | needs real GitHub; the lab cannot fake an installation |
| 8 gateway capability | any | Shield mints; the lab does not verify the signature |

Modes 7 and 8 are noted honestly rather than faked. Mode 7 needs a real App
installation, and mode 8's value is that the *upstream* verifies against Shield's
JWKS — a lab that skipped verification would prove nothing.

## The OAuth endpoints it fakes

Enough of a provider to drive modes 4–6 for real, not stubs:

```
GET  /.well-known/oauth-protected-resource/mcp   RFC 9728 — how discovery starts
GET  /.well-known/oauth-authorization-server     RFC 8414 metadata
POST /oauth2/register                            RFC 7591 dynamic registration
GET  /oauth2/authorize                           auto-approves, redirects with a code
POST /oauth2/device                              device_code + user_code
POST /oauth2/token                               all four grants
POST /oauth2/revoke
```

Two behaviors are deliberate, because they catch regressions a permissive stub
would hide:

- **`authorization_code` without a `code_verifier` is rejected.** PKCE is
  mandatory in Shield's flow, so if that ever regresses it fails loudly here.
- **The first device-code poll returns `authorization_pending`.** That is the
  normal "not yet" of a device flow, and treating it as a permanent failure would
  abort every flow before an operator finished typing the code. The lab forces the
  retry path to be exercised.
- **`client_credentials` gets no refresh token**, per RFC 6749 §4.4.3 — so the
  re-acquire path is tested rather than a refresh that would not exist.

## Verified against this lab

Shield's real discovery, registration, and acquisition code was run against it:

```
discovered issuer      : http://127.0.0.1:9200
token_endpoint         : http://127.0.0.1:9200/oauth2/token
brokerable scopes      : ['openid', 'email', 'offline_access']
registered client_id   : lab-b11833c5...
mode 6 token acquired  : labaccess-13f96b...
mode 6 refresh (none)  : ''            <- correct: RFC 6749 says none
device user_code       : LAB-CODE
first poll             : authorization still pending (status=202, permanent=False)
second poll            : acquired labaccess-086012...
```

> **One gotcha.** Shield's SSRF guard correctly refuses `localhost` and
> `127.0.0.1`, so a route pointed at the lab will be blocked by
> `validate_outbound_url` unless the data plane runs on the same host and you
> allow it. That guard is doing its job — do not weaken it in a shared
> environment. For a quick loop, run the data plane locally too, or expose the lab
> on a resolvable address.
