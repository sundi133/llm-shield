# Spec: connect OAuth upstreams that are not MCP-native (Google first)

Status: APPROVED 2026-10-04; task 1 done. Branch: `feat/tenant-enforce-mode`.
Builds on `docs/spec-mcp-oauth-brokering.md` and
`docs/spec-mcp-credential-modes.md` (mode 4, authorization code + PKCE).

## 1. Problem & outcome

Shield's OAuth broker (`core/mcp_oauth.py`, `core/mcp_credentials.AuthCodeProvider`,
`POST /v1/tenant/me/mcp/servers/{route}/oauth/connect`) works with MCP servers
whose authorization server registers clients dynamically and advertises the
`offline_access` scope. Most enterprise SaaS does neither. Checked live against
Google's Drive MCP server (`https://drivemcp.googleapis.com/mcp/v1`) on 2026-10-04:

- Discovery works: `/.well-known/oauth-protected-resource/mcp/v1` names
  `https://accounts.google.com/` and lists `drive`, `drive.readonly`,
  `drive.file`; Google's OIDC document has a token endpoint and supports
  `authorization_code` and `refresh_token`.
- **Connect is refused**: `check_brokerable` requires `offline_access` in the
  provider's `scopes_supported`. Google lists only `openid email profile`; it
  issues refresh tokens through `access_type=offline` (plus `prompt=consent`),
  not a scope.
- **Even if it were allowed, the token could not read Drive**: the broker asks
  only for `openid email offline_access`. The resource's own scopes are
  discovered and then thrown away (`discover` prefers the authorization
  server's scope list over the resource's).
- **And it would not be used**: after the callback, the route only sends the
  token if an operator has hand-set
  `headers: {"Authorization": "Bearer shield://oauth-<route>-access"}`.
- The MCP authorization spec asks clients to send the `resource` parameter
  (RFC 8707); the broker never does.

Outcome: an operator connects Google's Drive (and Gmail, Calendar, Docs, Sheets,
Chat) MCP servers through Shield by giving a client ID and secret and choosing
scopes. Shield holds a refreshable credential, the route uses it without manual
header editing, and agents call the tools through `/gateway/{route}/mcp`. The
same mechanism covers other providers with quirks by adding a profile, not code.

Non-goals:
- **Per-user credentials.** Every brokered route still acts as the one account
  that connected it. Users of the route get that account's access, not their
  own. This is the most important follow-up (its own spec, after verified
  identity), and the consent text says it plainly until then.
- On-behalf-of / token exchange (Entra OBO, RFC 8693), Okta ID-JAG, AWS SigV4,
  passing the agent's own token through. Demand-driven, separate specs.
- Google service accounts and domain-wide delegation (a different grant).
- Enrolling in Google's Workspace Developer Preview, which Google's MCP servers
  currently require. That is the customer's step; the docs say so.

## 2. Plane & latency contract

- **Admin plane** (`admin_app.py`): connect, callback, status, renewal and the
  portal. All new logic lives here, beside the existing broker.
- **Data plane**: unchanged. It already materializes the `shield://` access
  token reference on the way to the upstream. **Off the guard path**: no new
  call, read or network round trip on `tools/call`; renewal stays on the
  existing timer and lock.

## 3. Data model

No new keys. The broker record (`storage/mcp_oauth_store.py`, per tenant and
route) gains three fields:

| Field | Type | Meaning |
|---|---|---|
| `profile` | `"standard"` or `"google"` | How this provider issues refresh tokens and which extra parameters it needs |
| `resource` | string | The protected resource's identifier from its metadata, sent as RFC 8707 `resource` when the profile allows |
| `available_scopes` | list of strings | The resource's and the provider's advertised scopes, for the portal to offer |

`scopes` (existing) becomes the operator's choice when one is made. Records
written before this change have no `profile`; absent means `standard`, which is
exactly today's behaviour.

Profiles are a small table in `core/mcp_oauth.py`, matched on the discovered
issuer:

| Profile | Matched by | Refresh tokens via | Extra authorize parameters | Sends `resource` |
|---|---|---|---|---|
| `standard` | default | the `offline_access` scope (required, as today) | none | yes, when the resource published one |
| `google` | issuer `https://accounts.google.com` | `access_type=offline` | `access_type=offline`, `prompt=consent` | decided in task 1 against the live server (omit if Google rejects it) |

Another provider is one row, added when a customer needs it.

## 4. API / interface

Admin plane, existing routes, all with the tenant's key:

- `POST /v1/tenant/me/mcp/servers/{route}/oauth/connect`: the body gains
  `scopes: list[str]` (optional, at most 20, each at most 256 characters).
  - Given: each scope must appear in the advertised scopes (resource's or
    provider's, when either list is published), or **422** names the allowed
    ones. The identity scopes the profile adds (`openid`, `email`) are kept,
    plus `offline_access` for the `standard` profile.
  - Omitted, and the server advertises **access** scopes: **422** "choose
    scopes", with the list. Identity scopes (`openid`, `email`, `profile`,
    `offline_access`) do not count, so MCP-native servers that advertise only
    those (Higgsfield) connect exactly as before. Shield does not pick between, say, `drive` and `drive.readonly`
    for the operator. (Escape hatch below.)
  - Omitted, and the resource advertises none: today's behaviour.
  - The 202 response's `consent_note` names the scopes, says the grant is
    shared by every user of the route, and recommends a dedicated account.
- `GET /v1/tenant/me/mcp/servers/{route}/oauth`: also returns `profile`,
  `available_scopes`, `chosen_scopes`, `refresh_token_held` (bool) and
  `expires_at`, so the portal can show a connection that will not survive its
  first access token.
- `GET /v1/tenant/me/mcp/oauth/callback`: after a successful exchange, if the
  route has no `Authorization` header, it is set to
  `Bearer shield://oauth-<route>-access`. An existing header is never
  overwritten; the status says which one is in effect.

Portal (`static/tenant.html`, MCP Gateway): a **Connect with OAuth** panel on
an HTTP or SSE route: client ID, client secret, scope checkboxes from
`available_scopes` (none ticked by default), the consent note, then the
authorize link. Status shows connected, expiry, and whether a refresh token is
held.

## 5. Security & backward compatibility

- **Existing routes and records are untouched.** No `profile` means `standard`,
  the current code path.
- **Behaviour change on new connects only**: a server that advertises scopes now
  needs the operator to choose them. Escape hatch:
  `SHIELD_MCP_OAUTH_REQUIRE_SCOPE_CHOICE=off` restores "request identity scopes
  only". Migration note in the PR.
- **Least privilege by construction**: nothing is pre-ticked, scopes must be
  ones the server advertises, and the consent note lists exactly what is
  granted.
- **The callback stays as safe as today**: it authorizes on `state` alone, and
  header wiring only adds a reference to the vault entry the callback just
  wrote, for the route named in the pending record. It never accepts a header
  value from the request.
- **`prompt=consent` for Google** forces a consent screen on every connect,
  which is what guarantees a refresh token and makes a silent re-grant
  impossible.
- **Secrets**: the client secret and tokens stay in the vault (existing).
  Nothing new is logged; scope names are not secret.
- **Shared credential, said plainly**: the consent note and the portal warn
  that every agent using the route acts as the connected account.

## 6. Packaging & deploy

- No new modules: profiles live in `core/mcp_oauth.py`, already copied into
  `Dockerfile.admin`. No new dependencies.
- New env flag: `SHIELD_MCP_OAUTH_REQUIRE_SCOPE_CHOICE` (default on).
- Rebuild the admin image. The data plane needs no rebuild.
- Customer setup for Google, in the docs: a Google Cloud project with the
  Drive API and Drive MCP service enabled, an OAuth consent screen (Internal
  for a Workspace org; External apps in Testing get 7-day refresh tokens), a
  **Web application** client whose redirect URI is the deployment's
  `SHIELD_OAUTH_REDIRECT_URI`, and Developer Preview enrolment.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Google returns no refresh token | Cannot happen with `prompt=consent` in the normal path. If it does, status is `connected` with `refresh_token_held: false` and the expiry, and the portal says "will stop working at <time>; reconnect". Today this only logs a warning. |
| Refresh token revoked or expired (7 days in Testing) | Renewal fails permanently, status `error` with the provider's reason (existing); calls fail at the upstream with 401, visible in the gateway audit. |
| Operator picks a scope the server does not advertise | 422 naming the allowed ones. |
| Provider rejects the `resource` parameter | The profile turns it off (decided against Google in task 1); unknown providers keep sending it, as the MCP spec asks. |
| The route already has an `Authorization` header | Left as is; status says the brokered token is not in use. |
| Unknown provider without `offline_access` | Refused, as today. Adding its row to the profile table is the fix. |
| Discovery documents unreachable | 502, as today. |
| User removes Shield's access at the provider | Next renewal fails, status `error`. |

## 8. Test plan (Definition of Done)

- Discovery and checks against **recorded Google responses** (the live
  documents fetched on 2026-10-04): profile `google` selected; `check_brokerable`
  passes without `offline_access`; resource scopes kept in `available_scopes`.
- Authorize URL for `google`: chosen scopes, `access_type=offline`,
  `prompt=consent`, PKCE, no `offline_access`. For `standard`: unchanged except
  `resource` when published.
- Scope choice: given and allowed, given and not advertised (422), omitted with
  advertised scopes (422), omitted with none advertised (today), escape hatch.
- Callback: exchange stores the refresh token; the header is wired when absent
  and left alone when present; `refresh_token_held` reflects the response.
- Regression: every existing broker and credential-mode test passes unchanged;
  a pre-change record (no `profile`) renews exactly as before.
- Portal: pure functions for the scope list and status text, tested under node.
- Live check before merge: a test Google Cloud project connected to
  `drivemcp.googleapis.com` through a local admin plane, `tools/list` and one
  read through `/gateway/{route}/mcp`, then a forced renewal.
- Full suite green in a clean venv; CI passes.

## Tasks (one commit each)

1. **Broker profiles and scopes.** Profile table, Google row, scope choice and
   validation, `resource` handling, status fields. Tests against recorded Google
   metadata. Done. Notes from building it:
   - Google answers on the RFC 8414 path Shield tries first, and that document
     has **no** `scopes_supported`. Shield then uses the Drive server's own
     scopes, so for Google no `openid`/`email` is added; the request is exactly
     the chosen Drive scope(s), which is all Drive needs.
   - `resource`: an authorize probe with a dummy client cannot settle it (Google
     rejects the client first). Sent for Google on the inference that Google
     documents Claude, an MCP-spec client that sends `resource`, as supported.
     One switch in the profile table turns it off if task 4's live connect
     disagrees.
   - Token exchange and refresh send `resource` too, per the record's profile;
     records written before this change send exactly what they did.
2. **Callback wiring.** Header set when absent, `refresh_token_held`, status
   text. Tests.
3. **Portal.** Connect with OAuth panel and status. Node tests.
4. **Docs and the live check.** Google setup guide (customer-facing, no em
   dashes) and the end-to-end check against Google's Drive MCP server.
