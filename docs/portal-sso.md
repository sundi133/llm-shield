---
title: Portal SSO
layout: default
nav_order: 49
permalink: /portal-sso/
description: "Sign in to the tenant portal through your own IdP, so administrative actions name the person who took them instead of a shared API key. Setup for Keycloak, Okta and Entra, the rollout order, and what this does not fix."
---

# Portal SSO
{: .no_toc }

The portal signs in with a shared tenant API key, so the audit records
`tenant:acme` for every administrative action. That answers **which
organisation**, not **who** - and "who granted this agent production
credentials" is the first question of an access review.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## What it changes

| | before | after |
|---|---|---|
| Admin audit actor | `tenant:acme` | `user:d7662896-…` with the email recorded |
| Registry entries | no creator | `created_by` / `updated_by` |
| Access review | reviewer taken from the request body | the authenticated reviewer |
| Credential | one key, shared, in browser storage | a session per person, revocable |

**Entirely opt-in, per tenant.** A tenant with no OIDC provider sees the same
login screen and the same behaviour as before. API keys keep working on every
route they work on today, including for tenants that enable SSO - turning it on
must not lock out a CI job that has been posting to the registry for a year.

## Before you start

Two things Shield needs, and one it refuses without.

**`SHIELD_PORTAL_BASE_URL`** - the externally visible URL of the deployment,
used to build the `redirect_uri` your IdP has registered. It is never inferred
from the `Host` or `X-Forwarded-Proto` headers: behind Railway, an ingress or
any TLS-terminating proxy the app sees plain HTTP while the browser sees
HTTPS, so an inferred value would be `http://` and your IdP would reject the
mismatch. Inferring it would also mean trusting a header to build a
security-relevant URL.

```
SHIELD_PORTAL_BASE_URL=https://shield.example.com
```

**`admin_groups`** - the group or role values that grant portal administration.
Shield **refuses to run a login** for a provider that has none, rather than
treating an empty list as "everybody". Connect SSO without it and every account
in your directory could write the agent registry; refusing at login is louder
than a warning in a log nobody reads, and the fix is one field.

**A private CA, if your IdP uses one.** See
[the on-premises guide](/on-premises-deployment-guide/#portal-sso-and-your-internal-ca).
Skip it if `openssl s_client` already verifies your IdP.

## Keycloak

The redirect URI must match exactly, including scheme and port.

**1. Create a client.** Realm → Clients → Create:

| | |
|---|---|
| Client ID | `shield-portal` |
| Client authentication | **Off** (public client) |
| Standard flow | On |
| Valid redirect URIs | `https://shield.example.com/v1/tenant/auth/callback` |
| Web origins | `https://shield.example.com` |

A public client is correct here. Shield uses PKCE, so no client secret needs to
exist at all - one fewer credential to store, rotate and leak. Set
`client_secret` only if your Keycloak policy mandates a confidential client.

**2. Create the admin group,** e.g. `shield-admins`, and put your
administrators in it.

**3. Add a groups mapper.** This is the step that is easy to miss and produces
a login that works while nobody is ever an administrator:

Clients → `shield-portal` → Client scopes → `shield-portal-dedicated` → Add
mapper → By configuration → **Group Membership**

| | |
|---|---|
| Name | `groups` |
| Token Claim Name | `groups` |
| Full group path | **Off** |
| Add to ID token | **On** |

Full group path off matters: with it on the claim is `/shield-admins`, and an
`admin_groups` of `["shield-admins"]` will never match.

**4. Register it with Shield:**

```bash
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' -d '{"name":"keycloak","issuer":"https://keycloak.example.com/realms/shield","client_id":"shield-portal","admin_groups":["shield-admins"],"groups_claim":"groups"}' "$SHIELD/v1/admin/oidc-providers/acme"
```

The response tells you whether it is usable:

```json
{"status":"registered","admin_groups":["shield-admins"],"portal_login_ready":true}
```

`portal_login_ready: false` means `admin_groups` is empty and logins will be
refused.

## Okta

Create an **OIDC → Single-Page Application** (public client, PKCE), sign-in
redirect URI `https://shield.example.com/v1/tenant/auth/callback`.

Okta does not emit groups by default. Add a **Groups claim** to the ID token
on the authorization server: Security → API → your server → Claims → Add,
name `groups`, include in **ID Token**, value type Groups, filter Matches
regex `.*`.

```bash
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' -d '{"name":"okta","issuer":"https://YOUR.okta.com/oauth2/default","client_id":"0oa...","admin_groups":["ShieldAdmins"],"groups_claim":"groups"}' "$SHIELD/v1/admin/oidc-providers/acme"
```

## Microsoft Entra ID

Register an application, add a **Single-page application** redirect URI, and
under Token configuration add a **groups claim** for the ID token.

Entra emits group **object IDs**, not names, unless you enable group name
emission for groups synced from on-prem AD. So `admin_groups` normally holds
GUIDs:

```bash
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' -d '{"name":"entra","issuer":"https://login.microsoftonline.com/TENANT_GUID/v2.0","client_id":"APP_GUID","admin_groups":["8a1b...GUID"],"groups_claim":"groups"}' "$SHIELD/v1/admin/oidc-providers/acme"
```

If you prefer roles to groups, define app roles and set
`"groups_claim": "roles"`.

## Rollout

Declare first, enforce second. The same ladder as the other controls in Shield.

**1. Register the provider.** Nothing changes: the login screen gains a "Sign
in with SSO instead" link and the API key path is untouched.

**2. Have your administrators sign in once.** Confirm the header shows their
name and not `· read only` - that badge means the group claim did not match,
which is almost always the Keycloak full-path setting or a missing Okta claim.

```bash
curl -s -H "Cookie: shield_portal_session=..." "$SHIELD/v1/tenant/me/session"
```

**3. Watch the audit change shape.** New administrative actions should now
record `user:{sub}`. Old records keep their `tenant:` actor; nothing is
rewritten.

**4. Optionally require SSO.** `SHIELD_PORTAL_REQUIRE_SSO=1` refuses API key
authentication on portal routes. Do this only after step 2, and remember that
any automation calling `/v1/tenant/*` with a key stops working.

Sessions last 8 hours by default (`SHIELD_PORTAL_SESSION_TTL`). An idle timeout
is available and off by default (`SHIELD_PORTAL_SESSION_IDLE`, seconds) - it is
what regulated deployments are asked for, and also what logs people out
mid-task, so it is a choice rather than a default.

## What this does not fix

Worth saying to a customer before they discover it.

**An admin key in a browser is still an admin key.** SSO does not remove the
API key path unless you set `SHIELD_PORTAL_REQUIRE_SSO=1`, and a tenant that
puts an admin-scoped key into a deployed agent's environment has opted back
into the shared-credential model.

**A demotion is not instant.** Whether someone is an administrator is captured
at login and lives in the session, so removing them from the group takes effect
at their next login, or immediately if you revoke their sessions. The session
TTL bounds the window. Re-reading groups on every request would mean a
JWKS-backed lookup on every portal call.

**This is not per-user authorization.** There is one distinction - may
administer, or may only read. Finer-grained portal roles are not implemented.

**No SCIM.** Users are not provisioned or deprovisioned automatically. A person
removed from your directory cannot obtain a new session, but an existing one
lives until it expires or is revoked.

## Troubleshooting

**The SSO button never appears.** The tenant has no provider, or you typed the
wrong tenant id. Check directly:

```bash
curl -s "$SHIELD/v1/tenant/auth/providers?tenant=acme"
```

**503, "has no admin_groups configured".** Working as intended. Re-register
with `admin_groups` set.

**500, "SHIELD_PORTAL_BASE_URL is not set."** Set it to the URL the browser
uses, not an internal one.

**The IdP rejects the redirect URI.** It must match byte for byte, including
scheme and port. Behind a proxy this is nearly always `http` vs `https`, which
is exactly why Shield takes the value from configuration.

**Signed in, but badged `· read only`.** Authentication worked and the group
claim did not match. Decode the ID token and look at the claim your
`groups_claim` names. On Keycloak this is usually **Full group path** left on,
producing `/shield-admins` where you configured `shield-admins`.

**Sign-in appears to work and lands back on the login screen.** The session
cookie was not stored. Over plain HTTP the `Secure` flag prevents it; that is
correct, and `SHIELD_PORTAL_INSECURE_COOKIE=1` exists for local development
only.

**`certificate verify failed`.** Your IdP uses a private CA. See
[the on-premises guide](/on-premises-deployment-guide/#portal-sso-and-your-internal-ca).

## Trying it locally

A complete local setup, verified end to end. Keycloak on 8081, Shield on 8080.

```bash
docker run -d --name keycloak -p 8081:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HOSTNAME=http://localhost:8081 -e KC_HOSTNAME_STRICT=false quay.io/keycloak/keycloak:26.0 start-dev
```

```bash
docker run -d --name shield-admin-local -p 8080:8080 --add-host=localhost:host-gateway -e SHIELD_PORTAL_BASE_URL="http://localhost:8080" -e SHIELD_PORTAL_INSECURE_COOKIE=1 -e SHIELD_ADMIN_KEY="$ADMIN_KEY" shield-admin
```

`--add-host=localhost:host-gateway` is the part that makes this work. OIDC
needs **one** issuer string that resolves identically from the browser and from
inside the Shield container. Remapping `localhost` inside the container makes
`http://localhost:8081/realms/shield` mean Keycloak for both, with no
`/etc/hosts` edit.

Docker Desktop's `--network host` does **not** work here: on macOS the
container joins the VM's network namespace, so published ports stop working and
the browser can no longer reach Shield.

Then create the realm, client, group, user and groups mapper as above, register
the provider, and sign in at `http://localhost:8080/tenant`.
