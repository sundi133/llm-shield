# Spec: password sign-in for the tenant portal

Status: DRAFT, awaiting approval.

## 1. Problem and outcome

People sign in to the tenant portal with SSO, an emailed one-time link, or a
tenant API key. Customers without an identity provider want what every other
product has: an email address and a password. Today the only way in for them
is the emailed link (slow, needs the inbox open each time) or an API key
(meant for machines, shared, no person attached).

There is also no way to add a second person: a workspace's only member is
whoever signed it up.

**Outcome.**
- The sign-in page offers **Email and password** first, then SSO, the emailed
  link and an API key, as today.
- A workspace admin **invites people** by email from a new **People** page,
  as an admin or a viewer. The invitee sets their own password from an
  emailed link. Nobody ever types or sees another person's password.
- **Forgot password** sends a reset link. Changing or resetting a password
  signs that person out everywhere else.
- Passwords are stored only as salted, slow hashes, and guessing is limited
  per account and per address.

**Non-goals (this spec):**
- **Two-factor authentication (TOTP).** Planned as the next spec; the record
  below leaves room for it. Recommended before selling password sign-in to
  enterprises.
- **Operator (admin console) passwords.** Operators keep SSO and the admin key.
- **Replacing SSO.** A workspace that requires SSO (operator flag
  `require_sso`, or `SHIELD_PORTAL_REQUIRE_SSO`) never offers passwords.
- **Checking passwords against breach databases online** (Have I Been Pwned).
  No outbound call; built-in rules refuse the commonly guessed ones instead.

## 2. Plane and latency contract

- **Plane:** admin only (`admin_app.py`, `shield.votal.ai`). The data plane
  is unchanged.
- **Guard path:** untouched (`/guardrails/*`, `cap/mint`, `tools/call`). API
  keys keep working exactly as now.
- **Latency:** a sign-in costs one scrypt hash, about 50 to 100 ms of CPU, on
  the admin service only.

## 3. Data model

Identity is the **email address**, shared across workspaces, as the
email-link sign-in already does (`membertenants:{email_hash}`). One password
per person, whichever workspaces they belong to.

| Key | Value | TTL |
|---|---|---|
| `useracct:{email_hash}` | `{email, password: "scrypt$log2N$r$p$salt_b64$hash_b64", set_at, last_sign_in, lock_count}` | none |
| `pwdfail:{email_hash}` | wrong passwords since the last success or lockout (a single increment) | none |
| `pwdlock:{email_hash}` | `{n, until}` while locked; the deadline is in the record because the in-memory fallback keeps keys past their TTL | the lockout |
| `tenantmembers:{tenant_id}` (hash, exists) | adds `name`, `invited_by`, `status: invited\|active` to each member record; `role` is `admin` or `viewer` | none |
| `pwdlink:{sha256(token)}` | `{email, purpose: invite\|reset, tenant_id, expires_at}` | invite 7 days, reset 30 minutes |
| `pwdrate:ip:{ip_hash}:{15-min window}` | failed sign-ins from one address | 30 minutes |

- **Hashing:** `hashlib.scrypt` from the standard library (no new
  dependency): N=2^15, r=8, p=1, 16-byte random salt, 32-byte key. The
  parameters are stored with each hash, so they can be raised later and
  old hashes upgraded at the next sign-in.
- **Links:** 32 random bytes, only the sha256 stored, used once, like the
  sign-up and email-link tokens (`storage/signup_store.py`).
- **Sessions:** the same portal session as SSO and the emailed link, with
  subject `email:{email_hash}`, so `revoke_all_for_subject` signs a person
  out of every session, whichever way they signed in.

## 4. API and interface (admin plane)

**Sign-in, unauthenticated (rate limited, answers never say which part was wrong):**

| Method and path | Purpose |
|---|---|
| `POST /v1/tenant/auth/password` `{email, password, tenant_id?}` | Verify. One workspace: a portal session (cookie) and `/tenant`. Several: the list of workspace names to choose from, only after the password verified; the client posts again with `tenant_id`. Wrong email or password: `401 {"error": "Email or password is incorrect"}` |
| `POST /v1/tenant/auth/password/forgot` `{email, captcha_token}` | `202`, always the same answer; an email goes only to a member of a workspace that accepts passwords, with a password or not, so someone who has only used SSO links can set their first |
| `GET /v1/tenant/auth/password/set?token=` | A page to choose a password (invite or reset); consumes nothing |
| `POST /v1/tenant/auth/password/set` `{token, password}` | Set it, sign out every other session, sign in |

**Signed-in person:**

| Method and path | Purpose |
|---|---|
| `POST /v1/tenant/me/password` `{current_password, new_password}` | Change it; signs out every other session |

**Workspace admin (portal session with `is_admin`, or a settings key):**

| Method and path | Purpose |
|---|---|
| `GET /v1/tenant/me/people` | Members: email, name, role, status, has a password, last sign-in |
| `POST /v1/tenant/me/people` `{email, name?, role}` | Invite: adds the member as `invited` and emails a link to set a password (7 days) |
| `POST /v1/tenant/me/people/{email_hash}/resend` | A new invite link; the old one stops working |
| `PUT /v1/tenant/me/people/{email_hash}` `{role}` | Change the role |
| `DELETE /v1/tenant/me/people/{email_hash}` | Remove: membership gone, that person's sessions in this workspace revoked |
| `PUT /v1/tenant/me/sign-in-methods` `{passwords: true\|false}` | Whether this workspace accepts passwords (default true) |

Writes go through `require_registry_write`. A workspace keeps at least one
admin: removing or demoting the last one is refused.

**Password rules** (NIST SP 800-63B): 12 to 128 characters, any characters,
no composition rules. Refused, with the reason: one or two distinct
characters, a part repeated over and over, a commonly guessed word padded
with digits and symbols (`Password1234!`, `Summer2024!!!`), a keyboard row or
a sequence (`qwertyuiopas`, `123456789012`), the email's name part, or a
workspace's name. (Built-in rules instead of a downloaded list: with a
12-character minimum, almost every entry in the usual 10,000-password lists
is already too short. A full breached-password list can be added later.)

**Guessing limits:**
- **Per account:** after 5 wrong passwords in a row, locked for 15 minutes,
  doubling each further lockout up to 24 hours. A correct password or a reset
  clears it. The lockout answer is the same `401` text, so it does not confirm
  the account exists; the person is emailed that their account was locked,
  with a reset link.
- **Per address:** 20 wrong sign-ins in 15 minutes from one IP gives `429`.
- **Captcha:** when hCaptcha is configured, required after 3 failures from an
  address, as sign-up does.
- **Timing:** an unknown email is checked against a dummy hash, so a reply
  takes as long either way.

**Sign-in page (`/tenant`):** Email and Password first, with **Forgot
password?**. Below: Organisation + **Continue with SSO**, **Email me a
sign-in link**, **Use an API key instead**, **Create an account**, as today.
If the deployment turns passwords off, the page is as today.

**Portal:** a **People** page (in the new sidebar, under Identity & Access,
admins only): list, invite, resend, change role, remove; and a **Change
password** item in the account menu.

**Sign-up:** a new self-serve workspace's admin chooses a password on the
confirm page (optional; the emailed link keeps working).

## 5. Security and backward compatibility

- **Additive.** SSO, the emailed link and API keys are unchanged. Nobody has
  a password until they set one through an emailed link, so turning the
  feature on exposes no account.
- **Escape hatches:**
  - `SHIELD_PORTAL_PASSWORDS=off`: the deployment offers no password sign-in
    (routes `404`, the form hidden). Passwords stay stored for when it is on
    again.
  - per workspace, `passwords: false` in **Sign-in methods**;
  - a workspace with `require_sso` never offers passwords.
- **Viewer role:** a session with `is_admin` false reads the portal and is
  refused every write. Invited people default to viewer.

  The existing write gates (`_require_scoped_write` in `core/auth.py`)
  return early when `SHIELD_REGISTRY_WRITE_SCOPE` / `SHIELD_CONFIG_WRITE_SCOPE`
  are `off`, the default, so today a non-admin session can write on most
  deployments. A viewer role that only works under `enforce` would be
  decorative. So the gate refuses a non-admin session **whose issuer is
  Shield itself** (password or emailed link) in every mode. Non-admin SSO
  sessions keep today's behaviour (refused only under `warn`/`enforce`), so
  no existing deployment changes. No Shield-issued non-admin session exists
  today: every emailed-link member is the admin who signed up.
- **Never in logs or audit:** passwords, hashes, tokens. The audit records
  sign-in success and failure (email hash, address), lockouts, invites,
  role changes, removals, password changes and resets.
- **Emails** come from the existing Resend sender, and links use
  `SHIELD_PORTAL_BASE_URL`, never the request's host.
- **Session fixation:** a new session id at every sign-in (existing
  `create_session`). Cookie as SSO's: HttpOnly, Secure, SameSite=Lax.
- **CSRF:** the sign-in and set-password forms carry the same nonce cookie
  check as the email-link confirm page.

## 6. Packaging and deploy

- **New modules:** `api/routes_password_auth.py` (sign-in, forgot, set,
  change), `api/routes_people.py` (People), `storage/user_accounts.py`
  (accounts, hashing, lockout, links). Each must be COPYed into
  `Dockerfile.admin`;
  `tests/test_admin_dockerfile_imports.py` guards it.
- **Auth middleware:** `/v1/tenant/auth/password` is self-authenticating,
  like `/v1/tenant/auth/email-link`; listed in OPEN_BY_DESIGN with the reason.
- **Dependencies:** none (`hashlib.scrypt`, `secrets`, `hmac`).
- **Env:** `SHIELD_PORTAL_PASSWORDS` (default `on`). Needs the existing
  `RESEND_API_KEY` and `SHIELD_PORTAL_BASE_URL` for invites and resets;
  without them, invites and resets are refused with the reason, and sign-in
  still works for people who already have a password.
- **Images:** the admin image only.

## 7. Failure modes and edge cases

| Case | Behaviour |
|---|---|
| Redis down | Sign-in `503`; never "wrong password" |
| Email not configured | Invite and forgot answer what is missing; existing passwords still sign in |
| Same email in 3 workspaces | One password; after it verifies, choose the workspace |
| Person removed from a workspace | Their sessions there end at once; the password still works for their other workspaces |
| Last admin removed or demoted | Refused (`409`) |
| Invite to an email already a member | `409` with "already a member" |
| Invite link used twice, or after 7 days | The page says it expired; ask for a new one |
| Workspace switched to `require_sso` | Password sign-in refused for it; people use SSO |
| Trial suspended | Sign-in refused, as the emailed link is |
| Unicode in a password | NFKC-normalised before hashing (NIST) |
| Two sign-ins racing on a locked account | Both refused; the counter is a single Redis increment |

## 8. Test plan (definition of done)

- **Hashing:** scrypt round trip; a wrong password fails; hashes differ for
  the same password (salt); old parameters are upgraded on sign-in;
  `hmac.compare_digest` used.
- **Sign-in:** one workspace gives a session; several gives the choice only
  after the password verified; unknown email and wrong password give the same
  answer and similar time; trial suspended and `require_sso` refused;
  `SHIELD_PORTAL_PASSWORDS=off` gives `404`.
- **Limits:** lockout after 5, doubling, cleared by success or reset; IP `429`
  after 20; captcha after 3 when configured.
- **Rules:** length, common list, email and workspace name rejected, with
  reasons.
- **Links:** invite and reset work once, expire, and only their hash is
  stored; reset and change revoke other sessions.
- **People:** invite, resend (old link dead), role change, remove (sessions
  ended), last-admin guard, another tenant's member is `404`.
- **Viewer:** a password viewer is refused a registry write and a config write
  with both gates `off`; a non-admin SSO session under `off` still writes
  (unchanged); an admin password session writes.
- **Never logged:** no password, hash or token in audit rows or logs.
- **Regression:** SSO, email-link and API-key sign-in unchanged
  (`tests/test_portal_session_auth.py` stays green); the image import guard;
  OPEN_BY_DESIGN; full suite in a clean venv; CI.
- **Browser preview:** invite a person, open the emailed link (printed by the
  preview), set a password, sign out, sign in with it, lock the account with
  wrong passwords, reset it, remove the person.

## 9. Tasks (one PR each, in order)

| Task | Scope |
|---|---|
| 1 | `storage/user_accounts.py` (hashing, accounts, lockout, links, common-password list) and `POST /v1/tenant/auth/password` sign-in; auth exemption; `Dockerfile.admin`; tests |
| 2 | Set and reset by emailed link (`forgot`, `set`), change password, sessions revoked on change; sign-up's optional password; tests |
| 3 | People: invite, resend, role, remove, last-admin guard, viewer role enforced; sign-in methods setting; tests |
| 4 | UI: the sign-in page's Email and Password form, Forgot password, set-password page, People page, Change password; browser-checked |
| 5 | Docs: for customers (inviting people, passwords, resetting) and operators (`SHIELD_PORTAL_PASSWORDS`, what is audited) |

**Next spec:** two-factor authentication (TOTP), and optionally requiring it
per workspace.
