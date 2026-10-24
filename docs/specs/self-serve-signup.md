# Spec: self-serve sign-up and email-link sign-in

Status: APPROVED 2026-10-24 (open mode, Resend). Tasks 1 and 2 built.

## 1. Problem and outcome

A new customer cannot start alone. A tenant exists only once an operator calls
`POST /v1/admin/tenants` and hands over a key. The portal (`static/tenant.html`)
offers sign-in only: SSO, or an existing API key. There is no sign-up page,
route or trial (checked 2026-10-23: no sign-up in `static/`, `api/`, or the
docs, apart from Rafay's own customers).

**Outcome.** On `shield.votal.ai`, a person:

1. enters a work email, an organisation name, and passes a captcha;
2. clicks the link emailed to them (sent through Resend);
3. lands in the portal, signed in as the admin of a new **trial** tenant with
   the `general` policy template in monitor mode;
4. mints their own keys on the portal's existing key page;
5. signs in later with an emailed link: no password is stored anywhere.

Customers without SSO get a sign-in that is not a shared API key.

**Additive only.** SSO (OIDC) and API-key sign-in stay exactly as they are; this
adds a way in. Shield has no SAML: a customer whose identity provider only
speaks SAML connects through Votal's Keycloak, which brokers SAML to OIDC.

**Non-goals.**
- Payments and plan upgrades (an operator converts a trial).
- Passwords.
- Inviting team members (follow-up; section 9).
- SCIM.
- Sign-up on the data plane.

## 2. Plane and latency contract

- **Admin plane** (`admin_app.py`, `shield.votal.ai`): everything new, namely
  the sign-up and verify routes, email-link sign-in, the operator list and the
  portal UI. Off the hot path.
- **Data plane, one in-memory check:** an expired trial's keys are refused.
  The auth middleware already holds the tenant's config
  (`core/middleware.py`, `_tenant_cache`), so the check is a comparison
  against a timestamp in that dict.
  - No store read and no added latency for anyone else.
  - Quotas need nothing new: `effective_quota` and `check_and_increment`
    already enforce the trial's numbers.

## 3. Data model

All keys hash the email or the token; no plaintext email is used as a key.

| Key | Value | TTL |
|---|---|---|
| `signup:pending:{sha256(token)}` | `{email, org, ip, created_at}` | 24 h, deleted on use |
| `signup:email:{sha256(email)}` | `tenant_id` (one trial per verified email) | none |
| `signup:rate:ip:{ip}:{yyyymmdd}` | counter | 2 days |
| `signup:rate:domain:{domain}:{yyyymmdd}` | counter | 2 days |
| `signup:rate:all:{yyyymmdd}` | counter (platform-wide new trials) | 2 days |
| `tenantmembers:{tenant_id}` (hash) | `sha256(email)` -> `{email, role: admin, created_at}` | none |
| `membertenants:{sha256(email)}` (set) | tenant ids this email may sign in to | none |
| `emaillink:{sha256(token)}` | `{tenant_id, email_hash, created_at}` | 15 min, single use |

**New tenant record fields:**
- `plan: "trial"`;
- `trial: {"expires_at": epoch, "created_via": "self_signup", "email_domain": "..."}`;
- the trial quota.

The tenant id is a slug of the organisation name (lowercase, `[a-z0-9-]`, at
most 40 characters) plus `-` and 6 random characters, checked for collisions.

**Tenant scoping:** the tenant comes from the verified token or the session,
never from the request body.

## 4. API and interface (admin plane)

| Method and path | Auth | Body or answer |
|---|---|---|
| `GET /v1/signup/config` | none | `{"mode": "off\|open", "captcha_site_key"}` |
| `POST /v1/signup` | captcha | `{email, org, captcha_token}` -> always `202 {"status": "check_your_email"}`, so it never reveals whether an email is known |
| `GET /v1/signup/verify?token=` | token | A page with a **Continue** button that POSTs the token (email link scanners fetch GET links; a GET must not use the token) |
| `POST /v1/signup/verify` | token | Creates the tenant, sets the portal session cookie, `303` to `/tenant` |
| `POST /v1/tenant/auth/email-link` | captcha | `{email}` -> always `202`; emails a sign-in link if the email is a member of any tenant |
| `GET` / `POST /v1/tenant/auth/email-link/confirm` | token | Same GET-page-then-POST pattern; creates a portal session (`issuer: "votal-email-link"`, `sub: "email:" + sha256(email)`) |
| `GET /v1/admin/signups?limit&cursor` | admin | Recent self-serve tenants: org, email domain, created, expires, usage today |

- **Converting a trial** uses the existing `PUT /v1/admin/tenants/{id}` with
  `{"plan": "basic"}`. The update clears `trial` when the plan is not
  `trial`.
- **Keys:** the existing `POST /v1/tenant/me/api-keys` already lets a
  signed-in portal admin mint keys, at most 10 a tenant. A trial needs nothing
  new there.

**Emails** come from `core/email_resend.py`:
- `POST https://api.resend.com/emails` with `Authorization: Bearer $RESEND_API_KEY`;
- the sender is `SHIELD_SIGNUP_FROM`, for example
  `Votal Shield <noreply@votal.ai>`, on a domain verified in Resend;
- a plain-text and an HTML body, and no tracking pixels.

**Portal:** the sign-in card gains **Create an account** and **Email me a
sign-in link**. After sign-up, a first-run panel says "Make your first key"
and links to the key page and the quickstart.

## 5. Security and backward compatibility

| Setting (env) | Default | Meaning |
|---|---|---|
| `SHIELD_SELF_SIGNUP` | **`off`** | `open`: anyone can sign up. Votal sets `open` on production. With `off`, the routes answer 404 and the portal hides the form, so existing deployments are unchanged |
| `SHIELD_SIGNUP_TRIAL_DAYS` | 30 | Length of a trial |
| `SHIELD_SIGNUP_TRIAL_REQUESTS_PER_DAY` | 5000 | Trial daily request quota |
| `SHIELD_SIGNUP_TRIAL_TOKENS_PER_DAY` | 2000000 | Trial daily token quota |
| `SHIELD_SIGNUP_DAILY_CAP` | 100 | New trials a day, platform-wide; then sign-up answers "try tomorrow" |
| `SHIELD_SIGNUP_PER_IP_DAY` / `_PER_DOMAIN_DAY` | 3 / 3 | Sign-ups a day from one IP / one email domain |
| `RESEND_API_KEY`, `SHIELD_SIGNUP_FROM` | none | Required for `open`; without them sign-up is unavailable (503) |
| `HCAPTCHA_SECRET_KEY` | none | **Required** for `open`. The existing `/verify-captcha` lets everything through when it is unset; sign-up does not: no secret means sign-up is unavailable (503) |

The per-minute limit stays at the platform floor of 10,000
(`SHIELD_MIN_REQUESTS_PER_MINUTE`), which exists because a low per-minute limit
broke a customer's agents. Trials are limited per day instead.

**Threats and answers:**

| Threat | Answer |
|---|---|
| Bots creating thousands of tenants | Server-verified captcha (fail closed), per-IP and per-domain limits, the platform-wide daily cap, an email that must be verified before anything exists |
| Abuse of Votal's model spend | Daily request and token quotas, 30-day expiry, the daily cap, the operator list to suspend |
| Account enumeration | Sign-up and email-link sign-in always answer 202 with the same body and similar timing |
| Link scanners consuming one-time links | GET shows a page; only the POST from that page uses the token |
| Stolen or replayed links | Tokens are 32 random bytes, stored only as a hash, single use, short-lived (verify 24 h, sign-in 15 min), bound to the email they were sent to |
| Disposable emails | A built-in list of disposable domains is refused (a data file, no new dependency) |
| Open redirect after sign-in | Redirects go to `/tenant` only |
| Signing in to someone else's tenant | An email-link session is for a tenant the email is a member of (`membertenants`); the tenant comes from the token, never from the request |
| A trial reaching another tenant's data | A trial is an ordinary tenant: the existing tenant isolation applies unchanged |
| A runtime key lowering the guard | Unchanged: the write-scope gate applies to trial tenants as to any other |

**Sign-in under `require_sso`:** an email-link session is a portal session, as
SSO's is. A tenant that sets `require_sso` keeps email-link sign-in only if its
operator allows it (decided in task 3: email links count as SSO for that check
unless `require_sso: "idp"`).

## 6. Packaging and deploy

- **New modules, all on the admin plane:**
  - `api/routes_signup.py`;
  - `api/routes_email_link.py`;
  - `core/email_resend.py`;
  - `storage/signup_store.py`;
  - `core/signup/disposable_domains.txt`.

  **Every one must be COPYed into `Dockerfile.admin`**, or the admin image
  crash-loops; `tests/test_admin_dockerfile_imports.py` enforces it.
  `core/policy_templates.py`, which the sign-up uses to apply the `general`
  template, must be COPYed too: today only the data plane has it.
- **Dependencies:** none new. `httpx` is already in `requirements.txt`,
  `requirements-admin.txt` and the test requirements.
- **Images:** the admin image (all new routes) and the data plane image (the
  trial-expiry check in `core/middleware.py`).
- **Environment** (section 5): `SHIELD_SELF_SIGNUP=open`, `RESEND_API_KEY`,
  `SHIELD_SIGNUP_FROM`, `HCAPTCHA_SITE_KEY`, `HCAPTCHA_SECRET_KEY`, and
  `SHIELD_PORTAL_BASE_URL` (already needed for SSO; email links are built
  from it).

## 7. Failure modes and edge cases

| Case | Behaviour |
|---|---|
| Resend down or rejecting | Sign-up answers 503 "could not send the email, try again"; nothing is created (the pending record is deleted) |
| Redis down | Sign-up and email-link sign-in answer 503 (fail closed); existing keys keep working |
| The same email signs up twice | Before verifying: a new link replaces the old. After: "check your email" and a sign-in link to the existing tenant, not a second trial |
| A link used twice, or expired | A page that says so, with a button to send a new one |
| Organisation name empty, huge or unicode | 1 to 80 characters kept for display; the slug falls back to `org` |
| Two verifications race | The token is consumed with an atomic GETDEL; the loser sees "already used" |
| Trial ends | Keys answer 402 `trial_ended` with "contact Votal to continue"; the portal still signs in and shows the banner; data is kept |
| The daily cap is reached | 429 "sign-ups are paused for today" |
| Captcha not configured while `open` | 503; the portal shows "sign-up is not available" |

## 8. Test plan (definition of done)

Per task:

- **Unit tests:**
  - token hashing, single use, expiry;
  - each rate limit and the daily cap;
  - disposable domains;
  - slug generation and collisions.
- **Route tests** with Resend and hCaptcha faked at the HTTP layer:
  - a full sign-up, from the email to the tenant, session and template, with
    trial quotas set;
  - enumeration: the same answer for known and unknown emails;
  - a GET verify does not consume the token;
  - captcha unset or Resend unset means 503;
  - `off` means 404;
  - one trial per email.
- **Email-link sign-in:**
  - a member gets a link, a stranger gets the same 202 and no email;
  - the session is for the right tenant;
  - the token works once;
  - the 15-minute expiry.
- **Data plane:** an expired trial's key gets 402 with no store read (patch
  the store to fail); a converted tenant's key works.
- **Regression:**
  - `tests/test_admin_dockerfile_imports.py` passes with the new modules;
  - `tests/test_portal_session_auth.py` (the SSO tripwire) stays green;
  - the full suite passes in a clean venv;
  - CI passes.
- **Portal:** checked in the browser preview: create an account, the "check
  your email" page, the verify page, the first-run panel, email-link sign-in.

## 9. Tasks (one PR each, in order)

| Task | Scope |
|---|---|
| 1 | `core/email_resend.py` (Resend client, plain and HTML, no tracking) and `storage/signup_store.py` (pending sign-ups, tokens, rate counters, member index); unit tests |
| 2 | Sign-up: `GET /v1/signup/config`, `POST /v1/signup`, verify GET page and POST; trial tenant with template and quotas, admin member, portal session; captcha and Resend fail closed; disposable list; `Dockerfile.admin` |
| 3 | Email-link sign-in for members (request, confirm page, session); the `require_sso` rule |
| 4 | Portal UI: create an account, check your email, email-link sign-in, first-run "make your first key"; the key dialog asks what the key is for (an app gets a runtime key, the default; settings automation the current unscoped key); browser-checked |
| 5 | Trial lifecycle: the trial-expiry check on the data plane (in memory), `GET /v1/admin/signups`, conversion clears `trial`, a trial banner in the portal; customer docs page |

Found while building task 2: `core/security_headers.py` rewrote each
`Set-Cookie` by assignment, so a response setting two cookies kept only the
last. Sign-up's confirm sets the session and clears its nonce; fixed in
task 2 (append, not assign), with a test.

Follow-ups, not in this spec:
- inviting team members by email;
- reminder emails before a trial ends;
- self-serve upgrade and payment.
