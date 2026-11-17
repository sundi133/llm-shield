---
title: "AI Agent Detection: partner integration guide"
layout: default
nav_exclude: true
search_exclude: true
permalink: /agent-detection-integration/
description: "How a customer connects Shield's AI agent detection: a read-only SIEM connection, watch mode then enforcement through their own firewall or CDN, and the optional page tag, Web Bot Auth and decoys."
---

# AI Agent Detection: partner integration guide
{: .no_toc }

> **Design preview.** This guide describes the integration as designed. The
> feature is in development and not yet generally available. Page names,
> endpoints and fields may change before release. Talk to your Votal contact
> before planning a customer rollout.

AI agents now sign up, log in, redeem promotions and check out the way people
do, often as a fleet: one controller running hundreds of browsers in sandboxes,
each on its own home IP. Rate limits, IP reputation and bot managers see
nothing unusual in any single session.

Shield reads the logs your customer already sends to their SIEM, finds the AI
agents and the fleets behind them, and hands the result to the firewall or CDN
they already run.

![Visitors, the customer's website, their SIEM, Shield, and their firewall or CDN, left to right]({{ "/assets/images/agent-detection-overview.png" | relative_url }})

1. TOC
{:toc}

## What the customer installs

| Step | Required | Effort | What changes on the customer's side |
|---|---|---|---|
| [1. Connect the SIEM](#1-connect-the-siem) | yes | about an hour | a read-only SIEM account |
| [2. Watch, then enforce](#2-watch-then-enforce) | no | a firewall or SOAR rule | nothing until they switch to enforce |
| [3. Add the page tag](#3-add-the-page-tag-or-mobile-sdk) | no | one script line, one CDN route, one log field | the tag on protected pages |
| [4. Edge add-ons](#4-edge-add-ons) | no | CDN configuration | a setting and a rule set at the edge |

**Shield is never in the customer's traffic path.** It runs on its own,
reads logs on a schedule, and never touches a live request. Pages load exactly
as fast as before, and if Shield is down the site is unaffected.

## Before you start

Collect these from the customer:

- **SIEM:** Splunk Enterprise Security, Microsoft Sentinel or Elastic Security,
  and which indexes or tables hold their web (CDN, load balancer or WAF) and
  login logs.
- **Protected routes:** the paths that matter, for example sign-up, login,
  password reset, promotions and checkout.
- **Their edge:** the CDN, WAF or reverse proxy in front of the site, and
  whether they use a SOAR tool.
- **An owner for enforcement:** the person who decides when watch mode ends.

## 1. Connect the SIEM

### Create a read-only account

Give it read access to the web, login and existing-alert data only.

| SIEM | What to create |
|---|---|
| Splunk | A role with search rights on the web and login indexes and `notable`, and a token for a user in that role |
| Microsoft Sentinel | An Entra ID app registration with **Log Analytics Reader** on the workspace, and a client secret |
| Elastic | An API key with `read` on the web and login indices and `.alerts-security.alerts-*` |

### Add the source in the portal

1. Open **AI Agent Detection**, then **Sources**, then **Add source**.
2. Pick the SIEM, paste the endpoint and the credential, and choose the
   protected routes.
3. Confirm the **field mapping**. Shield proposes one from a sample.
4. Click **Test source**.

The test runs the query once and shows:
- a mapped sample of rows;
- fields it could not map;
- which checks this source can support.

Shield runs a summarizing query **inside** the SIEM, one row per session, so
the data moved grows with sessions, not with events. Only protected routes are
read.

### Fields Shield uses

| Field | Used for | If it is missing |
|---|---|---|
| Timestamp, session or cookie id, path, method, status | timing, form filling, navigation, fleets | required |
| Client IP | networks, fleets | required |
| User agent | client traits, fleets | required |
| Request size, referrer | error-recovery and navigation checks | those checks are off |
| Client hints (`Sec-CH-UA`, `Sec-CH-UA-Platform`) | spotting a faked browser | that check is off |
| Account id, event type (sign-up, login, order) | low-history accounts, the clean-up list | account indicators are off |

### What the customer gets from this step alone

- **AI agent checks** built for agents, not scripts: the pause pattern of a
  model thinking between steps, forms filled at a steady pace, error-and-retry
  loops, a straight line to the goal, and browser traits that contradict the
  claimed browser.
- **Fleet detection:** sessions from many networks that share at least two
  independent traits (behavior, timing, device, start time) are grouped into
  one fleet. A shared office IP or a popular sign-up path alone never links
  sessions.
- **Detections in their SIEM:** if their SIEM already alerted on the same
  account, IP or session, Shield adds its evidence to that alert instead of
  raising a duplicate. Otherwise it raises a new detection.

## 2. Watch, then enforce

### Watch mode (the default)

Every new tenant starts in watch mode. Shield computes what it **would** block
and shows it in the portal and the shadow report ("would have challenged 140
later sessions"), but nothing reaches the customer's edge. Plan on one to two
weeks of watch mode on real traffic before enforcing.

### Switch to enforce

Enforcement is switched on **per indicator type**. A common order is session
challenges first and account actions last.

| Indicator | Matched by | Default action |
|---|---|---|
| Session id | the edge, by cookie | challenge |
| Tag session id (`_shs`, with step 3) | the edge, by cookie | challenge |
| Client fingerprint | WAF or bot manager rule | challenge |
| Network (/24) | WAF or edge | challenge, and only with fleet evidence |
| Account id | identity provider, through SOAR | review (suspend is opt-in) |

Shield never blocks traffic itself. The customer's tools act on the
indicators, in one of these ways:

**Pull feed (firewalls, CDNs, Nginx).** Create a tenant API key with the
`indicators:read` scope. That scope can read the feed and nothing else. Poll
every 60 seconds; `ETag` makes an unchanged poll cheap.

```bash
curl -sf -H "Authorization: Bearer $SHIELD_INDICATORS_KEY" \
  "https://<your-shield-host>/v1/agent-detection/indicators?format=nginx" \
  -o /etc/nginx/shield/indicators.map && nginx -s reload
```

`format` can be `json`, `csv` or `nginx` (a `map` file). The docs ship a
complete Nginx example that sends matching sessions to a challenge page.

**Webhooks (SOAR and automation).** Subscribe to `agent_fleet.indicators` and
`agent_fleet.ended`, signed like every other Shield webhook. The docs ship
example Splunk SOAR and Sentinel playbooks that flag or suspend fleet accounts
in the identity provider and open a case.

### Safety rules the customer can rely on

- **Only confident detections become indicators:** confirmed fleets and clear
  agents. Uncertain cases go to the SIEM for an analyst, never to the edge.
- **Popular devices are never blocked.** A fingerprint or network is published
  only if fewer than 0.1% of the customer's other sessions share it.
- **Established accounts are never included,** only new or low-history ones.
- **Everything expires.** Indicators last an hour and renew only while the
  fleet is active. Analysts can revoke one, and one switch clears them all.
- **The default action is a challenge, not a block.**

### Clean-up list

Each fleet detection lists what the fleet did: accounts created, promotions
redeemed, orders placed. The customer uses it to cancel orders and void
promotions in their own systems. Shield doesn't change them.

## 3. Add the page tag (or mobile SDK)

The tag sees how visitors click and type, which logs can't show: an agent
fills fields without key presses, clicks the exact center of every button and
never makes a typo. It also places hidden traps that only an AI reads and
obeys, and recognizes sandboxes started from one image.

### Install

1. **Get a site key** in the portal under **AI Agent Detection**, then
   **Tag**. Site keys are public, like a CAPTCHA site key; they can only send
   tag data.
2. **Add the script** to protected pages:

   ```html
   <script src="/_shs/shs.js?k=SITE_KEY" async></script>
   ```

3. **Route `/_shs/*` to the Shield collector** at the CDN or proxy, so the tag
   stays first-party and ad blockers treat it like the site's own code. Nginx
   example:

   ```nginx
   location /_shs/ {
       proxy_pass https://<your-shield-collector>;
   }
   ```

4. **Log the tag cookie.** Add `_shs` to the web log format so tag data joins
   the log rows. In Nginx, add `"shs":"$cookie__shs"` to the JSON log format.
   Without it Shield falls back to a weaker join on IP, user agent and time.

**Mobile apps** use the Android or iOS SDK instead: same site key, same
collector. The SDK passes through the Play Integrity or App Attest verdict the
customer's backend already checks, and adds emulator and touch signals.

### What the tag collects, and what it never does

- **It collects** counts, timings and hashes: key and click counts, how far
  clicks land from the center, typing rhythm, graphics type, screen size.
- **It never reads** what people type, field values, page text, query
  strings or full URLs.
- It answers nothing back to the browser, so an attacker can't learn a verdict
  from it.
- It can wait for consent: set **Consent required** on the site key. Whether
  fraud prevention needs consent is the customer's legal decision.
- Hidden traps are invisible to screen readers and keyboard users, and are
  checked automatically for accessibility.

If an ad blocker stops the tag, everything from step 1 keeps working.

## 4. Edge add-ons

### Let good agents through (Web Bot Auth)

Some AI agents sign their requests to prove who operates them
([Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/), an IETF
draft built on HTTP Message Signatures, RFC 9421).

1. **Turn on signed-agent verification** at the CDN. Cloudflare verifies it
   today, and AWS WAF, Akamai, HUMAN and Vercel reportedly do too.
2. **Log the result** and the operator's key directory: two fields.
3. **Choose which operators to allow** in the portal under
   **Declared agents**.

Then:
- Signed agents from allowed operators are labeled and never treated as a
  fleet.
- Unknown operators are reported for the customer to allow or limit.
- A faked signature, someone posing as a trusted agent, raises a strong alert.

If the CDN doesn't verify signatures, Shield can't either. The source test
says so.

### Decoys

Decoys look valuable and are useless: a fake staff login page, fake
configuration files, a fake API key in the page code, a hidden API route. No
real visitor ever needs them. Each answers with a short instruction only an AI
agent follows, so touching one is a strong sign and following the instruction
is proof.

1. **Download the decoy rule set** for this deployment from the portal. Paths
   and values are generated per customer and never published.
2. **Load it into the CDN or Nginx.** Nothing in the customer's app changes.
3. **Add the customer's own scanners** (pentest and attack-surface tools) to
   the allow list, so their tests don't raise alerts.

The fake key uses the customer's own key format, never a cloud provider's, so
secret scanners don't react to it. Decoy content is harmless: no tracking
beyond the site and no hack-back.

## Rollout plan

| When | Do |
|---|---|
| Day 1 | Step 1. Review the first detections with the customer's SOC |
| Days 2 to 14 | Watch mode. Review the shadow report weekly; mark false positives in the portal |
| Week 2 | Step 3 on sign-up and checkout, if the customer wants the tag |
| Week 3 | Enforce session challenges |
| Later | Account actions through SOAR, Web Bot Auth allow list, decoys |

Detection rates depend on the customer's traffic and logs. Watch mode shows
what Shield finds on the customer's own data, and analysts mark false positives
there; don't quote rates before then.

## Deployment

- **Hosted:** Shield runs the worker and collector; the customer only connects
  their SIEM and edge.
- **On-premises:** the worker and collector run in the customer's cluster from
  the Shield images. The detector pack ships inside the release, so
  air-gapped installs work.

## FAQ

**Does it slow the site down?** No. Shield reads logs after the fact. The tag
loads asynchronously and sends data when a page is left.

**Will real customers get blocked?** The default action is a challenge, only
confident detections become indicators, popular devices and networks are never
published, established accounts are excluded, and everything expires within
an hour.

**What about the customer's own automation?** Allow-list it by IP range, user
agent or account.

**What data does Shield keep?** Session summaries for 24 hours. IPs are stored
as salted hashes of the /24, account ids are hashed, and no request bodies,
query strings or typed values are kept.

**What if the SIEM or Shield is down?** Shield resumes from where it stopped,
within the SIEM's retention. The customer's site never depends on Shield.
