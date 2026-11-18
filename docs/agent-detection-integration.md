---
title: "AI Agent Detection: partner integration guide"
layout: default
nav_exclude: true
search_exclude: true
permalink: /agent-detection-integration/
description: "How a customer turns on Shield's AI agent detection: a site key, one script tag, watch mode, then enforcement through their own firewall or CDN with a pull feed."
---

# AI Agent Detection: partner integration guide
{: .no_toc }

AI agents now sign up, log in, redeem promotions and check out the way people
do, often as a fleet: one controller running dozens of browsers in sandboxes,
each on its own home IP. Rate limits, IP reputation and per-session bot rules
see nothing unusual in any single session.

Shield finds those agents with a small script on the customer's pages, links
the sessions one controller runs into a fleet, and hands the customer's own
firewall or CDN a list to challenge. Shield is never in the request path and
never blocks anything itself.

**What is available today:** the tag, detection, fleets, watch mode and
enforcement through the pull feed and webhooks (steps 1 to 4 below). Detection
from SIEM logs, signed-agent (Web Bot Auth) handling, decoys and mobile SDKs
come later; see [What comes next](#what-comes-next).

1. TOC
{:toc}

## What the customer installs

| Step | Effort | What changes on the customer's side |
|---|---|---|
| [1. Create a site key](#1-create-a-site-key) | minutes | nothing |
| [2. Add the tag](#2-add-the-tag) | one script line, one CDN route | the tag on protected pages |
| [3. Watch](#3-watch) | one to two weeks of review | nothing |
| [4. Enforce](#4-enforce) | a poller and one edge rule | matching sessions are challenged |

Pages load as fast as before: the tag loads asynchronously, sends small
reports in the background, and never holds up a page or a form. If Shield is
down, the site is unaffected.

## Before you start

Collect these from the customer:

- **The sites to protect**, as origins (for example `https://shop.example.com`).
- **The pages that matter:** sign-up, login, password reset, promotions,
  checkout. The tag goes on these at least.
- **Their edge:** the CDN, WAF or reverse proxy in front of the site, and
  whether it can forward one path (`/_shs/`) to Shield.
- **Whether visitors must consent** to the tag before it runs. That is the
  customer's legal decision; the tag supports both.
- **An owner for enforcement:** the person who decides when watch mode ends.

## 1. Create a site key

In the Shield portal: **Security Operations**, then **AI Agent Detection**,
then **Tag**, then **New site key**.

| Setting | Meaning |
|---|---|
| Origins | The sites allowed to send tag data with this key. `https` only, except local development hosts |
| Run only after consent | The tag sets no cookie and sends nothing until the page says so |
| Our CDN forwards `/_shs/` | Tells Shield the reports arrive through one more proxy, so it reads the visitor's address correctly |
| Hidden traps | On by default. Turn off only if the site cannot tolerate hidden form elements |

A site key is public, like a CAPTCHA site key. It can only send tag data for
this customer, and only from the listed origins.

## 2. Add the tag

The **Tag** page shows the exact line to paste for each site key, with its
integrity hash. It looks like this:

```html
<script src="https://<tag-host>/shs-1.1.0.js"
  integrity="sha384-..." crossorigin="anonymous"
  data-site="shs_pk_..." async></script>
```

Put it on every protected page. The browser checks the integrity hash, so the
file can't be changed without the customer noticing: a new tag version comes
with a new line.

### Route `/_shs/` to Shield (recommended)

The tag sends its reports to `/_shs/` on the customer's own site. Forwarding
that path to the Shield collector keeps the tag first-party, so ad blockers
treat it like the site's own code. Nginx:

```nginx
location /_shs/ {
    proxy_pass https://<shield-collector>/;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Other CDNs: forward requests for `/_shs/*` to the collector host, keep the
`Origin`, `Referer`, `User-Agent` and `Sec-CH-UA*` headers, and append the
visitor's address to `X-Forwarded-For`. Tick **Our CDN forwards `/_shs/`** on
the site key.

If the edge can't forward a path, use the **direct** snippet from the Tag
page instead: it adds `data-collector="https://<shield-collector>"` and the
reports go straight to Shield.

### Consent

With **Run only after consent**, the snippet carries `data-consent="required"`.
Call this when the visitor agrees:

```html
<script>
  window.shs = window.shs || function () { (window.shs.q = window.shs.q || []).push(arguments); };
  window.shs('consent');   // when the visitor agrees; works before or after the tag loads
</script>
```

Shield also drops any report without consent for such a key, so an outdated
page that misses the attribute sends nothing that is kept.

### Check it works

Open a protected page in a browser, then the **Tag** page in the portal. The
site key shows **reporting**, when the last report arrived, and whether traps
were shown.

### What the tag collects, and what it never does

- **It collects** counts, timings and hashes: key and click counts, how far
  clicks land from the center of a button, whether the pointer moved first,
  typing rhythm, graphics type, screen size, and whether the browser reports
  being automated.
- **It never reads** what people type, field values, page text, query
  strings or full URLs.
- **It places hidden traps:** a short instruction only an AI reads and obeys,
  a hidden field and a hidden link. People never see them, screen readers and
  keyboards never reach them, and they are never sent to the customer's
  server with the form. The codes in them are different for every visitor.
- **It learns nothing back:** the collector answers every report with an
  empty response, so an attacker can't learn a verdict.

If an ad blocker stops the tag on some pages, those pages simply aren't
covered; nothing breaks.

## 3. Watch

Every customer starts in **watch mode**. Shield scores sessions and finds
fleets, and the portal shows what it would challenge, but nothing reaches the
customer's edge and no webhook fires.

| Portal section | What the customer sees |
|---|---|
| Detections | Each flagged session with plain-language reasons, for example "7 fields changed with no key presses" or "followed a hidden instruction with this session's own code" |
| Fleets | Sessions one controller runs: how many, across how many networks, what linked them, where they went on the site, and the device and browser they shared |
| Enforcement | Every indicator Shield would publish, marked **watch only** |

Plan on one to two weeks of watch mode on real traffic before enforcing.

## 4. Enforce

### What gets published

| Indicator | Matched by the edge on | Published for |
|---|---|---|
| Session cookie (`_shs`) | the `_shs` cookie | fleet members, clear agents, and any new session that shows up on a fleet's rare device (stopped once its first report arrives) |
| Browser signature | `User-Agent` plus the `Sec-CH-UA`, `Sec-CH-UA-Platform` and `Sec-CH-UA-Mobile` headers, exactly | fleets, and only when that exact signature is rare among the customer's real visitors |

Switch each type to **Enforce** under **Enforcement**. Choose the action the
edge should take (challenge by default) and how long an indicator lives
(an hour by default; it renews while the fleet is active).

### Pull the feed

Create a **feed token** under **Enforcement**. It is shown once. A feed token
can read the feed and nothing else; it is not an API key.

```bash
curl -sf -H "X-Shield-Feed-Token: $SHIELD_FEED_TOKEN" \
  "https://<shield-host>/v1/agent-detection/indicators?format=nginx" \
  -o /etc/nginx/shield/agd.conf && nginx -s reload
```

Poll every 60 seconds. Send the last `ETag` back as `If-None-Match` and an
unchanged list answers `304` with no body. `format` is `json`, `csv` or
`nginx`. The feed is empty in watch mode and while the kill switch is on.

The Nginx format is two `map` blocks for the `http` context. A complete edge
rule:

```nginx
http {
    include /etc/nginx/shield/agd.conf;          # $shield_agd_shs, $shield_agd_client
    map "$shield_agd_shs$shield_agd_client" $shield_agd_hit {
        default 1;
        "00"    "";
    }
    server {
        location /_shs/ { proxy_pass https://<shield-collector>/; }   # never challenged
        location / {
            if ($shield_agd_hit) { return 302 /challenge; }
            proxy_pass http://app;
        }
    }
}
```

Start the poller with an empty pair of maps so Nginx can load before the first
poll. For other edges, the JSON format lists each indicator's type and exact
value: match the `_shs` cookie, or the browser signature string built as
`User-Agent|Sec-CH-UA|Sec-CH-UA-Platform|Sec-CH-UA-Mobile`.

### Webhooks (SOAR and automation)

Subscribe to `agent_fleet.indicators` (a fleet's indicators were published,
with its size, traits, the pages it visited and the values) and
`agent_fleet.ended` (the fleet went quiet and its indicators lapse). They are
signed like every other Shield webhook and sent only when a type is enforced.

### Safety rules the customer can rely on

- **Only confident results become indicators:** fleets and clear agents.
  Grey sessions stay in the portal for review.
- **A popular device, browser or way of typing never links people.** Shield
  counts how common each one is among the customer's human-like visitors and
  uses only rare ones.
- **Everything expires:** an indicator lasts an hour by default and renews
  only while its fleet is still active.
- **Revoke** one indicator in the portal; it stays out for 24 hours.
- **Kill switch:** **Clear all** removes every indicator and pauses
  publishing until someone resumes it. The edge stops challenging at its next
  poll.
- **The default action is a challenge, not a block,** and every change is in
  the enforcement event log and the audit trail.

## Rollout plan

| When | Do |
|---|---|
| Day 1 | Steps 1 and 2 on sign-up and checkout; check the Tag page shows reporting |
| Days 2 to 14 | Watch mode. Review Detections and Fleets with the customer's security team |
| Week 2 or 3 | Step 4: the poller and the edge rule, then enforce session cookies |
| Later | Enforce browser signatures; add webhooks to the SOAR |

Detection rates depend on the customer's traffic. Watch mode shows what Shield
finds on their own visitors; don't quote rates before then.

## What comes next

- **Detection from SIEM logs** (Splunk, Sentinel, Elastic): checks that need
  no tag, account and network indicators, and evidence added to existing SIEM
  alerts instead of duplicates.
- **Signed agents** (Web Bot Auth): let declared agents from trusted
  operators through, and flag forged signatures.
- **Decoys:** things on the site no real visitor needs, with an instruction
  only an AI follows.
- **Mobile SDKs** for Android, then iOS.

## Deployment

- **Hosted:** Shield runs the collector, the scoring worker and the feed. The
  customer adds the tag, the `/_shs/` route and the edge rule.
- **On-premises:** the collector and worker run in the customer's cluster from
  the Shield admin image, and the tag can be served from the collector itself.

Operators: see the [deployment runbook]({{ "/agent-detection-deploy/" | relative_url }}).

## FAQ

**Does it slow the site down?** No. The script is about 15 KB, loads
asynchronously, and sends its reports in the background.

**Will real customers get challenged?** Only confident results are
published, only rare signatures are used, the default action is a challenge,
everything expires, and one switch clears it all. Watch mode first shows
exactly what would have been challenged.

**Can an agent just skip the tag?** Then its session sends no reports, and
the tag alone can't judge it. The detection from SIEM logs, coming next,
flags protected-form submits that arrive with no tag reports.

**What about agents that behave exactly like people?** Shield prefers no
false fleet to catching a perfect imitation: such agents link into a fleet
only through the hidden traps, when one session uses a code shown to another.

**What data does Shield keep?** Session summaries for 24 hours: counts,
timings and hashes. The visitor's network is kept only as a salted hash, and
no typed values, page text or query strings are kept.

**What if the collector is down?** Reports are lost for that time, pages are
unaffected, and detection resumes when it is back.
