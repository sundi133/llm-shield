---
title: "Deploy the LangChain demo on Railway"
layout: default
nav_order: 45
permalink: /deploy-langchain-demo-railway/
description: "Put the guarded LangChain agent on a public URL in about ten minutes, with the two settings that decide whether it is a demo or an open door."
---

# Deploy the LangChain demo on Railway
{: .no_toc }

The demo runs locally with one command. Putting it on a URL you can send
someone takes two more things: a port the platform chooses, and a secret that
must not travel with the code.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Before you start

You need a Shield deployment already running and reachable — this deploys the
**app**, not Shield. If you have not got that yet, start with
[the quickstart](/langchain-quickstart/) locally.

## 1. Create the service

From the Railway dashboard: **New Project → Deploy from GitHub repo**, pick this
repo, and let it build once. It will fail or serve nothing useful until step 2,
which is expected.

`examples/langchain/railway.json` already sets the build and start commands:

```json
{
  "build": {
    "buildCommand": "pip install -r examples/langchain/requirements.txt"
  },
  "deploy": {
    "startCommand": "python examples/langchain/langchain_trusted_proxy_agent.py",
    "healthcheckPath": "/whoami"
  }
}
```

If Railway does not pick it up automatically, set **Config-as-code path** to
`examples/langchain/railway.json` in service settings, or paste the two
commands into **Settings → Build** and **Settings → Deploy** by hand.

## 2. Set the variables

**Settings → Variables.** Six, and one of them is the whole security model:

```
LLM_SHIELD_URL      https://api.guardrails.votal.ai
TENANT_API_KEY      <your tenant key>
AGENT_ID            sre-agent
SHIELD_PROXY_TOKEN  <the shared secret>
OPENAI_API_KEY      sk-...
APP_SESSION_KEY     <openssl rand -base64 32>
```

`APP_SESSION_KEY` matters more here than locally. Without it the app generates a
random one at boot, so **every deploy and every restart logs everyone out** —
and with more than one replica, a cookie set by one is rejected by the other.

Optional:

```
DEMO_MODEL    gpt-4.1-mini
DEMO_CAPS     1                 # capability path; needs TENANT_ID too
TENANT_ID     <tenant id>
```

Do **not** set `PORT` or `APP_PORT`. Railway injects `PORT` and the app binds it.

## 3. Match the secret on Shield

The app and Shield must hold the same value:

| where | variable |
|---|---|
| this app | `SHIELD_PROXY_TOKEN` |
| Shield | `SHIELD_TRUSTED_PROXY_SECRET` |

And on Shield:

```
SHIELD_ROLE_BINDING=strict_proxy
SHIELD_TRUSTED_PROXY_ONLY=true
```

Without these, Shield discards the role your app asserts and everything is
denied. With `strict_proxy` but no matching secret, same result — which reads as
"the demo is broken" rather than "the secret does not match", so check this
first when nothing works.

## 4. Generate the domain

**Settings → Networking → Generate Domain.** Open it and sign in as `alex`.

## The port thing, in case you hit it

Railway assigns a port and health-checks it. Two ways to get that wrong, and
the app handles both:

```python
APP_PORT = int(os.getenv("PORT") or os.getenv("APP_PORT") or "8500")
APP_HOST = os.getenv("APP_HOST") or ("0.0.0.0" if os.getenv("PORT") else "127.0.0.1")
```

A container bound to `127.0.0.1` is unreachable from outside itself, so the
health check fails and the deploy is killed with no obvious error. Binding
`0.0.0.0` only when the platform assigns a port keeps local runs on loopback,
where they belong.

## Before you send anyone the link

{: .warning }
> **This demo has no real authentication.** Five usernames with the password
> `demo`, hardcoded in the file. That is fine on localhost and not fine on a
> public URL — anyone who finds it can sign in as `sre_lead` and drive your
> agent against your Shield tenant, using your OpenAI key.

Pick one before sharing:

- **Change the passwords.** Edit `USERS` to read from an environment variable.
  Ten minutes, and it is what you would do for a real app anyway.
- **Put it behind Railway's private networking** and share your screen instead.
- **Use a throwaway tenant** with a registry that grants only read-only tools,
  so the worst case is someone reading fake logs.
- **Take it down after the demo.** Railway makes this one click, and it is the
  option most people should take.

The `SHIELD_PROXY_TOKEN` deserves the same care: anything holding it can assert
any role to your Shield tenant. Rotate it after a public demo.

## If something does not work

| symptom | cause |
|---|---|
| Deploy killed, no logs after startup | bound to `127.0.0.1`, or `PORT` overridden |
| Everyone logged out on redeploy | `APP_SESSION_KEY` not set |
| Every tool denied for every user | secret mismatch, or `SHIELD_ROLE_BINDING` not `strict_proxy` |
| Every tool ALLOWED for every user | the tenant has no agent registry, so Shield is permissive — see [the quickstart](/langchain-quickstart/) |
| `/chat` returns 500 | `OPENAI_API_KEY` missing or the model name is wrong |
| Roles resolve but grants look wrong | role names must match the registry exactly; `oncall` is not `oncall_engineer` |

Check the authorization path without a browser or a model:

```bash
python examples/langchain/langchain_trusted_proxy_agent.py --attack
```

Run it with the same variables as the deployment. Its last check calls Shield
directly with a forged role and tells you whether `strict_proxy` is actually
enforcing.

## Want a walkthrough?

[Book a 30-minute demo](https://calendly.com/sundi133/book-a-meet) and we will go
through it against your own Shield tenant.

## Next

- [Quickstart](/langchain-quickstart/) — the local version and the three lines to copy
- [Role-binding runbook](/role-binding-runbook/) — the modes and how to roll them out
- [FAQ: verified identity](/faq-verified-identity/) — what this proves and what it does not
