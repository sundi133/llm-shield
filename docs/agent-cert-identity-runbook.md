---
title: Agent certificate identity runbook
layout: default
nav_order: 74
permalink: /agent-cert-identity-runbook/
description: Set up and run certificate-based agent identity. Your proxy checks the certificate, Shield maps it to an agent through a pinned fingerprint or your own CA, and agents can be required to prove who they are.
---

# Agent certificate identity runbook

For the administrators who set up how AI agents prove who they are to Shield.
In the portal, everything here is under **Enterprise Controls, then Agent
Identity**. Spec: `docs/specs/agent-cert-identity.md`.

## How it works

1. Your **proxy** (Envoy, nginx, a cloud load balancer) performs mutual TLS
   with the agent. That handshake is what proves the agent holds the private
   key: a certificate on its own is public.
2. The proxy forwards the certificate to Shield, with a **shared secret** that
   tells Shield the header came from the proxy and not from a caller.
3. Shield maps the certificate to a registered agent, either by a **pinned
   fingerprint** or because it was issued by **your CA** and a **mapping rule**
   names the agent.
4. Optionally, an agent's registry entry **requires** this proof, and requests
   that name the agent without it are refused.

A request that carries a certificate header without the proxy's secret is
treated as carrying no certificate.

## 1. Set up the proxy

Shield settings (both the guardrail server and the admin portal):

| Setting | Value |
|---|---|
| `SHIELD_MTLS_ENABLED` | `true` |
| `SHIELD_TRUSTED_PROXY_ONLY` | `true` |
| `SHIELD_TRUSTED_PROXY_SECRET` | a long random value, for example `openssl rand -hex 32`. The proxy sends it as `X-Shield-Proxy-Token` |
| `SHIELD_TRUSTED_PROXY_IPS` | optional: the proxy's addresses, as an extra check. On its own it is safe only when forwarded IPs are locked to the proxy |

The proxy must **overwrite** the certificate header, never append to one a
client sent.

**Envoy** (HTTP connection manager):

```yaml
forward_client_cert_details: SANITIZE_SET
set_current_client_cert_details:
  cert: true
  chain: true        # forwards intermediates, so Shield can build the chain
request_headers_to_add:
  - header: { key: X-Shield-Proxy-Token, value: "<SHIELD_TRUSTED_PROXY_SECRET>" }
    append_action: OVERWRITE_IF_EXISTS_OR_ADD
```

**nginx**:

```nginx
ssl_verify_client on;
ssl_client_certificate /etc/nginx/agent-ca.pem;
proxy_set_header X-Forwarded-Client-Cert $ssl_client_escaped_cert;
proxy_set_header X-Shield-Proxy-Token   "<SHIELD_TRUSTED_PROXY_SECRET>";
proxy_set_header X-Client-Cert-Fingerprint "";
```

Shield reads the certificate in Envoy's format, URL-encoded (nginx) or as raw
PEM. `SHIELD_MTLS_CERT_HEADER` changes the header name if yours differs.

**Check it.** The Agent Identity page shows a **Setup check** when any of
these is missing. Then send a request through the proxy and confirm the
certificate's **Last seen** column updates.

## 2. Tell Shield which certificate is which agent

Two ways; use either or both.

**Pin a certificate** (a few agents, or self-signed certificates). Under
**Register a certificate**, paste the agent's certificate. Shield records its
fingerprint, expiry and names. A fingerprint alone also works, in any common
form (`AB:CD:...` from `openssl x509 -fingerprint -sha256` is fine), but then
Shield cannot warn before it expires.

**Trust your CA** (many agents, or short-lived certificates such as SPIFFE
SVIDs that renew hourly):

1. Under **Trust anchors**, add your CA certificate (root or intermediate).
   Shield refuses a certificate that is not a CA, has expired, or uses a weak
   key or a SHA-1 signature.
2. Under **Mapping rules**, say how a certificate names its agent, for
   example:

   ```json
   [{"match": "san_uri", "pattern": "spiffe://acme.com/agent/{agent_id}"}]
   ```

   `match` is `san_uri`, `san_dns` or `subject_cn`. A pattern without
   `{agent_id}` must name an `agent_id`. First match wins. A rule never maps a
   certificate to an agent that is not registered.
3. Paste a real certificate into **Test a certificate**. It shows the anchor,
   the rule and the agent, or why not.

Shield checks every link of the chain: the signature (a copy of your CA's
name is not enough), the validity dates, that issuers are CAs, and that the
agent's certificate is for client authentication when it restricts its use.
If your proxy does not forward intermediates, add the intermediate CA as an
anchor too.

Verified certificates are remembered for up to 5 minutes (never past their
expiry), so a change of anchors, rules or revocations reaches every Shield
server within 5 minutes and the one that made it at once.

## 3. Rotate certificates

- **Pinned**: register the new certificate for the same agent before the old
  one expires; both work. Then revoke the old one from the **Certificates**
  list. **Expiring within 14 days** shows what needs attention.
- **CA-issued**: nothing to do in Shield. A renewed certificate from the same
  CA maps through the same rule.
- **The CA itself**: add the new CA as a second anchor, move agents over,
  then remove the old anchor.
- **The proxy secret**: set the new value on the proxy and Shield in one
  change window; requests in flight with the old value are refused once Shield
  has the new one.

## 4. Revoke

- **One certificate**: **Revoke** on its row in **Certificates**.
- **Everything an agent holds**: **Revoke all certificates** under Query
  Agent Trust.
- **CA-issued certificates**: load your CA's **revocation list (CRL)** on the
  anchor. Shield refuses a certificate whose serial it lists. Choose what
  happens when the CRL is past its next update: **refuse** (the default, safer)
  or **accept** (keeps agents working if a CRL upload is late; the portal marks
  it out of date). Load each new CRL before the old one's next update.
  Short-lived certificates make revocation largely unnecessary.

## 5. Require it

In the agent's registry entry, set:

```json
{"identity": {"require": "cert"}}
```

| Value | A request that names the agent must carry |
|---|---|
| `any` (default) | nothing more than today |
| `cert` | a certificate verified through your proxy, for this agent |
| `token` | a verified agent token (`X-Agent-Token`) for this agent |
| `cert_or_token` | either |

It applies wherever an agent is named: the `X-Agent-Key` header on every
guarded request, and the agent named in the body of tool checks, tool output
checks, agent chat and agent-to-agent tasks. A refused request gets
`identity_required` (401 on the guard path, a block result on tool checks)
and a row in the decision audit. For tokens, also set
`SHIELD_AGENT_TOKEN_POP=required`, so a copied token is useless without the
agent's key.

## Moving off the fingerprint header

Earlier guidance told agents to send `X-Client-Cert-Fingerprint` themselves.
A fingerprint is public, so that proves nothing. Move each agent to one of:

1. **Agent tokens bound to the agent's key** (`SHIELD_AGENT_TOKEN_POP=required`,
   `X-Agent-Token` plus `X-Agent-DPoP` on each call). No proxy needed.
2. **mTLS at your proxy**, as above.

`SHIELD_CERT_IDENTITY_TRUST_HEADER=true` keeps the old behavior while you
move. It is temporary, and the Agent Identity page warns while it is on.

## Reference

| Purpose | API (tenant key) |
|---|---|
| Configuration warnings | `GET /v1/tenant/me/agent-identity/status` |
| Certificates, expiry, last seen | `GET /v1/tenant/me/agent-identity/certs?expiring_days=14` |
| Register / revoke | `POST /v1/shield/agent/identity/register` `{agent_key, tenant_id, cert_pem}`; `POST .../revoke` `{agent_key, tenant_id, fingerprint?}` |
| Trust anchors | `GET`, `POST /v1/tenant/me/agent-identity/anchors` `{name, pem}`; `DELETE .../anchors/{id}` |
| Mapping rules | `GET`, `PUT /v1/tenant/me/agent-identity/rules` `{rules: [...]}` |
| Test a certificate | `POST /v1/tenant/me/agent-identity/test` `{cert_pem, chain_pem?}` |
| Revocation lists | `GET /v1/tenant/me/agent-identity/crls`; `PUT .../crls/{anchor_id}` `{pem, stale}`; `DELETE .../crls/{anchor_id}` |

Writes need the admin key when the tenant's registry write gate is enforced,
and every one is in the admin audit.
