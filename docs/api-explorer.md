---
title: API Explorer
layout: default
nav_order: 13
permalink: /api-explorer/
description: The partner-facing Votal Shield API, rendered from the OpenAPI spec - guard the content and tool paths, configure policies per tenant, manage keys. Twenty-nine operations, tenant-scoped by API key.
---

# API Explorer

The partner-facing subset of the Shield API, rendered from
[`openapi-partner.json`](/assets/openapi-partner.json). Import that file
directly into Postman, Insomnia, or a client generator.

For prose and integration patterns see the
[API Reference](/api-reference/); this page is the contract.

## What is in it

| | |
|---|---|
| **Guard the content path** | `POST /guardrails/input` before the model, `POST /guardrails/output` after it |
| **Guard the tool path** | `POST /v1/shield/tool/check` before a tool runs, `POST /v1/shield/tool/output` on the way back. An MCP gateway calls these. |
| **Configure** | `PUT /v1/tenant/me/policies`, plus the custom-policy routes |
| **Credentials** | `/v1/tenant/me/api-keys` - create, label, expire, rotate |
| **Observe** | usage, telemetry, audit, guardrail metrics |

Authentication is a tenant API key in `X-API-Key`. **The tenant is derived from
the key, never from the request**, so a key can only read and write its own
configuration. Keys carry a scope: `runtime` may call the guard endpoints,
`admin` may additionally change configuration. Issue runtime keys to anything on
the hot path.

Administrative routes, tenant provisioning, and anything taking a tenant id in
the path are deliberately absent. They exist, and they are not part of the
partner contract.

## Regenerating

The spec is generated, not hand-written, so it cannot drift from the running
service:

```bash
python scripts/build_partner_openapi.py --url https://api.guardrails.votal.ai/openapi.json
```

The script filters by an **allow list**. A deny list would fail open - a route
added next month would be public until somebody remembered to exclude it. This
fails closed, and exits non-zero if an allow-listed path has disappeared, so a
rename breaks the build rather than silently shrinking what a partner can see.

<div id="redoc"></div>

<!--
  Redoc (Redocly/redoc, MIT) pinned to an exact version with a subresource
  integrity hash. Pinned because the theme pins mermaid the same way, and with
  SRI because a docs page that loads unpinned third-party script is a supply
  chain argument we would lose. To drop the CDN entirely, vendor the 910 KB
  bundle into assets/ and change the src.
-->
<script src="https://cdn.redoc.ly/redoc/v2.5.0/bundles/redoc.standalone.js"
        integrity="sha384-4vOjrBu7SuDWXcAw1qFznVLA/sKL+0l4nn+J1HY8w7cpa6twQEYuh4b0Cwuo7CyX"
        crossorigin="anonymous"></script>
<script>
  Redoc.init(
    '{{ "/assets/openapi-partner.json" | relative_url }}',
    { scrollYOffset: 0, hideDownloadButton: false, expandResponses: "200,201" },
    document.getElementById('redoc')
  );
</script>
