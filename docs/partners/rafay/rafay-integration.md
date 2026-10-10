---
title: Votal Shield — Rafay integration guide (multi-tenant guardrails)
description: How Rafay enables Votal Shield AI guardrails for its customers. Each Rafay customer is one Shield tenant with its own API key; Rafay calls Shield PreCall (input) and PostCall (output) in its AI serving path.
audience: Rafay platform engineering
---

# Votal Shield — Rafay integration guide

This is the partner handoff for enabling **Votal Shield** AI guardrails on the
Rafay platform, multi-tenant. Pair it with the machine-readable contract:

- **OpenAPI 3.1 spec:** `docs/assets/openapi-partner.json` (curated partner
  subset — the guard, policy, and telemetry endpoints only, never the admin
  surface). Import this into Rafay's codegen / API explorer.

## 1. Model in one paragraph

Every Rafay **customer = one Shield tenant**, identified by its own **API key**.
Rafay provisions a tenant + key per customer (section 4), stores the key, and at
request time calls Shield **PreCall** on the user's input and **PostCall** on the
model's output, passing that customer's key. Shield resolves the tenant **from
the key**, applies that tenant's configured guardrails, and returns an
allow/block/redact verdict. Policy is per tenant, so one customer's rules never
touch another's. Shield never needs to store Rafay's model keys or see anything
beyond the text being screened.

```
Rafay customer app ──► Rafay AI serving path
                          │  (1) PreCall:  POST /guardrails/input   ─┐
                          │        block? → return the block to user │  X-API-Key:
                          ▼                                          │  <customer tenant key>
                       LLM / model                                  ├─► Votal Shield
                          │                                          │   (hosted API, or
                          │  (2) PostCall: POST /guardrails/output  ─┘    in-cluster container)
                          ▼        block/redact? → use sanitized_output
                       response to user
```

## 2. Base URL (two deployment shapes, same API)

- **Hosted (fastest):** `https://api.guardrails.votal.ai`
- **In-cluster (data residency):** the Shield guardrail container deployed in the
  customer's cluster; same paths, Rafay sets the base URL per deployment. See
  **Appendix A** for the Kubernetes/Helm reference.

Everything below is relative to the chosen base URL.

## 3. Authentication

Send the customer's tenant key on **every guard call**. Header priority:

1. `X-API-Key: <tenant-key>`  ← **preferred** (avoids collision with upstream proxies)
2. `X-Tenant-Key: <tenant-key>`
3. `Authorization: Bearer <tenant-key>`

The key is hashed and mapped to exactly one tenant; the tenant's policy is applied
automatically. **A caller cannot override the tenant** — any `tenant_id` in the
body/headers that disagrees with the key is rejected (IDOR defense).

> **REQUIRED deployment setting for multi-tenant isolation:**
> Deploy the Rafay-facing Shield with **`SHIELD_GUARD_REQUIRE_KEY=enforce`**.
> The default is `off`, under which a call with a missing/invalid key **fails
> open** (screens with no tenant policy) instead of being refused. In a
> multi-tenant deployment that is a silent isolation gap — set it to `enforce`
> so a bad key returns `401 missing_tenant_key` / `invalid_tenant_key`.

## 4. Onboarding a customer ("enable guardrails")

Enabling guardrails for a Rafay customer = **provision a Shield tenant + key** and
store the key against that customer. Two ways:

### 4a. Rafay provisions via the admin API (recommended)
> These admin endpoints are **privileged and intentionally NOT in the partner
> OpenAPI** (`openapi-partner.json` publishes only tenant-scoped surfaces). Votal
> issues Rafay the **admin key and these provisioning endpoints separately** as a
> partner capability. Do not expect them in the imported spec.

Rafay holds a Shield **admin key** (`X-Admin-Key`, issued to Rafay once, out of
band — not a tenant key). Per customer:

```bash
# create the tenant
curl -X POST "$BASE/v1/admin/tenants" \
  -H "X-Admin-Key: $RAFAY_ADMIN_KEY" -H "content-type: application/json" \
  -d '{"tenant_id":"rafay-cust-acme","name":"ACME Corp","api_keys":[]}'

# mint that tenant's key (store the returned key against the customer in Rafay)
curl -X POST "$BASE/v1/admin/tenants/rafay-cust-acme/api-keys" \
  -H "X-Admin-Key: $RAFAY_ADMIN_KEY" -H "content-type: application/json" \
  -d '{"label":"rafay-prod","scope":"guard"}'
```
List/revoke a customer's keys: `GET` / `DELETE /v1/admin/tenants/{tenant_id}/api-keys`.

### 4b. Self-service (customer mints their own)
If the customer has a Shield portal session or an existing key, they can mint:
`POST /v1/tenant/me/api-keys` (returns the plaintext key **once** — store it then).

> The admin key is the one high-privilege secret in this integration. It mints
> and revokes tenants, so Rafay must hold it like any provisioning credential
> (vault, not in customer-visible config). Tenant keys are per customer and
> low-blast-radius by comparison.

## 5. Let the customer choose which guardrails are on

Two options — pick one, or offer both:

- **Embed the Shield tenant portal** (SSO) so the customer configures policy in
  Shield's own UI. Lowest build cost for Rafay.
- **Surface it in Rafay's UI** via the policy API (authed with the customer's key):
  - `GET /v1/tenant/me/policies` → current input/output guardrails + custom policies
  - `PUT /v1/tenant/me/policies` → replace the input/output guardrail config
  - Natural-language / OWASP-style custom rules: `GET|POST /v1/tenant/me/custom-policies/`,
    `POST /v1/tenant/me/custom-policies/{id}/enable` (and `/disable`).
    A custom policy body is: `name`, `description`, `prompt` (20–2000 chars),
    `action` (`pass|warn|redact|block`), `stage` (`input|output`),
    `confidence_threshold` (0.5–1.0), `priority` (1–1000), `multi_turn`.

New/changed policy takes effect on the next guard call for that tenant — no
redeploy.

## 6. Runtime: the guard calls

### 6a. PreCall — screen the user's input
`POST /guardrails/input`

Request (only `message` is required; the tenant's configured guardrails run
automatically — you do not list them per call):
```json
{
  "message": "the user's prompt text",
  "messages": [{"role":"user","content":"..."}],
  "session_id": "rafay-session-123",
  "user_role": "analyst",
  "agent_key": "rafay-app-x"
}
```
```bash
curl -X POST "$BASE/guardrails/input" \
  -H "X-API-Key: $CUSTOMER_KEY" -H "content-type: application/json" \
  -d '{"message":"my SSN is ..."}'
```
Response:
```json
{
  "safe": false,
  "action": "block",
  "guardrail_results": [
    {"guardrail":"pii-detection","passed":false,"action":"block",
     "message":"message contains a Social Security Number","details":{...},"latency_ms":41.2}
  ],
  "inference_time_ms": 44.0
}
```
- **PASS:** `safe=true`, `action="pass"`, every `guardrail_results[].passed=true` → forward the prompt to the model.
- **BLOCK:** `safe=false`, `action="block"` → **do not call the model**; return the
  block to the user. The reason is the failing result's `message`.
- `action` is the highest-severity outcome across guardrails, ranked
  `pass < log < warn < redact < block`. On `redact`, a guardrail may have rewritten
  content — see PostCall for the sanitized payload pattern.

### 6b. PostCall — screen the model's output (and tool results)
`POST /guardrails/output`

Request (`output` required):
```json
{
  "output": "the model's response text",
  "context": {"tool_name":"search","user_role":"analyst","stage":"output"}
}
```
Response adds two conditional fields to the same schema:
- `sanitization` — audit of any data-policy redaction applied
- `sanitized_output` — **present only when the payload was modified**; forward
  **this** to the user instead of the original.

So PostCall handling: if `action=="block"` → suppress the output; else if
`sanitized_output` is present → return it; else return the original.

### 6c. File uploads
`POST /guardrails/file` — same verdict schema plus a `file` block; use it when a
customer uploads a document to an AI tool through Rafay.

### Also in the partner spec (beyond prompt screening)
The curated spec also publishes the **agentic / tool surfaces** Rafay may want for
agent workloads: agent registry (`/v1/agents/registry`), tool-call RBAC
(`/v1/shield/tool/check`, `/v1/shield/tool/output`, `/v1/agents/tools/policies`),
data policies (`/v1/data-policies/...`), and MCP gateway upstreams
(`/v1/tenant/me/mcp-gateway/upstreams`). Same tenant-key auth.

### Optional: one-call gateway (not in the partner spec)
If Rafay prefers Shield to also make the model call, an OpenAI-compatible endpoint
(`POST /v1/shield/chat/completions`) does input-screen → model → output-screen in
one request. It is **not published in the partner subset** — ask Votal to enable
it if Rafay wants Shield to own the model call rather than the split
PreCall/PostCall above.

## 7. Telemetry (per customer)

- `GET /v1/tenant/me/telemetry` — **(in the partner spec)** tenant-scoped
  agent/chat telemetry, keyed by the caller's own key; filters `limit`, `offset`,
  `agent_key`, `status` (`pass|warn|redact|mask|block`), `tool_name`, `q`,
  `since`, `until`. This is the partner-appropriate telemetry call.
- `GET /v1/tenant/me/usage`, `GET /v1/tenant/me/audit`,
  `GET /v1/tenant/me/guardrails/metrics` — usage, audit, and effectiveness (all
  in the partner spec).
- An admin-scoped `GET /v1/shield/decisions/{tenant_id}` also exists for
  cross-tenant enforcement queries, but like the admin provisioning endpoints it
  is **not in the partner subset** — use `/v1/tenant/me/telemetry` from Rafay.

Rafay can surface these in its own dashboard, or link customers to Shield's
Telemetry view.

## 8. Failure modes & latency (state these to customers, don't SLA them)

- **Store/Redis outage:** Shield **fails open** (screens with a warning rather
  than taking the customer's app down). If the deployment must fail *closed*,
  raise it with Votal — it's a deploy posture, not a per-call flag.
- **Timeouts:** Rafay should set a client timeout on the guard call and decide
  its own fail-open vs fail-closed if Shield is unreachable. Recommended: fail
  closed on `PreCall` for regulated tenants, fail open otherwise — Rafay's choice
  per customer.
- **Latency (typical, measured — not an SLA):** Tier-1 keyword/regex `<5 ms`,
  Tier-2 sentiment/topic `~150 ms`, Tier-3 adversarial/PII `~500 ms`. The
  response reports actual `inference_time_ms` / per-result `latency_ms` every
  call. Absolute latency varies with load and model placement; quote ranges, not
  a single number.

## 9. End-to-end Rafay steps (checklist)

1. **Receive** from Votal: the admin key (`X-API-Key`-style `X-Admin-Key`), a
   sandbox tenant + key, the base URL(s), and `docs/assets/openapi-partner.json`.
2. **Import** the OpenAPI into Rafay's API tooling; generate a client.
3. **Deploy posture:** set `SHIELD_GUARD_REQUIRE_KEY=enforce` on the Rafay-facing
   Shield (hosted config confirmed by Votal, or in the in-cluster Helm values).
4. **Onboarding hook:** when a Rafay customer enables guardrails, call §4a to
   create the tenant + mint the key; store the key in Rafay's secret store keyed
   to the customer.
5. **Policy UX:** embed the Shield portal (§5) or build the policy screens on
   `/v1/tenant/me/policies` + `/custom-policies`.
6. **Serving path:** wire §6a PreCall before the model and §6b PostCall after;
   honor `action` and `sanitized_output`.
7. **Observability:** pull §7 telemetry into Rafay's dashboard per customer.
8. **Validate** against the sandbox tenant: a benign prompt passes, a policy-
   violating prompt returns `action=block`, and the decision appears in telemetry.
9. **Go-live:** repeat for a pilot customer, confirm isolation (customer A's key
   never sees customer B's policy or decisions), then roll out.

## 10. What Votal still needs to confirm before sending

- Issue Rafay an **admin/provisioning key** and a **sandbox tenant + key**.
- Confirm the **deployment shape** (hosted vs in-cluster) and, if in-cluster, hand
  over the Helm chart + model sizing.
- Confirm **`SHIELD_GUARD_REQUIRE_KEY=enforce`** is set on the Rafay-facing
  deployment.
- Decide whether policy config is **portal-embed** or **API in Rafay's UI** (or
  both) so section 5 can be trimmed to the chosen path.

---

## Appendix A — In-cluster deployment (Kubernetes / Helm)

For data residency, the Shield guardrail server runs **inside the customer's
cluster**; Rafay points its serving path at the in-cluster Service instead of the
hosted URL. The API in sections 3–7 is identical — only the base URL changes.

> **What Votal ships:** the container **image** (registry path provided per
> partner) and a **packaged Helm chart on request**. The manifests below are a
> **reference** Rafay/the customer can apply directly or fold into their own
> chart — they are not a published chart in this repo. (A `deploy/helm/shield-identity`
> chart exists for the *identity* plane; the guardrail data plane is shipped as an
> image today.)

### A.1 Pick an image (model placement)

| Image | Model | Node | Use when |
|---|---|---|---|
| `Dockerfile.cloud` (app only, port **80**) | calls a **remote** model endpoint Votal provides | **CPU** | lightest in-cluster footprint; model traffic may leave the cluster |
| `Dockerfile` (app + in-cluster vLLM, ports **80** app / **8000** model) | **local** vLLM, nothing leaves the cluster | **GPU** | strict residency — the model runs in the customer's cluster too |

Both expose the **same guard API on port 80**. The GPU image additionally runs
vLLM on 8000 (internal to the pod).

### A.2 Shared dependency: Redis (tenant store + policy cache)

Multi-tenancy needs a Redis the Shield pods share — it holds tenant→key mappings
and the policy cache. Use a managed Redis or a serverless one:
- `REDIS_URL=redis://<host>:6379/0`, **or**
- `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` for serverless.

### A.3 Config (the env that matters)

| Env | Value | Why |
|---|---|---|
| `SHIELD_GUARD_REQUIRE_KEY` | **`enforce`** | **required** — else a bad key fails open (isolation gap) |
| `REDIS_URL` *(or `UPSTASH_*`)* | your Redis | tenant store + policy cache |
| `SHIELD_ADMIN_KEY` | secret | authorizes tenant provisioning (section 4a) |
| `LLM_MODEL_NAME` | model id | which guardrail model to use |
| *(cloud image)* model endpoint + token | from Votal | points the app at the remote model |
| *(GPU image)* `VLLM_PORT=8000`, `SHIELD_MAX_MODEL_LEN` | as sized | local vLLM; confirm GPU/VRAM with Votal |

### A.4 Reference manifest (cloud-model image, CPU)

```yaml
apiVersion: v1
kind: Secret
metadata: { name: shield-guardrail, namespace: shield }
stringData:
  REDIS_URL: "redis://redis.shield.svc:6379/0"
  SHIELD_ADMIN_KEY: "<admin-key-from-votal>"
  SHIELD_LLM_TOKEN: "<model-endpoint-token-from-votal>"
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: shield-guardrail, namespace: shield }
spec:
  replicas: 2                       # stateless app; scale horizontally
  selector: { matchLabels: { app: shield-guardrail } }
  template:
    metadata: { labels: { app: shield-guardrail } }
    spec:
      containers:
        - name: shield
          image: <registry>/votal/shield-guardrail-cloud:<tag>   # Votal provides
          ports: [ { containerPort: 80 } ]
          env:
            - { name: SHIELD_GUARD_REQUIRE_KEY, value: "enforce" }
            - { name: LLM_MODEL_NAME, value: "<model-id-from-votal>" }
            - { name: REDIS_URL,        valueFrom: { secretKeyRef: { name: shield-guardrail, key: REDIS_URL } } }
            - { name: SHIELD_ADMIN_KEY, valueFrom: { secretKeyRef: { name: shield-guardrail, key: SHIELD_ADMIN_KEY } } }
            - { name: SHIELD_LLM_TOKEN, valueFrom: { secretKeyRef: { name: shield-guardrail, key: SHIELD_LLM_TOKEN } } }
          readinessProbe: { httpGet: { path: /health, port: 80 } }
          resources:
            requests: { cpu: "500m", memory: "1Gi" }
            limits:   { cpu: "2",    memory: "2Gi" }
---
apiVersion: v1
kind: Service
metadata: { name: shield-guardrail, namespace: shield }
spec:
  selector: { app: shield-guardrail }
  ports: [ { port: 80, targetPort: 80 } ]
```
Rafay's serving path then calls `http://shield-guardrail.shield.svc:80/guardrails/input`.

### A.5 GPU (fully on-prem model) deltas

Swap the image for the app+vLLM one and give the pod a GPU; the model never leaves
the cluster:
```yaml
      containers:
        - name: shield
          image: <registry>/votal/shield-guardrail:<tag>     # app + vLLM
          ports: [ { containerPort: 80 } ]                    # 8000 is pod-internal
          env:
            - { name: SHIELD_GUARD_REQUIRE_KEY, value: "enforce" }
            - { name: LLM_MODEL_NAME,  value: "<model-id>" }
            - { name: VLLM_PORT,       value: "8000" }
            - { name: SHIELD_MAX_MODEL_LEN, value: "<confirm with Votal>" }
          resources:
            limits: { nvidia.com/gpu: 1 }                     # GPU/VRAM sizing: confirm with Votal
      # schedule onto a GPU node pool (nodeSelector/taints per Rafay's cluster)
```
`replicas` for the GPU variant is bounded by available GPUs; keep the CPU
cloud-model variant if you need to scale the app out independently of the model.

### A.6 Helm-ify (optional)

If Rafay prefers Helm, parameterise the above as `values.yaml`
(`image.repository/tag`, `model.name`, `guard.requireKey`, `redis.url`,
`replicaCount`, `gpu.enabled`) over the same Deployment/Service/Secret templates,
or ask Votal for the packaged chart. The identity-plane chart at
`deploy/helm/shield-identity/` is a structural example (it is **not** the
guardrail chart).

### A.7 In-cluster checklist

1. Image registry path + model endpoint/token + `SHIELD_ADMIN_KEY` received from Votal.
2. Redis reachable in-cluster; `REDIS_URL`/`UPSTASH_*` set.
3. `SHIELD_GUARD_REQUIRE_KEY=enforce` set.
4. Service reachable from Rafay's serving path; base URL pointed at it.
5. GPU node pool present (GPU image only); VRAM/model sized with Votal.
6. Smoke test: a benign prompt passes, a policy-violating prompt returns
   `action=block`, and `/v1/tenant/me/telemetry` shows the decision.

### A.8 OpenShift (Rafay runs OpenShift)

Ready-to-apply OpenShift manifests live in the repo's `openshift/` directory:

| Manifest | Deploys |
|---|---|
| `openshift/redis.yaml` | Redis (tenant store + policy cache) — the dependency from A.2 |
| `openshift/shield-guardrail-vllm.yaml` | The **guardrail data plane with in-cluster vLLM** (GPU) — Deployment + Service + `Route` + model-cache PVC |
| `openshift/shield-admin.yaml` | *(optional)* the admin/tenant portal (`Route`, port 8080) |

The vLLM manifest is a thin wrapper — the image's entrypoint
(`scripts/start_vllm.sh`) already launches vLLM on `:8000`, waits for it, then
runs the guard API; the manifest only schedules that image on a GPU with the
volumes, `Route`, and env it needs. Model runs **in-cluster** (full residency).

```bash
oc new-project shield || oc project shield
oc apply -f openshift/redis.yaml
# edit the Secret (REDIS_URL, SHIELD_ADMIN_KEY, optional HF token) first, then:
oc apply -f openshift/shield-guardrail-vllm.yaml
oc get route shield-guardrail -o jsonpath='{.spec.host}'   # Rafay's base URL
```

OpenShift specifics baked into the manifest (and why):
- **App on port 8080**, not 80 — the restricted SCC can't bind privileged ports.
- **`/dev/shm` as an in-memory `emptyDir`** — vLLM/NCCL need more than the 64 MB default.
- **Model-cache PVC** (`HF_HOME`) so the 4B model isn't re-pulled on restart.
- **`Route` timeout 120s** — Tier-2/agentic calls exceed the 30s default.
- **GPU toleration + `nvidia.com/gpu: 1`** — needs the **NVIDIA GPU Operator** installed.
- **fp8 by default** (L40S/L4/H100); set `VLLM_QUANTIZATION=none` on A100/V100/T4.
- **SCC:** if the vLLM image needs root, `oc adm policy add-scc-to-user anyuid -z shield-guardrail -n shield`.

For the no-GPU option (app calls a remote model), use the `llm-shield-cloud`
image with `SKIP_VLLM=true` + `LLM_BACKEND_URL` instead — same Deployment shape,
no GPU, no model-cache PVC.
