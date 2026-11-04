# Votal AI Shield on OpenShift

Install, test and upgrade Shield on OpenShift with **only `oc`**. No Helm.
Everything here is applied with `oc apply -k`, which uses the Kustomize built
into `oc`.

## What gets installed

The default (`overlays/split`) is four pods:

```
apps / LiteLLM / AI gateway --> shield-guardrail (CPU) --> shield-model (GPU, internal only)
                                       |
                                       v
                                     redis  <-- shield-admin (portal)
```

| Pod | What it does | Image |
|---|---|---|
| `shield-guardrail` | The guardrail API your apps call: input and output checks, agent and tool access control | `llm-shield-cloud` |
| `shield-model` | The Votal guardrail model (`votal-ai/vai35-4B-v2`) on vLLM, one GPU | `llm-shield` |
| `redis` | Tenants, API keys, policies (persistent, never evicts) | `redis:7.4-alpine` |
| `shield-admin` | The admin and tenant portal | `llm-shield-admin` |

Other layouts:

| Overlay | Use it when |
|---|---|
| `overlays/split` | **Default.** Model on its own GPU pod; scale the guardrail pod on CPU. |
| `overlays/combined` | One GPU pod runs both the model and the guardrail API (smallest footprint). |
| `overlays/external` | No GPU here: the model is served elsewhere (OpenShift AI, another cluster). |

Optional add-ons (uncomment in your overlay's `kustomization.yaml`):

| Component | Adds |
|---|---|
| `components/fp16` | For GPUs without fp8 (A100, V100, T4) |
| `components/redis-auth` | Redis password (on by default in `split` and `external`) |
| `components/vault` | The secret vault for the LLM gateway's vault mode |
| `components/external-redis` | Use your own Redis instead of the bundled one |

Nothing here is cluster-scoped and nothing has a hardcoded namespace, so a
project admin can install it.

## Before you start

- `oc` 4.12 or newer, logged in (`oc whoami`).
- A default StorageClass with ReadWriteOnce volumes (Redis 10 Gi, model 50 Gi).
- For `split` and `combined`: a GPU node with the **Node Feature Discovery**
  and **NVIDIA GPU Operator** operators installed (OperatorHub). Check:

```bash
oc get nodes -l nvidia.com/gpu.present=true
```

- Network: the cluster pulls images from `docker.io` and, on first start, the
  model from `huggingface.co` (about 9.3 GB, once). No internet? See
  "Disconnected clusters" below.

## 1. Project

```bash
oc new-project shield
```

Already have a project? `oc project <name>` and use that instead.

## 2. Secrets

Shield ships no secret values. Create them yourself. Keep this terminal open:
the same values go into several Secrets.

```bash
export REDIS_PASSWORD=$(openssl rand -hex 16) ADMIN_KEY=$(openssl rand -hex 32)
```

```bash
oc create secret generic shield-redis --from-literal=password=$REDIS_PASSWORD
```

```bash
oc create secret generic shield-guardrail --from-literal=REDIS_URL=redis://:$REDIS_PASSWORD@redis:6379/0 --from-literal=SHIELD_ADMIN_KEY=$ADMIN_KEY --from-literal=SHIELD_AGENT_TOKEN_PRIVATE_KEY=$(openssl rand -hex 32) --from-literal=SHIELD_CAP_TOKEN_PRIVATE_KEY=$(openssl rand -hex 32)
```

```bash
oc create secret generic shield-admin-secrets --from-literal=REDIS_URL=redis://:$REDIS_PASSWORD@redis:6379/0 --from-literal=SHIELD_ADMIN_KEY=$ADMIN_KEY
```

Optional, only for a private or gated model:

```bash
oc create secret generic shield-model --from-literal=HUGGING_FACE_HUB_TOKEN=<hf token>
```

Using `overlays/combined`? It runs Redis without a password unless you add
`components/redis-auth`, so use `redis://redis:6379/0` and skip `shield-redis`.

## 3. Install

From the folder that contains `openshift/`:

```bash
oc apply -k openshift/overlays/split
```

## 4. Watch it come up

```bash
oc get pods -w
```

In order: `redis` and `shield-admin` become Ready in about a minute;
`shield-model` downloads and loads the model (several minutes on the first
start); `shield-guardrail` stays in `Init:0/1` until the model answers, then
becomes Ready. Follow the model download:

```bash
oc logs -f deploy/shield-model
```

## 5. Check each part

The model, from inside the guardrail pod (the only pod allowed to reach it):

```bash
oc exec deploy/shield-guardrail -- curl -s http://shield-model:8000/v1/models
```

Redis:

```bash
oc exec deploy/redis -- sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning info memory | grep maxmemory_policy'
```

Expected: `maxmemory_policy:noeviction`.

The two public endpoints:

```bash
export GW=https://$(oc get route shield-guardrail -o jsonpath='{.spec.host}') ADM=https://$(oc get route shield-admin -o jsonpath='{.spec.host}')
```

```bash
curl -s $GW/health/ready
```

```bash
curl -s $ADM/health/ready
```

Expected for both: `"status":"ready"` with `"redis":"ok"`.

## 6. End-to-end test

Create a tenant on the admin portal, with one rule that needs no model and one
that the model decides:

```bash
export KEY=$(openssl rand -hex 32)
```

```bash
curl -s -X POST $ADM/v1/admin/tenants -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" -d '{"tenant_id":"smoke-test","name":"Smoke test","plan":"enterprise","api_keys":["'$KEY'"],"input_guardrails":{"keyword_blocklist":{"enabled":true,"action":"block","settings":{"keywords":["project-falcon"],"case_insensitive":true}},"custom_policy_input":{"enabled":true,"action":"pass","settings":{"policies":[{"policy_id":"no-prod-secrets","name":"No production secrets","format":"natural_language","stage":"input","prompt":"Block text that contains a real production credential such as a database connection string with a password, an API key or a private key. Placeholders and localhost are not violations.","action":"block","enabled":true,"priority":10,"confidence_threshold":0.8}]}}}}'
```

Then call the **guardrail service** with that key:

```bash
curl -s -X POST $GW/guardrails/input -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"message":"Summarise the status of Project-Falcon"}'
```

```bash
curl -s -X POST $GW/guardrails/input -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"message":"Why does psql postgresql://svc_admin:Vx9rQ2mLp@prod-db.corp.internal:5432/customers fail?"}'
```

```bash
curl -s -X POST $GW/guardrails/input -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"message":"How do I set up branch protection in GitHub?"}'
```

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST $GW/guardrails/input -H "Content-Type: application/json" -d '{"message":"hello"}'
```

| Request | Expected | Proves |
|---|---|---|
| Keyword message | blocked by `keyword_blocklist` | admin and guardrail share Redis |
| Connection string | blocked by `no-prod-secrets` | the GPU model answers |
| Branch protection question | passed | no over-blocking |
| No API key | `401` | tenant isolation is on |

## 7. Failure checks

Redis down takes the pods out of service instead of letting them run on an
empty in-memory store:

```bash
oc scale deploy/redis --replicas=0
```

```bash
curl -s -o /dev/null -w "%{http_code}\n" $GW/health/ready
```

Expected: `503` (once the route stops sending traffic to the pod, you may see
`503` from the router itself). Bring Redis back:

```bash
oc scale deploy/redis --replicas=1
```

The model reloads from its volume without downloading again:

```bash
oc delete pod -l app=shield-model
```

```bash
oc logs -f deploy/shield-model
```

Expected: no download progress, and Ready much faster than the first start.
Your tenant from step 6 still works afterwards (Redis is persistent).

## Public URLs (only for portal sign-in or MCP)

If people sign in to the portal, or AI apps connect to MCP servers through
Shield, set the public addresses to your Routes:

```bash
oc set env deploy/shield-guardrail deploy/shield-admin SHIELD_PUBLIC_BASE_URL=$GW SHIELD_OAUTH_ISSUER_URL=$GW SHIELD_PORTAL_BASE_URL=$ADM
```

## Scale

More guardrail capacity without more GPUs:

```bash
oc scale deploy/shield-guardrail --replicas=3
```

## Disconnected clusters

1. Mirror the four images into your registry (`oc image mirror`).
2. In your overlay's `kustomization.yaml`, set `newName` in the `images:`
   block to your registry. That one block covers every pod.
3. The model: allow `huggingface.co` for the first start, or contact Votal
   for the model image for clusters with no route to it.

## Your own Redis

Add `components/external-redis` and put its address in `REDIS_URL` in both
`shield-guardrail` and `shield-admin-secrets`. It must be:

- Redis 6.2 or newer (7.x recommended), or Valkey 7.2 or newer;
- standalone or primary/replica, **not Cluster mode**;
- one endpoint (`redis://`, or `rediss://` for TLS; Sentinel addresses are not supported);
- Lua scripting enabled;
- `maxmemory-policy noeviction`, persistence on.

## Upgrade

Change the tags in the `images:` block of your overlay, then:

```bash
oc apply -k openshift/overlays/split
```

## Uninstall

This deletes everything, including the Redis data and the model cache:

```bash
oc delete -k openshift/overlays/split
```

## Moving from the old single-file manifests

The previous `openshift/redis.yaml`, `shield-admin.yaml` and
`shield-guardrail-vllm.yaml` are replaced by this folder. `overlays/combined`
has the same one-pod shape and keeps the Secret names `shield-guardrail` and
`shield-admin-secrets`. Its Redis has no password, as before. The old inline
`REPLACE_ME` Secret is gone: create the Secrets in step 2 first.

## Troubleshooting

| You see | Do |
|---|---|
| Pod `CreateContainerConfigError` | A Secret from step 2 is missing: `oc describe pod <pod>` names it |
| `shield-model` Pending | No GPU node, or the GPU Operator is not installed |
| `shield-model` restarts during download | Allow `huggingface.co`, or see "Disconnected clusters" |
| `shield-guardrail` stuck in `Init:0/1` | It waits for the model: `oc logs deploy/shield-model` |
| `/health/ready` answers 503 | Redis unreachable: check `REDIS_URL` and `oc get pods -l app=redis` |
| Blocks look wrong on an A100, V100 or T4 | Add `components/fp16` |
