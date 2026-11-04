# Spec: on-prem release bundle (Helm + oc-only)

Status: DRAFT, awaiting approval.

## 1. Problem and outcome

Enterprise customers (first: RTA, on OpenShift and OpenShift AI with H200 GPUs,
often without internet on cluster nodes) need to install and upgrade Shield
themselves. Today they get:

- hand-maintained manifests in `openshift/*.yaml`, copied by hand into
  `docs/assets/openshift/*.yaml`;
- images on public Docker Hub tagged `:latest`, `:v2` and `:<sha>`
  (`.github/workflows/build.yml`), unsigned, amd64 only;
- a model that the GPU pod downloads from Hugging Face on first start.

The manifests have known problems, each of which breaks or degrades an install:

| Problem | Where | Effect |
|---|---|---|
| Admin secret example sets `UPSTASH_REDIS_REST_URL=http://srh:8079` (not deployed) | `openshift/shield-admin.yaml` header | Admin falls back to the in-memory store; tenants made in the portal never reach the data plane |
| Guardrail Secret shipped inline with `REPLACE_ME` | `openshift/shield-guardrail-vllm.yaml` | Secrets live in a file people edit and may commit |
| `HF_HOME=/model-cache` is overridden by the image's `HUGGINGFACE_HUB_CACHE=/tmp/cache/huggingface/hub` | `Dockerfile` vs manifest | The 9.3 GB model lands in `/tmp`, not the PVC, and re-downloads on every restart |
| Namespace hardcoded to `shield` in the guardrail manifest, absent in the others | all three | `oc apply -n <other>` fails or splits the install |
| No no-GPU variant | | Cannot run on a cluster without GPUs (or a Developer Sandbox) |
| `WORKERS` unset, so `handler.py` starts **32** uvicorn workers | data plane | Memory far beyond the pod limit |
| Image caches and `logs/` are root-owned `755` | `Dockerfile` | Writes fail under OpenShift's random UID, so the manifest tells customers to grant `anyuid` |
| `AUDIT_DB_PATH` set on the admin pod | `openshift/shield-admin.yaml` | Dead: no code reads it (the audit log is in Redis) |
| `:latest` images, unpinned `vllm/vllm-openai:latest` base | | Two installs of "the same" release differ |
| No vault env (`SECRET_VAULT_ENABLED`, `SECRET_VAULT_KEK`) | | The Shield LLM gateway's vault mode is unavailable on-prem |

**Outcome.** Each release `vX.Y.Z` produces one bundle a customer can install
with **only `oc`**, or with Helm, on a connected or disconnected cluster:

```
shield-onprem-vX.Y.Z/
  README.md                 install, test and upgrade runbook
  chart/shield-X.Y.Z.tgz    Helm chart (also pushed as an OCI artifact)
  values/                   example values: gpu.yaml, remote-model.yaml
  rendered/gpu/             plain YAML + kustomization.yaml   (oc apply -k)
  rendered/remote-model/    plain YAML + kustomization.yaml   (oc apply -k)
  images.txt                every image, by digest
  mirror.sh                 oc image mirror to dir / from dir, skopeo fallback
  cosign.pub                verifies every image signature offline
  SHA256SUMS
```

Success: on a real OpenShift cluster, `oc apply -k rendered/remote-model/`
(after creating one Secret) brings up Redis, the admin portal and the
guardrail service, and the end-to-end check passes: a tenant created on the
admin plane is enforced by the data plane. The same with `helm install`. The
GPU profile does the same on a GPU node, with the model loaded from the
mirrored model image and no Hugging Face access.

**Non-goals.**

- An Operator or OperatorHub listing (later, if customers ask).
- Red Hat certification of images or chart (later; this spec makes it possible).
- Multi-arch images (OpenShift customers in scope are amd64).
- Redis Cluster or Sentinel support (section 3 explains why Cluster cannot work).
- HA Redis inside the chart (customers who need it bring their own, as `externalRedis`).
- Changing any guardrail behavior.

## 2. Plane and latency contract

- **Both planes**, packaging only: the chart deploys the data plane
  (`core/app.py` via `handler.py`, GPU or remote-model) and the admin plane
  (`admin_app.py`), plus Redis.
- **Off the hot path.** No change to `/guardrails/*`, `cap/mint` or
  `tools/call` handling. Two small code changes ship with this spec, and both
  are inert unless configured:
  - `vllm` backend mode gains an **optional** bearer token and model name
    (task 2). Unset, the model request is byte-identical to today's.
  - A new readiness endpoint (task 1b) that probes call; it is not on any
    request path.

## 3. Data model

No new Redis keys. The bundle documents what Shield requires of Redis, which
the chart's bundled Redis satisfies and an external one must:

| Requirement | Why |
|---|---|
| Redis 6.2+ (7.x recommended) or Valkey 7.2+ | `GETDEL` (oauth, signup, MCP OAuth stores) |
| Lua `EVAL` enabled | audit chain CAS (`storage/audit_chain.py`, two keys), MCP lock release |
| Standalone or primary/replica, **not Cluster** | multi-key `EVAL` and multi-key pipelines get `CROSSSLOT` in Cluster mode |
| One endpoint in `REDIS_URL` (`redis://`, `rediss://`, password in URL) | `redis.Redis.from_url`; Sentinel URLs are not supported |
| `maxmemory-policy noeviction` | Redis is the store of record for tenants, keys, policies, revocations and nonces (merged with PR #539) |
| Persistence on (AOF) | same |
| `UPSTASH_*` unset on-prem | `_get_redis()` tries Upstash first if both vars are set |

Tenant scoping is unchanged: one Redis per install, tenants isolated by the
existing key layout.

## 4. API / interface

### 4.1 Chart: `deploy/helm/shield/`

Values (abridged; defaults shown):

```yaml
global:
  imageRegistry: docker.io/sundi133      # customer sets their mirror
  imagePullSecrets: []
  exposure: route                        # route | ingress | none

secrets:                                 # customer-created; the chart never creates secret values
  admin:     { existingSecret: shield-admin-secrets }   # SHIELD_ADMIN_KEY, REDIS_URL
  dataPlane: { existingSecret: shield-guardrail }       # SHIELD_ADMIN_KEY, REDIS_URL [, LLM_BACKEND_API_KEY]
  vault:     { existingSecret: "" }                     # key: kek  -> SECRET_VAULT_KEK (file)

redis:
  enabled: true                          # false -> externalRedis via REDIS_URL in the secrets above
  image: redis@sha256:...                # pinned by digest at release
  auth: { enabled: true, existingSecret: shield-redis, key: password }
  maxmemory: 2gb
  maxmemoryPolicy: noeviction
  persistence: { size: 10Gi, storageClass: "" }

admin:
  replicas: 1
  resources: { requests: { cpu: 250m, memory: 256Mi }, limits: { cpu: "1", memory: 512Mi } }

dataPlane:
  profile: gpu                           # gpu | remote-model
  replicas: 1
  workers: 4                             # WORKERS; 32 is the handler default
  requireKey: enforce                    # SHIELD_GUARD_REQUIRE_KEY
  gpu:
    model:
      source: modelImage                 # modelImage | huggingface
      image: vai35-4b-modelcar@sha256:...
      name: votal-ai/vai35-4B-v2         # SERVED_MODEL_NAME, so callers see the same name
    quantization: fp8                    # none on A100/V100/T4
    maxModelLen: 8196
    gpuMemoryUtilization: 0.85
    cache: { size: 50Gi, storageClass: "" }
    tolerations: [{ key: nvidia.com/gpu, operator: Exists, effect: NoSchedule }]
    nodeSelector: {}
  remoteModel:
    url: ""                              # LLM_BACKEND_URL, OpenAI-compatible
    modelName: ""                        # LLM_MODEL_NAME, sent only when set
    # bearer token, if any, is LLM_BACKEND_API_KEY in secrets.dataPlane
  vault: { enabled: false }

modelServing:                            # optional, needs OpenShift AI / KServe CRDs
  inferenceService: { enabled: false }   # serves the model image; remoteModel.url points at it
```

Templates (namespace-scoped only, so a project admin can install into an
existing namespace; no `Namespace`, `ClusterRole`, CRD or SCC objects):
Deployments (redis, admin, data plane), Services, Routes or Ingresses,
NetworkPolicies (Redis accepts only Shield pods; admin and data plane accept
the router and same-namespace pods), PVCs (redis data, model cache), an
optional KServe `InferenceService`, `NOTES.txt` with the post-install check.

Probes: liveness `GET /health` (unchanged); readiness `GET /health/ready`
(task 1b); data-plane **startup** probe with a long budget (model load).

Environment the chart sets, per plane (secrets by reference only):

| Var | Admin | Data plane | Value |
|---|---|---|---|
| `PORT` | 8080 | 8080 | restricted-v2 cannot bind :80 |
| `WORKERS` | | `dataPlane.workers` | |
| `SHIELD_GUARD_REQUIRE_KEY` | | `enforce` | tenant isolation |
| `REDIS_URL`, `SHIELD_ADMIN_KEY` | secret | secret | must match across planes |
| `HF_HOME`, `HUGGINGFACE_HUB_CACHE`, `VLLM_CACHE_ROOT`, `TRITON_CACHE_DIR`, `TORCHINDUCTOR_CACHE_DIR`, `FLASHINFER_CACHE_DIR` | | all under the cache PVC | fixes the re-download |
| `HF_HUB_OFFLINE=1`, `MODEL_NAME=/model-cache/models/<name>` | | when `source: modelImage` | air-gapped |
| `SKIP_VLLM=true`, `LLM_BACKEND_TYPE=vllm`, `LLM_BACKEND_URL` | | remote-model profile | |
| `SECRET_VAULT_ENABLED`, `SECRET_VAULT_KEK` (path) | | when `vault.enabled` | |

### 4.2 oc-only install: `rendered/<profile>/`

CI renders the chart with `helm template` once per profile into plain YAML,
plus a `kustomization.yaml` that exposes what customers change without
editing YAML: `namespace`, `images` (registry rewrite), and patches for
storage class and resources. Install is `oc apply -k rendered/<profile>/`.

The hand-maintained files keep their paths, so no link breaks:
`openshift/redis.yaml`, `openshift/shield-admin.yaml`,
`openshift/shield-guardrail-vllm.yaml` and their `docs/assets/openshift/`
copies become **generated** from the chart (header: "generated by
scripts/render_manifests.sh, do not edit"), rendered with values that keep
today's secret names.

### 4.3 Data plane: two small additions

- **1b. `GET /health/ready`** on both planes: 200 when the process is up and,
  if `REDIS_URL` or `UPSTASH_*` is configured, Redis answers; otherwise 503
  `{"status":"not_ready","reason":"redis_unreachable"}`. Unauthenticated like
  `/health`: the auth skip list is exact-match (`_SKIP_PATHS` in
  `core/middleware.py`), so the path is added there explicitly. Already exempt
  from the HTTPS redirect, which matches by `/health` prefix
  (`core/security_headers.py`). Returns no Redis address or error text.
- **2. `vllm` backend mode** (`core/llm_backend.py`): when
  `LLM_BACKEND_API_KEY` is set, send `Authorization: Bearer <key>`; when
  `LLM_MODEL_NAME` is set, send `model`. Only `LLM_BACKEND_API_KEY` counts in
  this mode, not `OPENROUTER_API_KEY` / `OLLAMA_API_KEY`, so a key meant for
  another service is never sent to the model endpoint. This lets the
  remote-model profile reach an OpenShift AI model served with token auth.

### 4.4 Release pipeline: `.github/workflows/release.yml` (new)

On a `v*` tag:

1. Build the four images as `build.yml` does, with the vLLM base pinned (build
   arg from `deploy/release/versions.env`), tagged `:vX.Y.Z`; buildx SBOM and
   provenance attestations on.
2. Sign each image digest with cosign (key-based, `COSIGN_PRIVATE_KEY` secret)
   so customers verify offline with `cosign.pub`, with no Sigstore/Rekor access.
3. Build and sign the model image (task 6) for the pinned Hugging Face revision.
4. Package the chart (`version` = `appVersion` = `X.Y.Z`, image refs by
   digest), push it as an OCI artifact, render `rendered/*`.
5. Write `images.txt`, `SHA256SUMS`, assemble the bundle, attach it to the
   GitHub Release.

`build.yml` on `main` is unchanged (`:latest`, `:v2`, `:<sha>` keep working
for RunPod and Railway).

## 5. Security and backward compatibility

- **Images under restricted-v2 without `anyuid` (task 1a).** App dirs and
  caches become `chgrp -R 0 && chmod -R g=u`, the OpenShift arbitrary-UID
  pattern. **No `USER` line is added**: the data plane defaults to port 80,
  and RunPod and Railway run these images as root; a non-root `USER` would
  break them. Root still works; the random UID now works too.
- **No secret values in the bundle or chart.** The chart only references
  existing Secrets; `secrets.*.existingSecret` defaults match today's names
  (`shield-admin-secrets`, `shield-guardrail`), so a customer re-applying the
  generated `openshift/*.yaml` keeps their Secrets. The inline `REPLACE_ME`
  Secret is removed. **Migration note:** create `shield-guardrail` before
  applying; without it the pod stops at `CreateContainerConfigError` (loud).
- **Redis auth on by default for new chart installs.** A customer coming from
  the old `openshift/redis.yaml` (no password) sets `redis.auth.enabled=false`,
  or adds the password to `REDIS_URL`. **Migration note** in the runbook.
- **Remote-model bearer (task 2)** is opt-in by setting the variable; unset
  is unchanged behavior.
- **No egress by default.** Telemetry export to Votal Elasticsearch needs
  `VOTAL_ES_URL` and `VOTAL_ES_API_KEY` (`core/telemetry.py`); the chart sets
  neither. The runbook states that nothing leaves the cluster unless the
  customer configures an exporter.
- **Supply chain.** Images by digest, cosign-signed, SBOM attached; the model
  image is pinned to a Hugging Face commit, not a branch.

## 6. Packaging and deploy

- **Dockerfiles:** `Dockerfile`, `Dockerfile.cloud`, `Dockerfile.admin` gain
  the group-permission lines (task 1a). No new COPY entries: task 1b's
  endpoint lives in modules both images already ship (`api/routes_health.py`
  on the data plane; the admin route in `admin_app.py`).
- **Python deps:** none new.
- **CI tools (not pip):** `helm` and `kubeconform` at pinned versions with
  checksum verification; `cosign` in the release workflow only.
- **New files:** `deploy/helm/shield/**`, `scripts/render_manifests.sh`,
  `deploy/release/{versions.env,mirror.sh,README.md.tmpl}`,
  `.github/workflows/release.yml`, model image `deploy/modelcar/Containerfile`.
- **Rebuild:** all images on the first release tag.

## 7. Failure modes and edge cases

| Case | Behavior |
|---|---|
| Secret missing | Pod `CreateContainerConfigError`; `NOTES.txt` and the runbook name the secret. Fail closed. |
| Redis unreachable at start or later | Today the stores silently fall back to memory. `/health/ready` returns 503, so the pod leaves the Service and traffic stops reaching a pod with a split store. Fail closed for routing; liveness stays green so it is not restart-looped. |
| Redis full | `noeviction` refuses writes; nonce store fails closed; runbook says alert on `used_memory`. |
| GPU without fp8 (A100, V100, T4) | `quantization: none`; values comment and runbook table. |
| Model image not mirrored (air-gapped) | init container `ImagePullBackOff`; `mirror.sh` covers it via `images.txt`. |
| `source: huggingface` on a cluster without egress | vLLM start fails; startup probe fails; runbook says use `modelImage`. |
| Model load slower than probes | startup probe budget sized for a cold 9.3 GB load; values allow raising it. |
| Customer cannot create namespaces (Developer Sandbox) | chart installs into the current namespace; no Namespace object. |
| No KServe CRDs | `modelServing.inferenceService.enabled=false` by default; enabling it without the CRD fails `oc apply` with a clear error. |
| Rendered YAML edited by hand in the repo | CI drift check fails (section 8). |
| `WORKERS` too high for limits | default 4; values comment ties workers to memory. |
| Two Redis clients (cloud) | unaffected: chart is on-prem only, and `UPSTASH_*` is never set by it. |

## 8. Test plan (Definition of Done)

Per task, in CI unless stated:

- **1a images:** a test reads each Dockerfile and asserts the `chgrp -R 0` /
  `chmod -R g=u` lines cover the app dir and every cache dir set by `ENV`, and
  that there is no `USER` line. Manual: run the admin image with
  `docker run --user 1000770000:0` and hit `/health`.
- **1b readiness:** unit tests: no Redis configured gives 200; configured and
  reachable gives 200; configured and unreachable gives 503; unauthenticated
  with `SHIELD_GUARD_REQUIRE_KEY=enforce`; not redirected to HTTPS.
- **2 bearer:** unset vars give a byte-identical payload and no
  `Authorization` header (regression guard); set vars add exactly the header
  and `model`; `OPENROUTER_API_KEY` alone is never sent in `vllm` mode.
- **3 chart:** `helm lint`; `helm template` for both profiles with
  `kubeconform -strict` (OpenShift `Route` validated against a vendored
  schema); assertions: no Secret with data, no Namespace/cluster-scoped kinds,
  every container has `PORT=8080`, data plane has `WORKERS`, all HF/vLLM cache
  vars point at the PVC, Redis has `noeviction`.
- **4 rendered output:** CI re-renders and fails on any diff in `rendered/`,
  `openshift/*.yaml` or `docs/assets/openshift/*.yaml` (the drift guard).
  `kustomize build rendered/<profile>` succeeds.
- **5 release:** a dry-run job on PRs that builds the bundle without pushing
  or signing; asserts `images.txt` lists every image referenced by the
  rendered YAML, by digest.
- **6 model image:** a CI job builds the model image and checks the weights'
  checksums against the pinned Hugging Face revision.
- **7 acceptance (manual, documented in the PR):**
  - OpenShift Developer Sandbox, `remote-model` profile pointed at an
    OpenAI-compatible endpoint: install once with `oc apply -k` and once with
    `helm install`; run the runbook's end-to-end check (tenant on admin,
    blocked prompt on data plane, `401` without a key, restart survives).
  - A GPU OpenShift cluster, `gpu` profile, model from the model image with
    `HF_HUB_OFFLINE=1`: same check, plus no Hugging Face request in pod logs.
- Full suite green in a clean venv (`requirements-test.txt` only); CI
  `pytest` gate passes.

## 9. Tasks (one PR each, in order)

| # | Task | Plane | Depends on |
|---|---|---|---|
| 0 | PR #539 merged (`noeviction`, both Redis clients) | storage | none |
| 1a | Images run under restricted-v2: group-writable app and cache dirs, no `USER` change | both images | none |
| 1b | `GET /health/ready` on both planes | both | none |
| 2 | `vllm` mode: optional `LLM_BACKEND_API_KEY` bearer and `LLM_MODEL_NAME` | data | none |
| 3 | Helm chart `deploy/helm/shield` (gpu + remote-model), CI lint/template/kubeconform | deploy | 1a, 1b |
| 4 | `scripts/render_manifests.sh`, `rendered/<profile>` with kustomization, regenerate `openshift/*.yaml` and docs copies, drift guard, runbook | deploy, docs | 3 |
| 5 | Release workflow: semver tags, pinned vLLM base, cosign, SBOM, chart OCI, bundle on GitHub Release, PR dry run | CI | 3, 4 |
| 6 | Model image (modelcar) + chart wiring (init-container copy for gpu, optional `InferenceService`) | deploy | 3 |
| 7 | Acceptance on real OpenShift (Sandbox and a GPU cluster); fixes found there | all | 4, 5, 6 |

Tasks 1a, 1b and 2 are independent and can run in parallel.

## 10. Decisions taken (change any before approval)

1. **Chart is the source; rendered YAML and `openshift/*.yaml` are generated.**
   Paths stay, so docs links keep working.
2. **Images stay on public Docker Hub** for now; customers mirror them.
   A private registry is a value change later, not a design change.
3. **cosign with a key pair**, not keyless, so disconnected customers can
   verify. The public key ships in every bundle.
4. **No `USER` in Dockerfiles**; group permissions only, to keep RunPod and
   Railway (root, port 80) working.
5. **Redis auth on by default** for new chart installs, with the escape hatch
   and migration note in section 5.
6. **`WORKERS=4`** chart default for the data plane.

## 11. Open questions (need an answer, not a design choice)

1. **Model redistribution:** Hugging Face lists `votal-ai/vai35-4B-v2` as
   `license: other`, based on `Qwen/Qwen3.5-4B`. Confirm Votal may ship the
   weights inside a customer-mirrored image.
2. **RTA's OpenShift AI version:** OCI model images in KServe
   (`storageUri: oci://...`) need a recent OpenShift AI release; task 6's
   `InferenceService` path depends on it. The init-container path does not.
