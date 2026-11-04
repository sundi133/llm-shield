# Spec: on-prem release bundle (plain oc, Kustomize)

Status: APPROVED 2026-11-04 (revised the same day: Kustomize only, no Helm).

## 1. Problem and outcome

Enterprise customers (first: RTA, on OpenShift and OpenShift AI with H200 GPUs,
often without internet on cluster nodes) need to install and upgrade Shield
themselves. Today they get:

- hand-maintained manifests in `openshift/*.yaml`, copied by hand into
  `docs/assets/openshift/*.yaml`;
- images on public Docker Hub tagged `:latest`, `:v2` and `:<sha>`
  (`.github/workflows/build.yml`), unsigned, amd64 only;
- a model that the GPU pod downloads from Hugging Face on first start:
  `scripts/start_vllm.sh` runs vLLM with `--model "$MODEL_NAME"` (default
  `votal-ai/vai35-4B-v2`, public, about 9.3 GB). That stays the default
  model path; this spec only makes the download land on the PVC once, and
  adds an opt-in model image for clusters with no route to Hugging Face.

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

**Revision 2026-11-04: plain `oc` only.** The first draft made a Helm chart the
source and generated `oc apply -k` files from it. Customers never needed Helm
under that design either, so the chart only added a tool, a render step and a
drift check. This revision drops Helm: the install files are Kustomize, which
is built into `oc`, and the files we test are the files customers apply.

**Outcome.** Each release `vX.Y.Z` produces one bundle a customer installs
with **only `oc`**, on a connected or disconnected cluster:

```
shield-onprem-vX.Y.Z/
  README.md                 install, test and upgrade runbook
  openshift/                the Kustomize tree below, image refs pinned by digest
  images.txt                every image, by digest
  mirror.sh                 oc image mirror to dir / from dir, skopeo fallback
  cosign.pub                verifies every image signature offline
  SHA256SUMS
```

Install is: create the Secrets, then `oc apply -k openshift/overlays/<topology>`.

Success: on a real OpenShift cluster, `oc apply -k openshift/overlays/external`
(after creating the Secrets) brings up Redis, the admin portal and the
guardrail service, and the end-to-end check passes: a tenant created on the
admin plane is enforced by the data plane. `overlays/split` does the same on a
GPU node, with the model pod pulling the model from Hugging Face once into the
cache PVC (a restart does not re-download); and, for an air-gapped cluster,
from the mirrored model image with no Hugging Face access.

**Non-goals.**

- Helm. Revisit only if a customer requires it; a thin chart could then wrap
  the same YAML.
- An Operator or OperatorHub listing (later, if customers ask).
- Red Hat certification of images (later; this spec makes it possible).
- Multi-arch images (OpenShift customers in scope are amd64).
- Redis Cluster or Sentinel support (section 3 explains why Cluster cannot work).
- HA Redis in the bundle (customers who need it bring their own, via the
  `external-redis` component).
- Changing any guardrail behavior.

## 2. Plane and latency contract

- **Both planes**, packaging only: the manifests deploy the data plane
  (`core/app.py` via `handler.py`), the model server, the admin plane
  (`admin_app.py`) and Redis.
- **Off the hot path.** No change to `/guardrails/*`, `cap/mint` or
  `tools/call` handling. The two small code changes (tasks 1b and 2, merged in
  PR #541) are inert unless configured:
  - `vllm` backend mode sends a bearer token and model name **only when set**;
    unset, the model request is byte-identical to before.
  - `GET /health/ready` runs only when the kubelet probes it.

## 3. Data model

No new Redis keys. The bundle documents what Shield requires of Redis, which
the bundled Redis satisfies and an external one must:

| Requirement | Why |
|---|---|
| Redis 6.2+ (7.x recommended) or Valkey 7.2+ | `GETDEL` (oauth, signup, MCP OAuth stores) |
| Lua `EVAL` enabled | audit chain CAS (`storage/audit_chain.py`, two keys), MCP lock release |
| Standalone or primary/replica, **not Cluster** | multi-key `EVAL` and multi-key pipelines get `CROSSSLOT` in Cluster mode |
| One endpoint in `REDIS_URL` (`redis://`, `rediss://`, password in URL) | `redis.Redis.from_url`; Sentinel URLs are not supported |
| `maxmemory-policy noeviction` | Redis is the store of record for tenants, keys, policies, revocations and nonces (PR #539) |
| Persistence on (AOF) | same |
| `UPSTASH_*` unset on-prem | `_get_redis()` tries Upstash first if both vars are set |

Tenant scoping is unchanged: one Redis per install, tenants isolated by the
existing key layout.

## 4. API / interface

### 4.1 Install files: `openshift/` (Kustomize, applied with `oc apply -k`)

```
openshift/
  base/                     redis, admin, guardrail service; Services, Routes, NetworkPolicies
    kustomization.yaml      images: (registry + tag/digest), commonLabels
  components/               optional add-ons, each a Kustomize Component
    model-split/            the GPU model Deployment + Service + PVC; points the guardrail at it
    model-combined/         replaces the guardrail with one GPU pod running start_vllm.sh (RunPod style)
    model-external/         points the guardrail at LLM_BACKEND_URL from a ConfigMap
    model-offline/          init container copies weights from the model image into the PVC (task 6)
    vault/                  SECRET_VAULT_ENABLED + KEK file from a customer Secret
    redis-auth/             requirepass from a customer Secret
    external-redis/         removes the bundled Redis; REDIS_URL from the Secrets
    fp16/                   drops the fp8 flags for GPUs without fp8 (A100, V100, T4)
  overlays/
    split/                  base + model-split          (default for OpenShift)
    combined/               base + model-combined
    external/               base + model-external       (model served elsewhere, e.g. OpenShift AI)
  README.md                 the runbook: Secrets, install, test, upgrade, migration
```

A customer copies an overlay, then in its `kustomization.yaml` sets their
`namespace`, rewrites `images` to their mirror, adds components (`vault`,
`redis-auth`, ...) and patches resources or storage class. No YAML templating,
no extra tool: `oc` 4.x ships Kustomize, and Components are supported.

**Topologies.** RunPod runs the model and the guard API in one pod
(`start_vllm.sh` starts vLLM, then `exec python3 handler.py`). On OpenShift the
default splits them:

| Overlay | Pods | Use |
|---|---|---|
| `split` (default) | `shield-model` (GPU, `llm-shield` image, `VLLM_ONLY=true`, internal Service :8000) + `shield-guardrail` (CPU, `llm-shield-cloud` image, `SKIP_VLLM=true`, `LLM_BACKEND_TYPE=vllm`, `LLM_BACKEND_URL=http://shield-model:8000`) | Guardrail replicas scale on CPU and share one GPU; NetworkPolicy lets only guardrail pods reach the model |
| `combined` | one GPU pod running `start_vllm.sh` as on RunPod | Smallest footprint, one GPU per replica |
| `external` | `shield-guardrail` only, `LLM_BACKEND_URL` (and optional `LLM_BACKEND_API_KEY`, `LLM_MODEL_NAME`) to a model served elsewhere | Customer already serves the model (OpenShift AI, another cluster) |

The model pod uses the same `llm-shield` image as RunPod (the vLLM version
proven with this model) with `VLLM_ONLY=true` (task 2b), so vLLM runs with the
script's own flags and `handler.py` never starts; every cache variable plus
`HOME` points at the cache PVC.

Guardrail replicas share `SHIELD_AGENT_TOKEN_PRIVATE_KEY` and
`SHIELD_CAP_TOKEN_PRIVATE_KEY` from one Secret: without them each process
generates an ephemeral key (`core/signers.py`), so a token minted by one
replica fails on another. `CONFIG_PATH` is not set: `handler.py` overwrites
that file with the image default on every boot, so it holds no state.

**Objects** (namespace-scoped only, so a project admin can install into an
existing namespace; no `Namespace`, `ClusterRole`, CRD or SCC objects):
Deployments, Services, Routes, NetworkPolicies (Redis and the model accept only
Shield pods), PVCs (Redis data, model cache). No Secret objects: the customer
creates `shield-guardrail`, `shield-admin-secrets` and the optional ones, with
commands in the README.

**Probes:** liveness `GET /health`; readiness `GET /health/ready` (task 1b,
503 when Redis is unreachable); the model pod gets a startup probe with a
30-minute budget for a cold 9.3 GB download.

**Environment set by the manifests** (secrets by reference only):

| Var | Admin | Guardrail | Model pod | Value |
|---|---|---|---|---|
| `PORT` | 8080 | 8080 | | restricted-v2 cannot bind :80 |
| `WORKERS` | | 4 | | `handler.py` defaults to 32 |
| `SHIELD_GUARD_REQUIRE_KEY` | | `enforce` | | tenant isolation |
| `REDIS_URL`, `SHIELD_ADMIN_KEY` | Secret | Secret | | must match across planes |
| `SHIELD_AGENT_TOKEN_PRIVATE_KEY`, `SHIELD_CAP_TOKEN_PRIVATE_KEY` | | Secret | | shared by every replica |
| `SKIP_VLLM=true`, `LLM_BACKEND_TYPE=vllm`, `LLM_BACKEND_URL` | | split, external | | |
| `VLLM_ONLY=true`, `MODEL_NAME`, `SERVED_MODEL_NAME` | | | split | task 2b |
| `HOME`, `HF_HOME`, `HUGGINGFACE_HUB_CACHE`, `VLLM_CACHE_ROOT`, `TRITON_CACHE_DIR`, `TORCHINDUCTOR_CACHE_DIR`, `FLASHINFER_CACHE_DIR` | | | under the cache PVC | fixes the re-download |
| `HUGGING_FACE_HUB_TOKEN` | | | optional Secret | private or gated model only |
| `HF_HUB_OFFLINE=1`, local `MODEL_NAME` | | | `model-offline` | air-gapped |
| `SECRET_VAULT_ENABLED`, `SECRET_VAULT_KEK` (file) | | `vault` | | |

### 4.2 The old hand-written files

`openshift/redis.yaml`, `openshift/shield-admin.yaml`,
`openshift/shield-guardrail-vllm.yaml` and their `docs/assets/openshift/`
copies are **removed** in task 4, replaced by the tree above; the docs page
that links them (`docs/partners/rafay/integration.md`) points at
`openshift/overlays/` instead. **Migration note** in the README: the new
manifests keep the Secret names `shield-guardrail` and `shield-admin-secrets`
and the Service names, so an existing install moves over with
`oc apply -k openshift/overlays/combined` (same one-pod shape) after creating
the Secrets; the inline `REPLACE_ME` Secret is gone.

### 4.3 Code changes (done, PR #541)

- **1b. `GET /health/ready`** on both planes: 503
  `{"status":"not_ready","reason":"redis_unreachable"}` when Redis is configured
  but does not answer; its own connection with 2 s timeouts, never the app's
  client; unauthenticated (exact-match skip lists).
- **2. `vllm` backend mode**: `Authorization: Bearer` when
  `LLM_BACKEND_API_KEY` is set, `model` when `LLM_MODEL_NAME` is set; unset is
  byte-identical to before.
- **2b. `start_vllm.sh` `VLLM_ONLY=true`**: exec vLLM with the script's flags,
  no `handler.py`.

### 4.4 Release pipeline: `.github/workflows/release.yml` (new)

On a `v*` tag:

1. Build the four images as `build.yml` does, with the vLLM base pinned (build
   arg from `deploy/release/versions.env`), tagged `:vX.Y.Z`; buildx SBOM and
   provenance attestations on.
2. Sign each image digest with cosign (key-based, `COSIGN_PRIVATE_KEY` secret)
   so customers verify offline with `cosign.pub`, with no Sigstore/Rekor access.
3. Build and sign the model image (task 6) for the pinned Hugging Face revision.
4. Copy `openshift/` into the bundle with `images:` in `base/kustomization.yaml`
   rewritten to the release digests (`kustomize edit set image`, run by `oc`'s
   embedded Kustomize or the standalone binary).
5. Write `images.txt`, `SHA256SUMS`, assemble the bundle, attach it to the
   GitHub Release.

`build.yml` on `main` is unchanged (`:latest`, `:v2`, `:<sha>` keep working
for RunPod and Railway).

## 5. Security and backward compatibility

- **Images under restricted-v2 without `anyuid` (task 1a, done).** Group-0
  permissions on app and cache dirs. **No `USER` line**: RunPod and Railway run
  these images as root on port 80, and a non-root `USER` would break them.
  Pepper flags `DOCKERFILE-NO-USER` on `Dockerfile` for this reason; it is a
  deliberate decision, dismissed in Pepper.
- **No secret values in the bundle.** The manifests only reference Secrets the
  customer creates. Missing Secret means `CreateContainerConfigError` (loud).
- **Redis auth is a component** (`redis-auth`), on in the `split` and
  `external` overlays for new installs. A customer moving from the old
  `openshift/redis.yaml` (no password) uses an overlay without it, or adds the
  password to `REDIS_URL`. Migration note in the README.
- **Remote-model bearer (task 2)** is opt-in; unset is unchanged behavior.
- **No egress by default.** Telemetry export to Votal Elasticsearch needs
  `VOTAL_ES_URL` and `VOTAL_ES_API_KEY` (`core/telemetry.py`); the manifests set
  neither. The README states that nothing leaves the cluster unless the
  customer configures an exporter. The default `split` overlay downloads the
  model from Hugging Face once; `model-offline` removes that too.
- **Supply chain.** Images by digest, cosign-signed, SBOM attached; the model
  image is pinned to a Hugging Face commit, not a branch.

## 6. Packaging and deploy

- **Dockerfiles:** done in task 1a. No Python deps added; no
  `Dockerfile.admin` COPY change.
- **CI tools (not pip):** `kubectl kustomize` (preinstalled on GitHub runners)
  and `kubeconform` at a pinned version with checksum verification; `cosign`
  in the release workflow only. No Helm.
- **New files:** `openshift/**` (tree above), `deploy/release/{versions.env,
  mirror.sh}`, `.github/workflows/release.yml`, model image
  `deploy/modelcar/Containerfile`.
- **Rebuild:** all images on the first release tag.

## 7. Failure modes and edge cases

| Case | Behavior |
|---|---|
| Secret missing | Pod `CreateContainerConfigError`; the README names each Secret. Fail closed. |
| Redis unreachable at start or later | `/health/ready` returns 503, so the pod leaves the Service instead of serving from a per-process memory store. Liveness stays green, so it is not restart-looped. |
| Redis full | `noeviction` refuses writes; nonce store fails closed; README says alert on `used_memory`. |
| GPU without fp8 (A100, V100, T4) | add the `fp16` component. |
| Model not reachable from guardrail pods (`split`) | Guardrail init container waits on `shield-model:8000/health`; pods stay `Init` with a clear log line. |
| No egress to huggingface.co (`split`, `combined`) | vLLM download fails, startup probe fails; README says allow huggingface.co or add `model-offline`. |
| Hugging Face outage on first start | Retried by the pod restart; once cached on the PVC, later starts need no Hugging Face access. |
| Model image not mirrored (air-gapped) | init container `ImagePullBackOff`; `mirror.sh` covers it via `images.txt`. |
| Customer cannot create namespaces (Developer Sandbox) | everything is namespace-scoped; set `namespace:` or apply in the current project. |
| No GPU at all | `external` overlay. |
| Customer edits base files | Their own fork; the README says to change only overlay `kustomization.yaml` so upgrades stay a copy-over. |
| `WORKERS` too high for limits | default 4, documented next to the memory limit. |
| Two Redis clients (cloud) | unaffected: the manifests are on-prem only and never set `UPSTASH_*`. |

## 8. Test plan (Definition of Done)

Done (PR #541): 1a, 1b, 2, 2b, each with tests that fail on the old code.

- **3 install files (CI job `openshift manifests`):** `kubectl kustomize` builds
  every overlay, and every overlay plus each optional component; `kubeconform
  -strict` validates the output (OpenShift `Route` against a vendored schema).
  A pytest suite over the built YAML asserts: no `Secret` objects; no
  `Namespace` or cluster-scoped kinds; no `namespace:` hardcoded in base;
  admin and guardrail have `PORT=8080`; guardrail has `WORKERS=4`,
  `SHIELD_GUARD_REQUIRE_KEY=enforce`, readiness on `/health/ready`, and the
  token keys from the Secret; the model pod has `VLLM_ONLY=true` and every
  cache variable under the PVC mount; Redis has `noeviction`; the model's
  NetworkPolicy admits only guardrail pods; no image uses `:latest`.
- **4 docs:** the README runbook; old files removed; the Rafay doc link updated;
  a docs test that every `oc apply -k` path in the README exists.
- **5 release:** a dry-run job on PRs builds the bundle without pushing or
  signing and asserts `images.txt` lists every image the built YAML references,
  by digest.
- **6 model image:** a CI job builds it and checks the weights' checksums
  against the pinned Hugging Face revision.
- **7 acceptance (manual, documented in the PR):**
  - OpenShift Developer Sandbox, `external` overlay pointed at an
    OpenAI-compatible endpoint: `oc apply -k`, then the README's end-to-end
    check (tenant on admin, blocked prompt on data plane, `401` without a key,
    restart survives, `/health/ready` goes 503 when Redis is scaled to 0).
  - A GPU OpenShift cluster, `split` overlay: same check; then delete the model
    pod and confirm the restart loads from the PVC with no download.
  - If task 6 is built: the same with `model-offline`, plus no Hugging Face
    request in pod logs.
- Full suite green in a clean venv (`requirements-test.txt` only); CI
  `pytest` gate passes.

## 9. Tasks (one PR each, in order)

| # | Task | Status |
|---|---|---|
| 0 | Redis client compat + `noeviction` | PR #539 |
| 1a | Images run under restricted-v2 without `anyuid` | PR #541 |
| 1b | `GET /health/ready` on both planes | PR #541 |
| 2 | `vllm` mode: optional bearer and model name | PR #541 |
| 2b | `start_vllm.sh` `VLLM_ONLY=true` | PR #541 |
| 3 | `openshift/` Kustomize tree (base, components, overlays) + CI job | next |
| 4 | README runbook, remove the old files, update links | after 3 |
| 5 | Release workflow: semver tags, pinned vLLM base, cosign, SBOM, bundle | after 3 |
| 6 | **Optional, air-gapped only:** model image + `model-offline` component | after 3 |
| 7 | Acceptance on real OpenShift (Sandbox and a GPU cluster) | after 4, 5 |

## 10. Decisions taken

1. **Kustomize only, no Helm** (2026-11-04). Customers and CI use plain `oc`.
2. **Images stay on public Docker Hub** for now; customers mirror them.
3. **cosign with a key pair**, not keyless, so disconnected customers can
   verify. The public key ships in every bundle.
4. **No `USER` in Dockerfiles**; group permissions only, to keep RunPod and
   Railway (root, port 80) working.
5. **Redis auth on** in the `split` and `external` overlays for new installs.
6. **`WORKERS=4`** for the guardrail service.

## 11. Open questions (need an answer, not a design choice)

1. **Model redistribution (task 6 only):** Hugging Face lists
   `votal-ai/vai35-4B-v2` as `license: other`, based on `Qwen/Qwen3.5-4B`.
   Confirm Votal may ship the weights inside a customer-mirrored image.
2. **Does RTA's GPU cluster reach huggingface.co?** If yes, the default
   download path is all they need and task 6 can wait.
3. **RTA's OpenShift AI version:** matters only if they want OpenShift AI to
   serve the model (the `external` overlay pointed at an `InferenceService`).
