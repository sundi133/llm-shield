# Votal AI Shield for OpenShift {{VERSION}}

Install with **only `oc`** (4.12 or newer). No Git, no Helm.

## What is in this bundle

| File | What it is |
|---|---|
| `openshift/` | The install files. `openshift/README.md` is the full install and test guide. |
| `images.txt` | The four container images, each pinned by digest |
| `mirror.sh` | Copies the images into your registry and points the install files at it |
<!-- if-signed -->
| `cosign.pub` | Votal's public key: verifies the Votal images' signatures offline |
<!-- end-if-signed -->
| `SHA256SUMS` | Checksums of every file in this bundle |

Check the bundle arrived intact:

```bash
sha256sum -c SHA256SUMS
```

(macOS: `shasum -a 256 -c SHA256SUMS`)

<!-- if-signed -->
## Verify the images (optional, recommended)

The three Votal images are signed with the key in `cosign.pub`. On a machine
that can reach the images (before you mirror them), with
[cosign](https://github.com/sigstore/cosign) installed:

```bash
grep -v '^#' images.txt | grep -v '^redis' | while read -r name src tag; do cosign verify --key cosign.pub --insecure-ignore-tlog=true "$src" >/dev/null && echo "verified $name"; done
```

Each line must print `verified`. The install files pin the same digests, so
what you mirror and run is what you verified. (`--insecure-ignore-tlog` is
correct here: Votal signs with this key only, without a public transparency
log, so verification works fully offline.)

<!-- end-if-signed -->
## Step 1: get the images where your cluster can pull them

Pick the case that matches your network. Mirroring keeps each image's digest,
so you run exactly the images Votal built.

**A. Your cluster can pull from docker.io.** Nothing to do. Go to step 2.

**B. One machine reaches both docker.io and your registry.**

```bash
./mirror.sh to-registry registry.example.internal/votal
```

**C. Fully disconnected.** On a machine with internet access:

```bash
./mirror.sh to-dir ./shield-images
```

Carry `./shield-images` (about 10 GB, almost all of it the GPU model server
image) and this bundle inside, then:

```bash
./mirror.sh from-dir ./shield-images registry.example.internal/votal
```

Cases B and C also point `openshift/overlays/*` at your registry. Log in to your
registry first (`oc registry login`, or `REGISTRY_CONFIG=/path/to/auth.json`).

The guardrail model itself (about 9.3 GB) downloads from `huggingface.co` the
first time the model pod starts, then stays on its volume. If your cluster
cannot reach `huggingface.co`, ask Votal for the offline model package.

## Step 2: install and test

Follow `openshift/README.md` from "1. Project". In short:

```bash
oc new-project shield
```

Create the Secrets (`openshift/README.md`, step 2), then:

```bash
oc apply -k openshift/overlays/split
```

`split` runs four pods: Redis, the admin portal, the guardrail service (CPU) and
the guardrail model (one GPU). No GPU in this cluster? Use
`openshift/overlays/external` and point it at a model served elsewhere.
