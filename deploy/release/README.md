# Cutting a Shield release (on-prem bundle)

A version tag builds the images customers run, signs them, and publishes the
OpenShift install bundle as a GitHub Release
(`.github/workflows/release.yml`, spec `docs/specs/onprem-release-bundle.md`).

## One-time setup: the signing key

Releases are signed with a key pair, not keyless signing, so customers can
verify offline. Generate it on a trusted machine and store the private half
only in GitHub secrets:

```bash
cosign generate-key-pair
```

```bash
gh secret set COSIGN_PRIVATE_KEY < cosign.key
```

```bash
gh secret set COSIGN_PASSWORD
```

Then delete `cosign.key` from that machine, or move it to the company vault.
Every release puts the matching `cosign.pub` in the bundle and on the GitHub
Release. Rotating the key means old bundles still verify with their own
`cosign.pub`, and new ones carry the new one.

`DOCKER_PASSWORD` (Docker Hub, user `sundi133`) is already set for `build.yml`.

## Cut a release

From an up-to-date `main` that has passed CI:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

The workflow then:

1. builds `llm-shield`, `llm-shield-cloud` and `llm-shield-admin` as
   `:v1.0.0`, with the vLLM base pinned in `versions.env`, plus SBOM and
   provenance attestations;
2. signs each image digest with the key above (no transparency log upload, so
   verification needs no internet) and verifies each signature;
3. pins Redis (`versions.env`) by digest;
4. runs `make_bundle.py`: the `openshift/` install files with every image
   pinned by digest, `images.txt`, `mirror.sh`, `cosign.pub`, `README.md`,
   `SHA256SUMS`, as a reproducible `shield-openshift-v1.0.0.tar.gz`;
5. checks every overlay in the bundle builds, then publishes the tarball, its
   `.sha256` and `cosign.pub` on the GitHub Release `v1.0.0`.

Rebuild an existing tag: Actions, "Release", "Run workflow", version `v1.0.0`.

## Change a pinned input

Edit `versions.env` in a PR (for example a newer `vllm/vllm-openai` tag; take
its digest from `docker buildx imagetools inspect vllm/vllm-openai:<tag>`).
Never edit the workflow to change a version.

## Build a bundle by hand

For a customer before a tagged release exists, with digests you looked up:

```bash
python3 deploy/release/make_bundle.py --version v0.0.1 --images images.json --out dist
```

`images.json` format: see the top of `make_bundle.py`. Without
`--cosign-pub` the bundle is unsigned and its README says nothing about
signatures.
