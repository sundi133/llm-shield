# Releasing the MCP scanner suite

The scanner, its distribution wrappers, the registry, and the small-team gateway
all shipped to `main` behind package/version scaffolding. Nothing is published to
a public registry yet. This is the maintainer runbook to make the
`pipx install` / `npx` / `uses:` / `docker run` commands real for outside users.

Do the steps **in order** — later ones depend on earlier ones.

## 0. One-time prerequisites

- [ ] Reserve the **PyPI** project name `shield-mcp` (create it under the Votal org
      or your account).
- [ ] Reserve the **npm** name `@votal/mcp-scan` (the `@votal` scope must exist and
      you must be a member).
- [ ] Create the public repo **`votal/mcp-scan-action`** (empty; it will hold the
      GitHub Action for the Marketplace).
- [ ] Add repository/org **secrets**:
  - `PYPI_API_TOKEN` — a PyPI project-scoped API token for `shield-mcp`
    (or configure Trusted Publishing and drop the token).
  - `NPM_TOKEN` — an npm automation token with publish rights to `@votal`.
- [ ] Decide the container registry for the gateway image (Docker Hub `sundi133/…`
      matches the existing `build.yml`, or GHCR).

## 1. Publish `shield-mcp` to PyPI + the standalone binaries

Both fire off the **same tag**. Tag `shield-mcp-v<version>` (matching
`packages/shield-mcp/pyproject.toml` `version`) and push it:

```bash
git tag shield-mcp-v0.1.0
git push origin shield-mcp-v0.1.0
```

This triggers:
- [ ] **`.github/workflows/release-shield-mcp.yml`** → builds the sdist+wheel,
      `twine check`, and uploads to PyPI (needs `PYPI_API_TOKEN`). Verify:
      `pipx install shield-mcp && shield-mcp scan --help`.
- [ ] **`.github/workflows/build-shield-mcp-binaries.yml`** → PyInstaller binaries
      for linux/macos x64+arm64 and windows x64, attached to the GitHub Release
      with a `SHA256SUMS`. Verify the Release has all 5 assets + `SHA256SUMS`.

> The npx wrapper's binary fallback is pinned to `shield-mcp-v0.1.0`
> (`packages/mcp-scan-npm/src/resolve.js` `RELEASE_TAG`). If you tag a different
> version, bump that constant (and the npm `version`) together before step 3.

## 2. (once PyPI is live) confirm the Action installs from PyPI

The composite action installs `shield-mcp` from PyPI when it isn't already on PATH.
No action needed here beyond step 1 completing — the self-test workflow
(`mcp-scan-action-selftest.yml`) already preinstalls the local build for CI.

## 3. Publish `@votal/mcp-scan` to npm

Do this **after** step 1 (the wrapper downloads the pinned binaries as its
fallback). From `packages/mcp-scan-npm`:

```bash
cd packages/mcp-scan-npm
npm publish --access public     # uses NPM_TOKEN in CI, or `npm login` locally
```

- [ ] Verify: `npx @votal/mcp-scan --help`, then a real scan against a server that
      has a local `shield-mcp` (fast path) and one that doesn't (binary fallback).

## 4. Publish the GitHub Action to the Marketplace

The action source lives in `packages/mcp-scan-action/` (`action.yml` + `scan.sh`).
Mirror it to the dedicated repo and publish:

- [ ] Copy `packages/mcp-scan-action/*` to the root of `votal/mcp-scan-action`.
- [ ] Tag it `v1` (and a moving `v1` major tag) in that repo.
- [ ] In that repo's GitHub UI: **Releases → Publish this Action to the
      Marketplace**.
- [ ] Verify a workflow elsewhere can use `uses: votal/mcp-scan-action@v1`.

Keep `packages/mcp-scan-action/` as the source of truth; re-mirror on changes.

## 5. Build + publish the small-team gateway image

```bash
docker build -f Dockerfile.gateway -t sundi133/shield-mcp-gateway:0.1.0 -t sundi133/shield-mcp-gateway:latest .
docker push sundi133/shield-mcp-gateway:0.1.0
docker push sundi133/shield-mcp-gateway:latest
```

- [ ] Update `docker-compose.gateway.yml` / docs if the image name differs from
      `shield-mcp-gateway`.
- [ ] Verify: `docker run -p 8080:8080 -v $PWD/examples/mcp_gateway_lite/gateway.yaml:/etc/mcp-gateway/gateway.yaml sundi133/shield-mcp-gateway` then hit `/health`.

## 6. Registry (already automated)

`.github/workflows/mcp-registry.yml` regenerates `docs/registry/**` weekly (and on
manual dispatch) and opens a PR — no manual publish. Merge the PR to update the
public ratings on the Pages site. Ensure the workflow can install `shield-mcp`
(it uses the local build today; switch to `pipx install shield-mcp` once step 1 is
live if you prefer).

## Version bumps (subsequent releases)

1. Bump `packages/shield-mcp/pyproject.toml` `version` **and**
   `packages/mcp-scan-npm/src/resolve.js` `RELEASE_TAG` + `package.json` `version`.
2. Tag `shield-mcp-v<new>` → PyPI + binaries (step 1).
3. `npm publish` the wrapper (step 3).
4. Re-mirror + re-tag the Action if it changed (step 4).
5. Rebuild + push the gateway image if `core/mcp/` or its deps changed (step 5).
