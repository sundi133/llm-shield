# shield-identity Helm chart

Kubernetes front door for the Shield Identity Bundle: an **Envoy mTLS proxy** that
verifies workload SVIDs (via the SPIFFE CSI driver / SPIRE Agent Workload API),
injects a sanitized `X-Forwarded-Client-Cert` + shared-secret `X-Shield-Proxy-Token`,
and proxies to the Shield data plane. Optionally creates a `ClusterSPIFFEID` for
pod-annotation auto-registration.

> **Status: authored, not yet cluster-validated.** `helm lint` and `helm template`
> pass (and run in CI). Validate on a `kind` cluster before production — see below.

This chart does **not** install SPIRE. Install SPIRE (server, agent DaemonSet, CSI
driver, Controller Manager, CRDs) with the official hardened chart first.

## Prerequisites

```bash
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm repo update

# CRDs, then SPIRE — set YOUR trust domain
helm upgrade --install spire-crds spiffe/spire-crds -n spire-mgmt --create-namespace
helm upgrade --install spire spiffe/spire -n spire-mgmt \
  --set global.spire.trustDomain=bank-co.internal \
  --set spire-agent.workloadAttestors.k8s.enabled=true
```

## Install this chart

```bash
helm upgrade --install shield-identity ./deploy/helm/shield-identity \
  --namespace shield --create-namespace \
  --set trustDomain=bank-co.internal \
  --set shield.upstreamHost=shield \
  --set shield.upstreamPort=8000 \
  --set proxySecret.value="$(openssl rand -hex 32)"     # or --set proxySecret.existingSecret=...
```

Then configure the Shield data plane (same secret):
```
SHIELD_SPIFFE_ENABLED=true
SHIELD_SPIFFE_TRUST_DOMAIN=bank-co.internal
SHIELD_TRUSTED_PROXY_ONLY=true
SHIELD_TRUSTED_PROXY_SECRET=<same value as proxySecret>
SHIELD_WORKLOAD_IDENTITY_PROVIDERS=spiffe,admin_key
```

## Key values

| Value | Default | Notes |
|---|---|---|
| `trustDomain` | `example.org` | must match the SPIRE install |
| `shield.upstreamHost` / `upstreamPort` | `shield` / `8000` | the Shield data-plane service |
| `proxySecret.value` | `""` | chart creates a Secret; **or** set `proxySecret.existingSecret` |
| `proxySecret.existingSecret` | `""` | reference a Secret (key `token`) from your manager — keeps the value out of values files |
| `autoRegister.enabled` | `true` | create a `ClusterSPIFFEID` for matched pods |
| `autoRegister.podSelector.matchLabels` | `spiffe.io/identity: shield-agent` | which pods get an SVID |
| `spiffeCSI.socketPath` | `/spiffe-workload-api/spire-agent.sock` | Workload API socket (CSI mount) |

The proxy token is rendered from the Secret into the Envoy config by an
initContainer, so it never lives in the ConfigMap.

## Validate on a cluster

```bash
kind create cluster
# install SPIRE (prereqs above), then this chart, then:
helm test ...        # (no bundled tests yet)
# port-forward the Envoy service and run the smoke script from an agent pod:
#   scripts/smoke_identity_bundle.sh   (see docs/identity-bundle.md)
```

CI runs `helm lint` + `helm template` on every change; the on-cluster smoke is the
manual pre-release gate.
