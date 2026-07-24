# go-agent — SPIFFE workload identity to Shield (Go)

A minimal Go workload that authenticates to Shield with a SPIFFE X.509 SVID over
mTLS — the Go counterpart to `examples/langchain/spiffe_guarded_e2e.py`.

It fetches its SVID from the SPIRE Agent **Workload API** socket (auto-rotated by
`go-spiffe`'s `X509Source` — never cache the cert yourself), presents it over mTLS
to the Envoy front door, and mints a Shield agent token.

## Run

Needs a running Identity Bundle (SPIRE + Envoy, see
[docs/identity-bundle.md](https://docs.shield.votal.ai/workload-identity-bundle/))
and a registered workload.

```bash
SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock \
SHIELD_ENVOY=https://envoy:8443 \
  go run .
```

Expected: `workload identity: spiffe://<domain>/agent/...` then
`agent token minted via SPIFFE identity`. From there, send `X-Agent-Token` on
`/v1/shield/cap/mint` per tool call, then make guarded calls.

## Notes

- **No client-side trust of the server identity** — `AuthorizeAny()` is used
  because Envoy (not this client) enforces mTLS. The client only needs a valid SVID.
- **Rotation is automatic** — `X509Source` streams a fresh SVID before the old one
  expires (default TTL 1h). Do not persist the cert.
- **Other languages:** `java-spiffe` (Java), `@spiffe/svid` (Node) follow the same
  Workload API contract.

Verified: `go build ./...` and `go vet ./...` pass (go-spiffe v2). CI builds it on
every identity change.
