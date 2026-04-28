# Ardur — Go Reference Implementation

Go-side runtime + governance engine for Ardur. Mirrors the Python reference's behaviour at the protocol layer; aimed at high-throughput sidecar / proxy deployments and Kubernetes operator integration.

## Module

```
module github.com/gnanirahulnutakki/ardur/go
```

Go version pinned via `go.mod`. The `vibap.` package prefix throughout the source tree is the technical-lineage protocol research name (VIBAP = Verifiable Identity-Bound Agent Passport), kept because it's the protocol name. The user-facing project name is **Ardur**; the Go binaries below print "ardur" as their identity.

## Build

```bash
cd go
go mod tidy
go build ./...
go test -race ./...
```

## What's here

| Path | What it is |
|---|---|
| `pkg/aat` | Attenuating Authorization Token primitives + AAT chain verification |
| `pkg/api/v1alpha1` | CRD types for the Kubernetes operator (`AgentPassport`, etc.) |
| `pkg/credential` | Mission credential issuance + verification |
| `pkg/governance` | Core governance engine (verifier, composition) |
| `pkg/issuer` | Mission Declaration issuer + signing-key management |
| `pkg/policy` | Policy evaluation surface (Cedar bridge, native checks) |
| `pkg/profiling` | Performance profiling helpers |
| `pkg/provenance` | Tool-response provenance + receipt-chain verification |
| `pkg/spiffe` | SPIFFE/SPIRE identity binding |
| `pkg/transparency` | Transparency-log integration (sigstore Rekor) |
| `pkg/trust` | Trust-bundle management |
| `cmd/authority` | The credential-issuing authority service |
| `cmd/governor` | The governance proxy server |
| `cmd/cli` | Command-line tool (issue, verify, demo) |
| `cmd/operator` | Kubernetes operator (reconciles `AgentPassport` CRs) |
| `cmd/benchmark*` | Benchmark harnesses (private fixtures stay in the internal research tree) |
| `cmd/specvalidate` | Mission-declaration schema validator |
| `cmd/webhook` | Admission webhook for K8s |
| `spec/mission-governance/v0alpha1` | JSON schemas (declaration, decision, event, finding, session) |

## What's NOT here

- **EDR connector** — `cmd/edr_*` and the `edr-connector` Go module stay private (CrowdStrike Falcon API integration with vendor-license context that hasn't been cleared for public release).
- **Live benchmark fixtures** — heavy corpora (AgentDojo, InjecAgent, R-Judge, STAC) remain in the internal research tree; reproducible smoke benchmarks land in a future Phase 7 commit.

## Status

Phase 5 of the lift wave — Go runtime and operator files are now in this repository with the Ardur public name applied across:

- Module path: `github.com/gnanirahulnutakki/ardur/go`
- Schema URIs: `https://ardur.dev/...`
- API GroupName: `vibap.ardur.dev`
- SPIFFE trust domain: `ardur.dev`
- Image refs in tests: `ghcr.io/ardur/...`
- All docstring/comment references rebranded.

`go mod tidy` and `go build ./...` have NOT been run from this lift commit (no Go toolchain available in the lift environment). A maintainer running `go mod tidy && go build ./...` from a clean checkout is the verification gate. CodeQL CI will pick up the Go tree on the next push and run static analysis automatically.

## License

MIT — see [../LICENSE](../LICENSE).
