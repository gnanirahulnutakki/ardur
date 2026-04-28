# Ardur — Go Reference Implementation

This is the Go side of Ardur: the runtime, the governance engine, and the Kubernetes operator. It mirrors the behaviour of the Python reference at the protocol layer, but the design intent is different — Go is where we want the work to land when throughput matters, where the governor sits inline as a sidecar or proxy, and where a controller has to reconcile CRs without burning a Python interpreter per pod.

## Module

```
module github.com/gnanirahulnutakki/ardur/go
```

The Go version is pinned in `go.mod`. You'll see `vibap.` everywhere in the source tree — that's the original protocol research name (VIBAP = Verifiable Identity-Bound Agent Passport) and it stays as the package prefix because it *is* the protocol's name. The user-facing project is **Ardur**; the CLI and operator binaries currently still print `vibap` in their identity strings (a follow-up commit will swap those to `ardur` once the CLI surface stabilises).

## Build

```bash
cd go
go mod tidy
go build ./...
go test -race ./...
```

## Layout

| Path | What lives here |
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

A note on why there are so many `cmd/` entries: they're genuinely separate binaries with different deploy shapes. `authority` is a long-lived service that issues credentials. `governor` is the inline policy decision point and runs as close to the agent as you can get it. `operator` and `webhook` are Kubernetes control-plane components — the operator owns reconciliation, the webhook owns admission — and keeping them as separate `main` packages lets each one ship with only the imports it actually needs. `cli` is the human-facing tool. Splitting them this way keeps each binary's dependency graph honest and makes vulnerability triage tractable.

## What's *not* in this tree

- **EDR connector.** The `cmd/edr_*` binaries and the `edr-connector` Go module stay private. They wrap CrowdStrike Falcon API calls under vendor-license context that hasn't been cleared for public release, so they're not something we can drop into an MIT repo.
- **Live benchmark fixtures.** The heavy corpora — AgentDojo, InjecAgent, R-Judge, STAC — remain in the internal research tree. They're large, redistribution terms vary, and they don't belong here. A reproducible smoke-benchmark harness will land later in a separate commit.

## Names that matter (don't drift these)

The public-facing identifiers are stable across the codebase:

- Module path: `github.com/gnanirahulnutakki/ardur/go`
- Schema `$id` base: `https://ardur.dev/spec/...`
- API GroupName: `vibap.ardur.dev`
- SPIFFE trust domain: `ardur.dev`
- Image refs in tests: `ghcr.io/ardur/...`

If you're contributing and you find yourself typing one of those by hand, double-check it against this list. Drift here breaks federation and breaks signature verification, and neither failure mode is loud.

## Verification status

Honest caveat: `go mod tidy`, `go build ./...`, and `go test -race ./...` haven't been run from this commit. The maintainer's local `go mod tidy && go build ./...` from a clean checkout is the verification gate before any tag gets published. CodeQL runs in CI on push and will pick up the Go tree automatically — that's the second layer.

If you're cloning this and the build is broken at HEAD, please open an issue; it means the gate caught nothing and we'd like to know.

## License

MIT — see [../LICENSE](../LICENSE).
