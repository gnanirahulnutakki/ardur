# kernelcapture proof harness (local-only)

This package is the Ardur Linux proof harness for process-lifecycle capture and kernel-effect synthetic receipts.

What it currently does:

- Correlates `exec` / `exit` process events to tool-call receipt candidates.
- Emits synthetic kernel-effect receipt fields, including:
  - `correlation_method`
  - `correlation_confidence`
  - `coverage_status`
  - `capture_loss`
- Enforces honesty behavior:
  - ambiguous attribution => `insufficient_evidence`
  - degraded/unknown coverage => `insufficient_evidence`
  - capture loss / consumer lag => degraded `insufficient_evidence`
  - daemon restart gap => unknown `insufficient_evidence`

Capture sources:

1. `RingbufProcessSource` (Linux only)
   - Uses `github.com/cilium/ebpf` ringbuf reader.
   - Expects an already-pinned ringbuf map path.
   - Reads a fixed process-lifecycle sample layout.
   - Carries kernel monotonic sample timestamps separately from wall clock.

2. `ReplayEventSource` (fallback)
   - Unprivileged deterministic source for local tests/demos.
   - Used to prove correlation/loss/restart behavior when privileged loading is unavailable.

Pinned-map trust boundary (required for privileged daemon use):

- `pinnedMapPath` must come from daemon-owned privileged config.
- Repository / mission config must not control privileged map-path selection.
- Privileged daemon deployments should use:
  - root-owned daemon config
  - root-owned restrictive bpffs namespace/path
  - explicit producer ownership/version checks before trusting samples

Concurrency contract:

- `Correlator` is goroutine-safe and supports concurrent receipt registration and event correlation.
- Race-safety is covered by `go test -race ./pkg/kernelcapture`.

Current boundary:

- This package does not install or persist a privileged daemon.
- It does not load/attach the eBPF producer program by itself.
- If no Linux privileged ringbuf producer exists, use `ReplayEventSource` and treat coverage as proof-harness scope only.
