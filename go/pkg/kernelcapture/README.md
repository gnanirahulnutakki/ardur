# kernelcapture proof harness

This package is the Ardur Linux proof harness for process-exec capture with paired process-exit lifecycle metadata and kernel-effect synthetic receipts.

## What it currently does

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
- Includes a Linux-only Phase 2 eBPF MVP smoke path that:
  - loads the embedded `sched/sched_process_exec` + `sched/sched_process_exit` eBPF tracepoint programs.
  - reads scoped process exec+exit lifecycle samples from a ringbuf.
  - runs a deterministic child command.
  - projects the observed exec and exit events through the same correlator.

## Capture sources

1. `RunLinuxEBPFExecSmoke` (Linux only, privileged/gated)
   - Loads the generated eBPF object with `github.com/cilium/ebpf`.
   - Attaches `sched/sched_process_exec` and `sched/sched_process_exit` through tracefs/debugfs.
   - Emits metadata-only lifecycle events: PID, PPID, TID, PID namespace id, cgroup id, monotonic timestamp, `comm`, and `exit_code` on exit events.
   - Does not collect argv, env, file contents, network destinations, or raw command payloads.

2. `RingbufProcessSource` (Linux only)
   - Uses `github.com/cilium/ebpf` ringbuf reader.
   - Supports an already-pinned ringbuf map path for future daemon integration.
   - Reads a fixed process-lifecycle sample layout.
   - Carries kernel monotonic sample timestamps separately from wall clock.

3. `ReplayEventSource` (fallback)
   - Unprivileged deterministic source for local tests/demos.
   - Used to prove correlation/loss/restart behavior when privileged loading is unavailable.

## Generate the eBPF object

The generated object is committed with the package so ordinary unit tests do not require clang.
Regenerate only in a Linux dev image with clang/LLVM/libbpf headers available:

```bash
cd go
go generate ./pkg/kernelcapture
```

## Verification commands

Default tests are unprivileged and should pass on macOS and Linux:

```bash
cd go
go test ./pkg/kernelcapture -count=1
go test -race ./pkg/kernelcapture -count=1
GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test
```

The live eBPF smoke is intentionally gated because it needs a Linux kernel, BTF, tracefs/debugfs, BPF privileges, and enough memlock. In the local Podman-machine proof environment it was run with a rootful privileged container:

```bash
sudo podman run --rm --privileged --pid=host --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  -v "$PWD/go:/workspace/go" \
  -w /workspace/go \
  -e ARDUR_RUN_EBPF_SMOKE=1 \
  ardur-ebpf-dev:fedora43 \
  go test -v ./pkg/kernelcapture -run TestLinuxEBPFExecSmoke -count=1
```

Rootless privileged containers can still fail if memlock cannot be raised or tracefs/debugfs are not visible. Treat that as environment evidence, not a product pass.

## Privileged boundary

This package does not install a daemon, persist maps, open a service, or manage system startup.
For a future daemon path:

- `pinnedMapPath` must come from daemon-owned privileged config.
- Repository / mission config must not control privileged map-path selection.
- Privileged daemon deployments should use:
  - root-owned daemon config
  - root-owned restrictive bpffs namespace/path
  - explicit producer ownership/version checks before trusting samples

## Concurrency contract

- `Correlator` is goroutine-safe and supports concurrent receipt registration and event correlation.
- Race-safety is covered by `go test -race ./pkg/kernelcapture`.

## Current MVP claim boundary

Allowed claim after the gated smoke passes:

Ardur has a local Linux eBPF process-exec MVP with paired process-exit evidence: in a privileged Linux container/VM it can load `sched_process_exec`/`sched_process_exit` tracepoint producers, read scoped ringbuf exec+exit metadata events, and project them into honest synthetic kernel-effect evidence.

Not claimed yet:

- production daemon readiness
- universal CLI capture
- file/network/privilege side-effect capture
- macOS/Windows kernel capture
- unprivileged/no-install eBPF support
