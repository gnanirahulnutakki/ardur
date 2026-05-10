# Ardur Phase 2 eBPF MVP Verification Report — 2026-05-10

Status: PASS for the narrow local Linux process-exec eBPF MVP.
Worktree: `/Users/gnutakki/.hermes/workspace/projects/ardur/worktrees/phase2-ebpf-mvp-2026-05-10`
Branch: `phase2-ebpf-mvp-2026-05-10`
Base: `origin/dev` at `7f001bc`

## Implemented MVP slice

Added `go/pkg/kernelcapture` as a Linux process-capture proof harness with:

- Correlator for kernel process events -> synthetic kernel-effect receipts.
- Replay event source for unprivileged deterministic tests.
- Ringbuf decoder/source with explicit PID namespace and cgroup fields.
- Linux-only generated eBPF object for `sched/sched_process_exec`.
- Linux-only loader/smoke path using `github.com/cilium/ebpf`.
- Repo-local smoke runner: `scripts/run-phase2-ebpf-smoke.sh`.
- Gated live smoke test `TestLinuxEBPFExecSmoke` behind `ARDUR_RUN_EBPF_SMOKE=1`.
- README claim boundary and verification instructions.

The eBPF producer emits metadata-only exec events:

- event type
- kernel monotonic timestamp
- PID
- PPID
- TID
- PID namespace id
- cgroup id
- `comm`

It does not collect argv, env, file contents, network destinations, or raw payloads.

## Tooling evidence

Local dev image:

- rootless image: `ardur-ebpf-dev:fedora43`
- rootful image: `ardur-ebpf-dev:fedora43`
- Go: `go1.25.9 linux/arm64`
- clang/LLVM: `21.1.8`
- bpftool: `7.6.0`
- kernel/BTF target: Fedora CoreOS Podman machine, `6.19.7-200.fc43.aarch64`, `/sys/kernel/btf/vmlinux` readable

Rootless privileged container limitation observed:

- effective caps were broad, but memlock remained `8192` and map creation failed.
- raw output: `reports/phase2-ebpf-smoke-output.txt`.
- this is recorded as environment evidence, not as product failure.

Passing live smoke used rootful Podman inside the local Podman machine with:

- `--privileged`
- `--pid=host`
- `--ulimit memlock=-1:-1`
- tracefs/debugfs bind mounts

## Verification commands run

### Host/offline unit

```bash
cd go
go test ./pkg/kernelcapture -count=1
```

Result:

```text
ok  	github.com/gnanirahulnutakki/ardur/go/pkg/kernelcapture	0.402s
```

### Host race

```bash
cd go
go test -race ./pkg/kernelcapture -count=1
```

Result:

```text
ok  	github.com/gnanirahulnutakki/ardur/go/pkg/kernelcapture	1.575s
```

### Linux arm64 compile gate

```bash
cd go
GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test
```

Result:

```text
-rwxr-xr-x@ 1 gnutakki  staff  6053599 May 10 01:31 /tmp/kernelcapture-linux-arm64.test
```

### Linux container unit, smoke gated off

```bash
podman run --rm -v "$WT/go:/workspace/go" -w /workspace/go ardur-ebpf-dev:fedora43 \
  sh -lc 'go test ./pkg/kernelcapture -count=1'
```

Result:

```text
ok  	github.com/gnanirahulnutakki/ardur/go/pkg/kernelcapture	0.090s
```

### Rootful privileged Linux eBPF smoke

Primary repeatable command:

```bash
scripts/run-phase2-ebpf-smoke.sh
```

Equivalent expanded command:

```bash
sudo podman run --rm --privileged --pid=host --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  -v "$WT/go:/workspace/go" \
  -w /workspace/go \
  -e ARDUR_RUN_EBPF_SMOKE=1 \
  ardur-ebpf-dev:fedora43 \
  sh -lc 'go test -v ./pkg/kernelcapture -run TestLinuxEBPFExecSmoke -count=1'
```

Result excerpt from `reports/phase2-ebpf-smoke-output-rootful.txt` after the repo-local smoke runner:

```text
2026-05-10T06:40:31Z
Linux 1a8ebf40ddd1 6.19.7-200.fc43.aarch64 #1 SMP PREEMPT_DYNAMIC Thu Mar 12 15:54:05 UTC 2026 aarch64 GNU/Linux
BTF=yes
debugfs on /sys/kernel/debug type debugfs (rw,nosuid,nodev,noexec,relatime,seclabel)
tracefs on /sys/kernel/tracing type tracefs (rw,relatime,seclabel)
unlimited
CapEff:	000001ffffffffff
=== RUN   TestLinuxEBPFExecSmoke
    linux_ebpf_smoke_linux_test.go:56: kernel=6.19.7-200.fc43.aarch64 btf=true tracepoint=sched/sched_process_exec command=[/usr/bin/true] observed_events=1 event_pid=23437 ppid=23430 tid=23437 pid_ns=4026531836 cgroup=16518 comm="true" coverage=complete correlation=explicit_pid/high verdict=compliant
--- PASS: TestLinuxEBPFExecSmoke (0.12s)
PASS
ok  	github.com/gnanirahulnutakki/ardur/go/pkg/kernelcapture	0.128s
```

### Local quick repo hygiene

First run failed because the local Python venv did not yet have PyYAML. I ran the repo setup script to install the Python dev dependencies, then re-ran the quick check.

```bash
./scripts/setup-dev.sh --skip-go
./scripts/check-local.sh --quick
```

Result:

```text
all quick checks passed
```

## Acceptance result

PASS for the narrow MVP:

Ardur can load a local Linux eBPF tracepoint producer, attach `sched/sched_process_exec`, stream one process exec sample through a ringbuf, decode process identity metadata, and produce a synthetic kernel-effect receipt with:

- `coverage_status=complete`
- `correlation_method=explicit_pid`
- `correlation_confidence=high`
- `verdict=compliant`

## Claim boundary

Allowed claim:

Ardur has a local Linux eBPF process-exec MVP: in a privileged Linux container/VM it can load an eBPF tracepoint producer, read ringbuf process lifecycle events, and project them into honest synthetic kernel-effect evidence.

Not claimed:

- production daemon readiness
- universal CLI capture
- file/network/privilege side-effect capture
- macOS/Windows kernel capture
- unprivileged/no-install eBPF support
- persistent bpffs map custody

## Next engineering tasks

1. Add an actual daemon boundary and root-owned config for eBPF object loading/map custody.
2. Add process-exit event capture.
3. Add cgroup/session-scoped filtering before ringbuf emission to reduce userspace filtering.
4. Add file/network side-effect event classes separately with explicit claim boundaries.
5. Add installation and operator docs only after daemon custody and privilege model are reviewed.
