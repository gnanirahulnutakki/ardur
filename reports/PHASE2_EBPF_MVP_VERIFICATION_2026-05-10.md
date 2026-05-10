# Ardur Phase 2 eBPF MVP Verification Report — 2026-05-10

Status: PASS for the narrow local Linux process lifecycle eBPF MVP (`exec` + `exit`) plus a cgroup-guarded userspace process-tree/session smoke.
Worktree: `phase2-ebpf-mvp-2026-05-10 worktree`
Branch: `phase2-ebpf-mvp-2026-05-10`
Base: `origin/dev` at `7341186`

## Implemented MVP slice

Added `go/pkg/kernelcapture` as a Linux process-capture proof harness with:

- Correlator for kernel process events -> synthetic kernel-effect receipts.
- Replay event source for unprivileged deterministic tests.
- Ringbuf decoder/source with explicit PID namespace, cgroup, and exit-code fields.
- Linux-only generated eBPF object for `sched/sched_process_exec` and `sched/sched_process_exit`.
- Linux-only loader/smoke path using `github.com/cilium/ebpf`.
- Repo-local smoke runner: `scripts/run-phase2-ebpf-smoke.sh`.
- Gated live smoke tests `TestLinuxEBPFExecSmoke` and `TestLinuxEBPFSessionSmoke` behind `ARDUR_RUN_EBPF_SMOKE=1`.
- Userspace `ProcessTreeScope` for the local MVP harness: seed from the launched root PID, guard by cgroup id, admit descendants by PPID lineage, retire exited PIDs, and retain optional start-time identity when present.
- README claim boundary and verification instructions.

The eBPF producer emits metadata-only exec+exit events:

- event type
- kernel monotonic timestamp
- PID
- PPID
- TID
- PID namespace id
- cgroup id
- `comm`
- `exit_code` on exit events

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
  sh -lc 'go test -v ./pkg/kernelcapture -run TestLinuxEBPF -count=1'
```

Result excerpt from `reports/phase2-ebpf-smoke-output-rootful.txt` after the repo-local smoke runner:

```text
2026-05-10T08:30:07Z
Linux 2ffaeb3b2449 6.19.7-200.fc43.aarch64 #1 SMP PREEMPT_DYNAMIC Thu Mar 12 15:54:05 UTC 2026 aarch64 GNU/Linux
BTF=yes
tracefs on /sys/kernel/tracing type tracefs (rw,relatime,seclabel)
debugfs on /sys/kernel/debug type debugfs (rw,nosuid,nodev,noexec,relatime,seclabel)
unlimited
CapEff:	000001ffffffffff
=== RUN   TestLinuxEBPFExecSmoke
    linux_ebpf_smoke_linux_test.go:92: kernel=6.19.7-200.fc43.aarch64 btf=true tracepoints=[sched/sched_process_exec sched/sched_process_exit] command=[/usr/bin/true] observed_events=2 exec_pid=31679 exec_ppid=31673 exec_tid=31679 exec_pid_ns=4026531836 exec_cgroup=19440 exec_comm="true" exit_pid=31679 exit_ppid=31673 exit_tid=31679 exit_pid_ns=4026531836 exit_cgroup=19440 exit_comm="true" exit_code=0 exec_coverage=complete exec_correlation=explicit_pid/high exec_verdict=compliant exit_coverage=complete exit_correlation=explicit_pid/high exit_verdict=compliant
--- PASS: TestLinuxEBPFExecSmoke (0.17s)
=== RUN   TestLinuxEBPFSessionSmoke
    linux_ebpf_smoke_linux_test.go:192: kernel=6.19.7-200.fc43.aarch64 btf=true tracepoints=[sched/sched_process_exec sched/sched_process_exit] command=[/bin/sh -c /usr/bin/true; /usr/bin/true] root_pid=31680 cgroup=19440 observed_events=5 child_pid=31681 child_exit_pid=31681
--- PASS: TestLinuxEBPFSessionSmoke (0.11s)
PASS
ok  	github.com/gnanirahulnutakki/ardur/go/pkg/kernelcapture	0.292s
```

The session smoke proves the harness can scope beyond one PID for the launched command tree: root shell exec/exit plus a child `/usr/bin/true` exec/exit were observed in the same cgroup and projected through receipts. This is still userspace filtering over metadata-only ringbuf samples, not kernel-map enforcement or daemon custody.

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

Ardur can load local Linux eBPF tracepoint producers, attach `sched/sched_process_exec` and `sched/sched_process_exit`, stream scoped process exec+exit metadata samples through a ringbuf, decode process identity and exit-code metadata, retain a launched command's userspace process-tree scope in the local harness, and produce synthetic kernel-effect receipts with:

- `coverage_status=complete`
- `correlation_method=explicit_pid`
- `correlation_confidence=high`
- `verdict=compliant`

## Claim boundary

Allowed claim:

Ardur has a local Linux eBPF process lifecycle MVP: in a privileged Linux container/VM it can load `sched_process_exec`/`sched_process_exit` tracepoint producers, read metadata-only ringbuf exec+exit events, scope a launched command tree in the local userspace harness by root PID + cgroup + PPID lineage, and project the events into honest synthetic kernel-effect evidence.

Not claimed:

- production daemon readiness
- universal CLI capture
- file/network/privilege side-effect capture
- macOS/Windows kernel capture
- unprivileged/no-install eBPF support
- persistent bpffs map custody
- kernel-enforced session/cgroup filtering

## Next engineering tasks

1. Harden exec/exit ordering and loss semantics under concurrent process churn.
2. Move from userspace process-tree scope to kernel-map/cgroup filtering before ringbuf emission.
3. Add an actual daemon boundary and root-owned config for eBPF object loading/map custody.
4. Add file/network side-effect event classes separately with explicit claim boundaries.
5. Add installation and operator docs only after daemon custody and privilege model are reviewed.
